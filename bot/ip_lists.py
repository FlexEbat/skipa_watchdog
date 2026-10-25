"""
Загрузка, кэширование и периодическое обновление баз IP-адресов сканеров.

Источники (настраиваются в config.yaml, секция sources):

1. primary_list_url - lists/skipa_cidr.txt из tread-lightly/CyberOK_Skipa_ips
                       (строки вида '185.224.228.0/24' либо одиночный IP).
                       Раньше сюда добавлялся ещё и skipa_range.txt - тот же
                       набор адресов, только в нотации диапазонов, поэтому
                       от него отказались (чистое дублирование).
2. blacklist_url   - произвольный дополнительный список (по умолчанию —
                      gist sngvy/blacklist.txt). Формат смешанный и
                      автоопределяется построчно: CIDR, диапазон "A-B" или
                      одиночный IP.

sources.active_list управляет тем, что реально используется:
  - "list1"  - только primary_list_url
  - "list2"  - только blacklist_url
  - "merged" - оба вместе, точные дубли убираются (по умолчанию)

Любой из двух URL можно оставить пустым в конфиге - соответствующий
источник тогда просто не подключается, бот не падает.

Каждая запись хранит источник (label), чтобы в алерте и в /status было видно,
по какой именно базе сработало совпадение (например "skipa" или "blacklist").
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import http_client

log = logging.getLogger("skipa_watchdog.ip_lists")

CACHE_FILE = Path(__file__).resolve().parent.parent / "data" / "ip_cache.json"
CACHE_FORMAT_VERSION = 3  # поднимается при несовместимых изменениях формата кэша

LABEL_PRIMARY = "skipa"

# Предохранители от "отравленного" или битого списка (источники внешние, а
# блокировка автоматическая): слишком широкая сеть вроде 0.0.0.0/0 заблокировала
# бы всех, включая администратора. Такие записи отбрасываются при разборе.
MIN_PREFIX_V4 = 16
MIN_PREFIX_V6 = 32
MAX_RANGE_SIZE = 1 << 20
# Если источник внезапно "похудел" больше чем вдвое - считаем это сбоем
# источника и оставляем предыдущую версию этого списка.
SHRINK_GUARD_RATIO = 0.5
# Если один из источников не скачался, база помечается degraded и обновление
# повторяется не через update_interval_days, а через этот интервал.
DEGRADED_RETRY_SECONDS = 3600


def normalize_ip(ip_str: str):
    """Разбирает IP и приводит IPv4-mapped IPv6 (::ffff:1.2.3.4, так их показывает
    /proc/net/tcp6 для IPv4-клиентов на dual-stack сокетах) к обычному IPv4.
    Возвращает объект адреса или None."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if ip_obj.version == 6 and ip_obj.ipv4_mapped is not None:
        return ip_obj.ipv4_mapped
    return ip_obj


def network_is_acceptable(net) -> bool:
    min_prefix = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
    return net.prefixlen >= min_prefix


@dataclass
class IPRange:
    start: int
    end: int
    raw: str
    label: str = "range"


@dataclass
class NetEntry:
    network: "ipaddress._BaseNetwork"
    label: str = LABEL_PRIMARY


@dataclass
class ThreatDB:
    """Хранит распарсенные сети/диапазоны (с указанием источника) и момент
    последнего обновления."""

    networks: list[NetEntry] = field(default_factory=list)
    ranges: list[IPRange] = field(default_factory=list)
    last_update_ts: float = 0.0
    source_line_count: int = 0
    # сколько записей пришло из каждого источника, для /status
    per_source_counts: dict[str, int] = field(default_factory=dict)
    # True, если при последнем обновлении не удалось получить один из
    # активных источников (используется его предыдущая версия)
    degraded: bool = False

    # ---------- матчинг ----------

    def match(self, ip_str: str) -> str | None:
        """Возвращает 'label: CIDR/диапазон' по которому сработало совпадение,
        либо None."""
        ip_obj = normalize_ip(ip_str)
        if ip_obj is None:
            return None

        for entry in self.networks:
            if ip_obj in entry.network:
                return f"{entry.label}: {entry.network}"

        ip_int = int(ip_obj)
        for r in self.ranges:
            if r.start <= ip_int <= r.end:
                return f"{r.label}: {r.raw}"

        return None

    def ipset_entries(self) -> list[str]:
        """Все IPv4-записи базы в виде CIDR-строк (диапазоны раскладываются на
        минимальный набор сетей) - для загрузки в ipset. Дубли убираются."""
        out: dict[str, None] = {}
        for e in self.networks:
            if e.network.version == 4:
                out[str(e.network)] = None
        for r in self.ranges:
            try:
                first = ipaddress.ip_address(r.start)
                last = ipaddress.ip_address(r.end)
            except ValueError:
                continue
            if first.version != 4 or last.version != 4:
                continue
            for net in ipaddress.summarize_address_range(first, last):
                out[str(net)] = None
        return list(out)

    # ---------- (де)сериализация кэша ----------

    def to_json(self) -> dict:
        return {
            "version": CACHE_FORMAT_VERSION,
            "networks": [[str(e.network), e.label] for e in self.networks],
            "ranges": [[r.start, r.end, r.raw, r.label] for r in self.ranges],
            "last_update_ts": self.last_update_ts,
            "source_line_count": self.source_line_count,
            "per_source_counts": self.per_source_counts,
            "degraded": self.degraded,
        }

    @classmethod
    def from_json(cls, data: dict) -> "ThreatDB":
        if data.get("version") != CACHE_FORMAT_VERSION:
            # Старый/чужой формат кэша - безопаснее не пытаться его читать
            # частично, а просто заставить вызывающий код перекачать базу.
            raise ValueError("устаревший формат кэша")
        nets = [NetEntry(ipaddress.ip_network(n), label) for n, label in data.get("networks", [])]
        ranges = [IPRange(s, e, raw, label) for s, e, raw, label in data.get("ranges", [])]
        return cls(
            networks=nets,
            ranges=ranges,
            last_update_ts=data.get("last_update_ts", 0.0),
            source_line_count=data.get("source_line_count", 0),
            per_source_counts=data.get("per_source_counts", {}),
            degraded=bool(data.get("degraded", False)),
        )


def _parse_cidr_list(text: str, label: str = LABEL_PRIMARY) -> list[NetEntry]:
    """skipa_cidr.txt: строки вида '185.224.228.0/24' или одиночные IP без маски."""
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "/" in line:
                net = ipaddress.ip_network(line, strict=False)
            else:
                net = ipaddress.ip_network(f"{line}/32", strict=False)
            if not network_is_acceptable(net):
                log.warning("Отбрасываю слишком широкую сеть из списка (%s): %s", label, line)
                continue
            entries.append(NetEntry(net, label))
        except ValueError:
            log.warning("Не удалось распарсить строку из списка (%s): %r", label, line)
    return entries


def _parse_mixed_list(text: str, label: str) -> tuple[list[NetEntry], list[IPRange]]:
    """Для произвольных доп. списков (blacklist_url): формат построчно
    автоопределяется - CIDR ('/'), диапазон ('A-B') или одиночный IP."""
    nets: list[NetEntry] = []
    ranges: list[IPRange] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "/" in line:
                net = ipaddress.ip_network(line, strict=False)
                if not network_is_acceptable(net):
                    log.warning("Отбрасываю слишком широкую сеть из доп. списка (%s): %s", label, line)
                    continue
                nets.append(NetEntry(net, label))
            elif "-" in line and line.count("-") == 1:
                start_s, end_s = [p.strip() for p in line.split("-", 1)]
                start_ip = ipaddress.ip_address(start_s)
                end_ip = ipaddress.ip_address(end_s)
                start, end = int(start_ip), int(end_ip)
                if start_ip.version != 4 or end_ip.version != 4 or end < start or end - start + 1 > MAX_RANGE_SIZE:
                    log.warning("Отбрасываю некорректный/слишком большой диапазон (%s): %r", label, line)
                    continue
                ranges.append(IPRange(start, end, line, label))
            else:
                nets.append(NetEntry(ipaddress.ip_network(f"{line}/32", strict=False), label))
        except ValueError:
            log.warning("Не удалось распарсить строку из доп. списка (%s): %r", label, line)
    return nets, ranges


async def _empty() -> str:
    """Заглушка для asyncio.gather, когда источник отключён/пуст - чтобы
    не городить отдельную ветку кода для «скачать» и «не скачивать»."""
    return ""


def _parse_generic_cidr_list(text: str, label: str) -> list[NetEntry]:
    """Универсальный парсер внешних блок-листов (Spamhaus DROP, FireHOL и т.п.):
    строка = CIDR или одиночный IP, хвостовой комментарий после ';' или '#'.
        203.0.113.0/24 ; SBL12345    <- Spamhaus DROP
        203.0.113.0/24               <- FireHOL netset
    Служебные/битые строки тихо пропускаются, слишком широкие сети отбрасываются."""
    out: list[NetEntry] = []
    for raw in text.splitlines():
        line = raw.split(";", 1)[0].split("#", 1)[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line if "/" in line else f"{line}/32", strict=False)
        except ValueError:
            continue
        if not network_is_acceptable(net):
            log.warning("Отбрасываю слишком широкую сеть из списка (%s): %s", label, line)
            continue
        out.append(NetEntry(net, label))
    return out


async def _fetch_extra_source(extra: dict) -> tuple[str, list[NetEntry]]:
    """Скачивает один дополнительный источник из sources.extra.
    type: cidr_list (по умолчанию) - текстовый список; abuseipdb - JSON API
    (нужен api_key). Возвращает (метка, записи); пустой список = недоступен."""
    name = str(extra.get("name", "extra"))
    label = str(extra.get("display_name") or name)
    src_type = str(extra.get("type", "cidr_list"))

    if src_type == "cidr_list":
        url = extra.get("url", "")
        text = await http_client.get_text(url) if url else ""
        return label, _parse_generic_cidr_list(text, label) if text else []

    if src_type == "abuseipdb":
        api_key = extra.get("api_key", "")
        if not api_key:
            log.warning("Источник %r (AbuseIPDB) пропущен: не задан api_key в config.yaml", name)
            return label, []
        conf = int(extra.get("min_confidence", 90))
        data = await http_client.get_json(
            f"https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum={conf}",
            headers={"Key": api_key, "Accept": "application/json"},
        )
        entries: list[NetEntry] = []
        for item in (data or {}).get("data", []):
            ip = item.get("ipAddress") if isinstance(item, dict) else None
            try:
                entries.append(NetEntry(ipaddress.ip_network(f"{ip}/32"), label))
            except ValueError:
                continue
        return label, entries

    log.warning("Неизвестный тип источника %r у %r, пропускаю", src_type, name)
    return label, []


def _previous_entries(previous: "ThreatDB | None", label: str):
    if previous is None:
        return [], []
    return (
        [e for e in previous.networks if e.label == label],
        [r for r in previous.ranges if r.label == label],
    )


async def fetch_threat_db(
    primary_url: str,
    blacklist_url: str = "",
    blacklist_label: str = "blacklist",
    active_list: str = "merged",
    previous: "ThreatDB | None" = None,
    extra_sources: "list[dict] | None" = None,
) -> ThreatDB:
    """Тянет настроенные списки и собирает единую базу.

    Оба источника скачиваются ВСЕГДА, независимо от active_list - чтобы
    данные по обоим листам оставались свежими (и не протухали, пока не
    выбраны), и было с чем сравнивать при переключении. active_list влияет
    только на то, какие из скачанных записей реально попадают в базу:
      - "list1"  - только primary_url (текущий/основной список)
      - "list2"  - только blacklist_url (доп. список)
      - "merged" - оба вместе, с удалением точных дублей (по умолчанию)

    Любой из URL может быть пустым - тогда соответствующий источник просто
    пропускается.

    extra_sources - дополнительные источники из sources.extra (Spamhaus DROP,
    FireHOL, AbuseIPDB и любые свои списки CIDR); включённые (enabled: true)
    участвуют всегда, независимо от active_list. Каждый показывается в алерте
    под своим display_name.

    previous - прошлая версия базы. Если АКТИВНЫЙ источник не скачался (или
    вернул подозрительно мало записей), берутся его записи из previous, а база
    помечается degraded=True (обновление повторится скоро, а не через неделю).
    Так временный сбой одного источника не стирает защиту."""
    if active_list not in ("list1", "list2", "merged"):
        log.warning("Неизвестный active_list=%r, использую 'merged'", active_list)
        active_list = "merged"

    use_list1 = active_list in ("list1", "merged")
    use_list2 = active_list in ("list2", "merged")

    enabled_extras = []
    for e in extra_sources or []:
        if not e.get("enabled", True):
            continue
        if e.get("type") == "abuseipdb" and not e.get("api_key"):
            log.warning("Источник %r (AbuseIPDB) пропущен: не задан api_key в config.yaml", e.get("name"))
            continue
        enabled_extras.append(e)
    primary_text, blacklist_text, *extra_results = await asyncio.gather(
        http_client.get_text(primary_url) if primary_url else _empty(),
        http_client.get_text(blacklist_url) if blacklist_url else _empty(),
        *[_fetch_extra_source(e) for e in enabled_extras],
        return_exceptions=False,
    )

    networks: list[NetEntry] = []
    ranges: list[IPRange] = []
    per_source: dict[str, int] = {}
    degraded = False

    def _guard(label: str, new_count: int) -> bool:
        """True, если новое число записей выглядит нормально."""
        old = (previous.per_source_counts.get(label, 0) if previous else 0)
        if old and new_count < old * SHRINK_GUARD_RATIO:
            log.warning(
                "Источник %s вернул %d записей вместо ~%d - похоже на сбой, оставляю прошлую версию",
                label, new_count, old,
            )
            return False
        return True

    # ---- primary ----
    if use_list1 and primary_url:
        new_nets = _parse_cidr_list(primary_text) if primary_text else []
        if new_nets and _guard(LABEL_PRIMARY, len(new_nets)):
            networks.extend(new_nets)
            per_source[LABEL_PRIMARY] = len(new_nets)
        else:
            old_nets, _ = _previous_entries(previous, LABEL_PRIMARY)
            degraded = True
            if old_nets:
                log.warning("Основной список недоступен - использую прошлую версию (%d записей)", len(old_nets))
                networks.extend(old_nets)
                per_source[LABEL_PRIMARY] = len(old_nets)
            else:
                log.error("Основной список недоступен, прошлой версии нет")

    # ---- blacklist ----
    if use_list2 and blacklist_url:
        bl_nets, bl_ranges = _parse_mixed_list(blacklist_text, blacklist_label) if blacklist_text else ([], [])
        count = len(bl_nets) + len(bl_ranges)
        if count and _guard(blacklist_label, count):
            networks.extend(bl_nets)
            ranges.extend(bl_ranges)
            per_source[blacklist_label] = count
        else:
            old_nets, old_ranges = _previous_entries(previous, blacklist_label)
            degraded = True
            if old_nets or old_ranges:
                log.warning(
                    "Доп. список (%s) недоступен - использую прошлую версию (%d записей)",
                    blacklist_label, len(old_nets) + len(old_ranges),
                )
                networks.extend(old_nets)
                ranges.extend(old_ranges)
                per_source[blacklist_label] = len(old_nets) + len(old_ranges)
            else:
                log.error("Доп. список (%s) недоступен, прошлой версии нет", blacklist_label)

    # ---- дополнительные источники (sources.extra) ----
    for (label, entries), extra in zip(extra_results, enabled_extras):
        if entries and _guard(label, len(entries)):
            networks.extend(entries)
            per_source[label] = len(entries)
        else:
            old_nets, _ = _previous_entries(previous, label)
            degraded = True
            if old_nets:
                log.warning("Источник %s недоступен - использую прошлую версию (%d записей)", label, len(old_nets))
                networks.extend(old_nets)
                per_source[label] = len(old_nets)
            else:
                log.error("Источник %s недоступен, прошлой версии нет", label)

    # "Объединить - без повторов": убираем точные дубли (одна и та же сеть/диапазон
    # встретилась в нескольких источниках). Оставляем первое вхождение, чтобы метка
    # источника указывала на исходный список, а не на blacklist.
    before = len(networks) + len(ranges)
    networks = _dedup_networks(networks)
    ranges = _dedup_ranges(ranges)
    removed = before - (len(networks) + len(ranges))
    if removed:
        log.info("Объединение списков: удалено %d точных дублей", removed)

    db = ThreatDB(
        networks=networks,
        ranges=ranges,
        last_update_ts=time.time(),
        source_line_count=len(networks) + len(ranges),
        per_source_counts=per_source,
        degraded=degraded,
    )
    log.info(
        "Обновлена база угроз (active_list=%s%s): %d сетей/IP + %d диапазонов (по источникам: %s)",
        active_list,
        ", degraded" if degraded else "",
        len(networks),
        len(ranges),
        per_source,
    )
    return db


def has_data(db: "ThreatDB | None") -> bool:
    return db is not None and bool(db.networks or db.ranges)


def _dedup_networks(entries: list[NetEntry]) -> list[NetEntry]:
    seen: dict[str, NetEntry] = {}
    for e in entries:
        key = str(e.network)
        if key not in seen:
            seen[key] = e
    return list(seen.values())


def _dedup_ranges(entries: list[IPRange]) -> list[IPRange]:
    seen: dict[tuple[int, int], IPRange] = {}
    for e in entries:
        key = (e.start, e.end)
        if key not in seen:
            seen[key] = e
    return list(seen.values())


def load_cache() -> ThreatDB | None:
    if not CACHE_FILE.exists():
        return None
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        return ThreatDB.from_json(data)
    except Exception as e:  # noqa: BLE001
        log.warning("Не удалось прочитать кэш %s (%s), перекачаю базу заново", CACHE_FILE, e)
        return None


def atomic_write_text(path: Path, text: str) -> None:
    """Запись через временный файл + rename: при сбое/отключении питания остаётся
    либо старая, либо новая версия файла целиком, но не обрубок."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def save_cache(db: ThreatDB) -> None:
    atomic_write_text(CACHE_FILE, json.dumps(db.to_json(), ensure_ascii=False, indent=2))


def needs_update(db: ThreatDB | None, interval_days: int) -> bool:
    if db is None or (not db.networks and not db.ranges):
        return True
    age_seconds = time.time() - db.last_update_ts
    if db.degraded and age_seconds >= DEGRADED_RETRY_SECONDS:
        return True
    return age_seconds / 86400 >= interval_days


# ---------------------------------------------------------------------------
# Проверка новых версий листов (по хэшу содержимого) - независимо от того,
# какой active_list сейчас выбран, проверяются оба источника, чтобы
# администратор видел, есть ли смысл переключиться/обновиться.
# ---------------------------------------------------------------------------
VERSION_STATE_FILE = Path(__file__).resolve().parent.parent / "data" / "list_versions.json"


def _hash_text(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


async def check_list_versions(
    primary_url: str, blacklist_url: str, blacklist_label: str = "blacklist"
) -> dict[str, bool]:
    """Скачивает оба источника и сравнивает их хэш с сохранённым на прошлый
    раз. Возвращает {label: changed} только для тех источников, что реально
    изменились (первая проверка просто сохраняет baseline и ничего не
    сообщает)."""
    urls = {LABEL_PRIMARY: primary_url, blacklist_label: blacklist_url}

    old_state: dict[str, str] = {}
    if VERSION_STATE_FILE.exists():
        try:
            old_state = json.loads(VERSION_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            old_state = {}

    new_state: dict[str, str] = {}
    changed: dict[str, bool] = {}
    for label, url in urls.items():
        if not url:
            continue
        text = await http_client.get_text(url)
        if not text:
            continue
        h = _hash_text(text)
        new_state[label] = h
        if label in old_state and old_state[label] != h:
            changed[label] = True

    if new_state:
        merged_state = {**old_state, **new_state}
        atomic_write_text(VERSION_STATE_FILE, json.dumps(merged_state, ensure_ascii=False, indent=2))

    return changed
