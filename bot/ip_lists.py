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

import ipaddress
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

import aiohttp

log = logging.getLogger("skipa_watchdog.ip_lists")

CACHE_FILE = Path(__file__).resolve().parent.parent / "data" / "ip_cache.json"
CACHE_FORMAT_VERSION = 3  # поднимается при несовместимых изменениях формата кэша

LABEL_PRIMARY = "skipa"


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

    # ---------- матчинг ----------

    def match(self, ip_str: str) -> str | None:
        """Возвращает 'label: CIDR/диапазон' по которому сработало совпадение,
        либо None."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        for entry in self.networks:
            if ip_obj in entry.network:
                return f"{entry.label}: {entry.network}"

        ip_int = int(ip_obj)
        for r in self.ranges:
            if r.start <= ip_int <= r.end:
                return f"{r.label}: {r.raw}"

        return None

    # ---------- (де)сериализация кэша ----------

    def to_json(self) -> dict:
        return {
            "version": CACHE_FORMAT_VERSION,
            "networks": [[str(e.network), e.label] for e in self.networks],
            "ranges": [[r.start, r.end, r.raw, r.label] for r in self.ranges],
            "last_update_ts": self.last_update_ts,
            "source_line_count": self.source_line_count,
            "per_source_counts": self.per_source_counts,
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
                nets.append(NetEntry(ipaddress.ip_network(line, strict=False), label))
            elif "-" in line and line.count("-") == 1:
                start_s, end_s = [p.strip() for p in line.split("-", 1)]
                start = int(ipaddress.ip_address(start_s))
                end = int(ipaddress.ip_address(end_s))
                ranges.append(IPRange(start, end, line, label))
            else:
                nets.append(NetEntry(ipaddress.ip_network(f"{line}/32", strict=False), label))
        except ValueError:
            log.warning("Не удалось распарсить строку из доп. списка (%s): %r", label, line)
    return nets, ranges


async def fetch_threat_db(
    primary_url: str,
    blacklist_url: str = "",
    blacklist_label: str = "blacklist",
    active_list: str = "merged",
) -> ThreatDB:
    """Тянет настроенные списки и собирает единую базу.

    active_list управляет тем, какие источники реально используются:
      - "list1"  - только primary_url (текущий/основной список)
      - "list2"  - только blacklist_url (доп. список)
      - "merged" - оба вместе, с удалением точных дублей (по умолчанию)

    Любой из URL может быть пустым - тогда соответствующий источник просто
    пропускается."""
    if active_list not in ("list1", "list2", "merged"):
        log.warning("Неизвестный active_list=%r, использую 'merged'", active_list)
        active_list = "merged"

    use_list1 = active_list in ("list1", "merged")
    use_list2 = active_list in ("list2", "merged")

    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        primary_text = await _fetch_text(session, primary_url) if (use_list1 and primary_url) else ""
        blacklist_text = (
            await _fetch_text(session, blacklist_url) if (use_list2 and blacklist_url) else ""
        )

    networks = _parse_cidr_list(primary_text) if primary_text else []
    ranges: list[IPRange] = []

    per_source = {}
    if use_list1:
        per_source[LABEL_PRIMARY] = len(networks)

    if blacklist_text:
        bl_nets, bl_ranges = _parse_mixed_list(blacklist_text, blacklist_label)
        networks.extend(bl_nets)
        ranges.extend(bl_ranges)
        per_source[blacklist_label] = len(bl_nets) + len(bl_ranges)

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
    )
    log.info(
        "Обновлена база угроз (active_list=%s): %d сетей/IP + %d диапазонов (по источникам: %s)",
        active_list,
        len(networks),
        len(ranges),
        per_source,
    )
    return db


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


async def _fetch_text(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url) as resp:
            resp.raise_for_status()
            return await resp.text()
    except Exception as e:  # noqa: BLE001
        log.error("Не удалось скачать %s: %s", url, e)
        return ""


def load_cache() -> ThreatDB | None:
    if not CACHE_FILE.exists():
        return None
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        return ThreatDB.from_json(data)
    except Exception as e:  # noqa: BLE001
        log.warning("Не удалось прочитать кэш %s (%s), перекачаю базу заново", CACHE_FILE, e)
        return None


def save_cache(db: ThreatDB) -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(db.to_json(), ensure_ascii=False, indent=2), encoding="utf-8")


def needs_update(db: ThreatDB | None, interval_days: int) -> bool:
    if db is None or (not db.networks and not db.ranges):
        return True
    age_days = (time.time() - db.last_update_ts) / 86400
    return age_days >= interval_days


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

    timeout = aiohttp.ClientTimeout(total=20)
    new_state: dict[str, str] = {}
    changed: dict[str, bool] = {}
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for label, url in urls.items():
            if not url:
                continue
            text = await _fetch_text(session, url)
            if not text:
                continue
            h = _hash_text(text)
            new_state[label] = h
            if label in old_state and old_state[label] != h:
                changed[label] = True

    if new_state:
        VERSION_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        merged_state = {**old_state, **new_state}
        VERSION_STATE_FILE.write_text(
            json.dumps(merged_state, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    return changed
