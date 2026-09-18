"""
Загрузка, кэширование и периодическое обновление баз IP-адресов сканеров.

Источники (все настраиваются в config.yaml / service.yaml, секция sources):

1. cidr_list_url  - lists/skipa_cidr.txt из tread-lightly/CyberOK_Skipa_ips
                    (строки вида '185.224.228.0/24' либо одиночный IP)
2. range_list_url - lists/skipa_range.txt из того же репозитория
                    (строки вида '5.143.224.100-5.143.224.107')
3. blacklist_url  - произвольный дополнительный список (по умолчанию —
                    gist sngvy/blacklist.txt). Формат смешанный и
                    автоопределяется построчно: CIDR, диапазон "A-B" или
                    одиночный IP — всё, что не похоже на CIDR/диапазон,
                    но парсится как IP, тоже принимается.

Любой из трёх URL можно оставить пустым в конфиге — соответствующий
источник тогда просто не подключается, бот не падает.

Каждая запись хранит источник (label), чтобы в алерте и в /status было видно,
по какой именно базе сработало совпадение (например "skipa_cidr" или
"blacklist").
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
CACHE_FORMAT_VERSION = 2  # поднимается при несовместимых изменениях формата кэша

LABEL_CIDR = "skipa_cidr"
LABEL_RANGE = "skipa_range"


@dataclass
class IPRange:
    start: int
    end: int
    raw: str
    label: str = LABEL_RANGE


@dataclass
class NetEntry:
    network: "ipaddress._BaseNetwork"
    label: str = LABEL_CIDR


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


def _parse_cidr_list(text: str, label: str = LABEL_CIDR) -> list[NetEntry]:
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
            log.warning("Не удалось распарсить строку из cidr-листа (%s): %r", label, line)
    return entries


def _parse_range_list(text: str, label: str = LABEL_RANGE) -> list[IPRange]:
    """skipa_range.txt: строки вида '5.143.224.100-5.143.224.107' или одиночный IP."""
    ranges = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "-" in line:
                start_s, end_s = [p.strip() for p in line.split("-", 1)]
                start = int(ipaddress.ip_address(start_s))
                end = int(ipaddress.ip_address(end_s))
            else:
                start = end = int(ipaddress.ip_address(line))
            ranges.append(IPRange(start, end, line, label))
        except ValueError:
            log.warning("Не удалось распарсить строку из range-листа (%s): %r", label, line)
    return ranges


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
    cidr_url: str,
    range_url: str,
    blacklist_url: str = "",
    blacklist_label: str = "blacklist",
) -> ThreatDB:
    """Тянет все настроенные списки и собирает единую базу. Любой из URL
    может быть пустым - тогда соответствующий источник просто пропускается."""
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        cidr_text = await _fetch_text(session, cidr_url) if cidr_url else ""
        range_text = await _fetch_text(session, range_url) if range_url else ""
        blacklist_text = await _fetch_text(session, blacklist_url) if blacklist_url else ""

    networks = _parse_cidr_list(cidr_text) if cidr_text else []
    ranges = _parse_range_list(range_text) if range_text else []

    per_source = {LABEL_CIDR: len(networks), LABEL_RANGE: len(ranges)}

    if blacklist_text:
        bl_nets, bl_ranges = _parse_mixed_list(blacklist_text, blacklist_label)
        networks.extend(bl_nets)
        ranges.extend(bl_ranges)
        per_source[blacklist_label] = len(bl_nets) + len(bl_ranges)

    db = ThreatDB(
        networks=networks,
        ranges=ranges,
        last_update_ts=time.time(),
        source_line_count=len(networks) + len(ranges),
        per_source_counts=per_source,
    )
    log.info(
        "Обновлена база угроз: %d сетей/IP + %d диапазонов (по источникам: %s)",
        len(networks),
        len(ranges),
        per_source,
    )
    return db


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
