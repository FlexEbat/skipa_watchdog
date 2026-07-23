"""
Загрузка, кэширование и еженедельное обновление базы IP-адресов сканеров
из репозитория tread-lightly/CyberOK_Skipa_ips (файлы lists/skipa_cidr.txt
и lists/skipa_range.txt).
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


@dataclass
class IPRange:
    start: int
    end: int
    raw: str


@dataclass
class ThreatDB:
    """Хранит распарсенные сети/диапазоны и момент последнего обновления."""

    networks: list[ipaddress._BaseNetwork] = field(default_factory=list)
    ranges: list[IPRange] = field(default_factory=list)
    last_update_ts: float = 0.0
    source_line_count: int = 0

    # ---------- матчинг ----------

    def match(self, ip_str: str) -> str | None:
        """Возвращает строку-источник совпадения (CIDR/диапазон) либо None."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        for net in self.networks:
            if ip_obj in net:
                return str(net)

        ip_int = int(ip_obj)
        for r in self.ranges:
            if r.start <= ip_int <= r.end:
                return r.raw

        return None

    # ---------- (де)сериализация кэша ----------

    def to_json(self) -> dict:
        return {
            "networks": [str(n) for n in self.networks],
            "ranges": [[r.start, r.end, r.raw] for r in self.ranges],
            "last_update_ts": self.last_update_ts,
            "source_line_count": self.source_line_count,
        }

    @classmethod
    def from_json(cls, data: dict) -> "ThreatDB":
        nets = [ipaddress.ip_network(n) for n in data.get("networks", [])]
        ranges = [IPRange(s, e, raw) for s, e, raw in data.get("ranges", [])]
        return cls(
            networks=nets,
            ranges=ranges,
            last_update_ts=data.get("last_update_ts", 0.0),
            source_line_count=data.get("source_line_count", 0),
        )


def _parse_cidr_list(text: str) -> list[ipaddress._BaseNetwork]:
    """skipa_cidr.txt: строки вида '185.224.228.0/24' или одиночные IP без маски."""
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "/" in line:
                nets.append(ipaddress.ip_network(line, strict=False))
            else:
                nets.append(ipaddress.ip_network(f"{line}/32", strict=False))
        except ValueError:
            log.warning("Не удалось распарсить строку из cidr-листа: %r", line)
    return nets


def _parse_range_list(text: str) -> list[IPRange]:
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
            ranges.append(IPRange(start, end, line))
        except ValueError:
            log.warning("Не удалось распарсить строку из range-листа: %r", line)
    return ranges


async def fetch_threat_db(cidr_url: str, range_url: str) -> ThreatDB:
    """Тянет оба списка с GitHub и собирает единую базу."""
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        cidr_text = await _fetch_text(session, cidr_url)
        range_text = await _fetch_text(session, range_url)

    networks = _parse_cidr_list(cidr_text) if cidr_text else []
    ranges = _parse_range_list(range_text) if range_text else []

    db = ThreatDB(
        networks=networks,
        ranges=ranges,
        last_update_ts=time.time(),
        source_line_count=len(networks) + len(ranges),
    )
    log.info(
        "Обновлена база угроз: %d сетей/IP + %d диапазонов",
        len(networks),
        len(ranges),
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
        log.warning("Не удалось прочитать кэш %s: %s", CACHE_FILE, e)
        return None


def save_cache(db: ThreatDB) -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(db.to_json(), ensure_ascii=False, indent=2), encoding="utf-8")


def needs_update(db: ThreatDB | None, interval_days: int) -> bool:
    if db is None or not db.networks and not db.ranges:
        return True
    age_days = (time.time() - db.last_update_ts) / 86400
    return age_days >= interval_days
