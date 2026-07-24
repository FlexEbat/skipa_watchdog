"""
Загрузка, кэширование и еженедельное обновление базы IP-адресов угроз из
НЕСКОЛЬКИХ источников одновременно:

- "skipa" (встроенный, всегда включён) - CyberOK/Skipa/ГРЧЦ/НКЦКИ,
  https://github.com/tread-lightly/CyberOK_Skipa_ips (файлы skipa_cidr.txt +
  skipa_range.txt)
- любые дополнительные источники из config.yaml -> sources.extra, например
  Spamhaus DROP, FireHOL, AbuseIPDB blacklist - см. config.example.yaml

Каждый источник хранится отдельно (ThreatSource), поэтому при совпадении
IP бот точно знает, из какой базы прилетело срабатывание, и показывает это
в алерте (например "Совпадение: Spamhaus DROP (203.0.113.0/24)").
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from dataclasses import dataclass, field

import aiohttp

log = logging.getLogger("skipa_watchdog.ip_lists")

CACHE_FILE = None  # проставляется в config.py через set_cache_path(), см. ниже


def _default_cache_path():
    from pathlib import Path

    return Path(__file__).resolve().parent.parent / "data" / "ip_cache.json"


@dataclass
class IPRange:
    start: int
    end: int
    raw: str


@dataclass
class ThreatSource:
    """Один источник базы (Skipa, Spamhaus DROP, FireHOL, AbuseIPDB, ...)."""

    name: str
    display_name: str = ""
    networks: list = field(default_factory=list)
    ranges: list = field(default_factory=list)

    def __post_init__(self):
        if not self.display_name:
            self.display_name = self.name

    def line_count(self) -> int:
        return len(self.networks) + len(self.ranges)

    def match(self, ip_obj) -> str | None:
        for net in self.networks:
            if ip_obj in net:
                return str(net)
        if self.ranges:
            ip_int = int(ip_obj)
            for r in self.ranges:
                if r.start <= ip_int <= r.end:
                    return r.raw
        return None

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "networks": [str(n) for n in self.networks],
            "ranges": [[r.start, r.end, r.raw] for r in self.ranges],
        }

    @classmethod
    def from_json(cls, data: dict) -> "ThreatSource":
        nets = [ipaddress.ip_network(n) for n in data.get("networks", [])]
        ranges = [IPRange(s, e, raw) for s, e, raw in data.get("ranges", [])]
        return cls(
            name=data["name"],
            display_name=data.get("display_name", data["name"]),
            networks=nets,
            ranges=ranges,
        )


@dataclass
class ThreatDB:
    """Хранит все источники + момент последнего обновления."""

    sources: dict = field(default_factory=dict)  # name -> ThreatSource
    last_update_ts: float = 0.0

    @property
    def source_line_count(self) -> int:
        return sum(s.line_count() for s in self.sources.values())

    @property
    def networks(self):
        """Обратная совместимость: суммарный список сетей по всем источникам."""
        result = []
        for s in self.sources.values():
            result.extend(s.networks)
        return result

    @property
    def ranges(self):
        result = []
        for s in self.sources.values():
            result.extend(s.ranges)
        return result

    def match(self, ip_str: str):
        """Возвращает (source_display_name, matched_str) либо None."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        for src in self.sources.values():
            matched = src.match(ip_obj)
            if matched:
                return (src.display_name, matched)
        return None

    def to_json(self) -> dict:
        return {
            "sources": {name: src.to_json() for name, src in self.sources.items()},
            "last_update_ts": self.last_update_ts,
        }

    @classmethod
    def from_json(cls, data: dict) -> "ThreatDB":
        sources = {
            name: ThreatSource.from_json(sdata)
            for name, sdata in data.get("sources", {}).items()
        }
        return cls(sources=sources, last_update_ts=data.get("last_update_ts", 0.0))


# ---------------------------------------------------------------------------
# Парсеры разных форматов списков
# ---------------------------------------------------------------------------

def _parse_cidr_list(text: str) -> list:
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


def _parse_range_list(text: str) -> list:
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


def _parse_generic_cidr_list(text: str) -> list:
    """
    Универсальный парсер для внешних блок-листов (Spamhaus DROP, FireHOL и т.п.):
    строка = CIDR или одиночный IP, возможен хвостовой комментарий после ';' или '#'.
    Примеры реальных строк:
        203.0.113.0/24 ; SBL12345          <- Spamhaus DROP
        203.0.113.0/24                      <- FireHOL netset
        # это комментарий, пропускаем
    """
    nets = []
    for raw_line in text.splitlines():
        line = raw_line.split(";", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "/" in line:
                nets.append(ipaddress.ip_network(line, strict=False))
            else:
                nets.append(ipaddress.ip_network(f"{line}/32", strict=False))
        except ValueError:
            continue  # внешние листы часто содержат служебные строки, тихо пропускаем
    return nets


# ---------------------------------------------------------------------------
# Загрузка отдельных источников
# ---------------------------------------------------------------------------

async def _fetch_text(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url) as resp:
            resp.raise_for_status()
            return await resp.text()
    except Exception as e:  # noqa: BLE001
        log.error("Не удалось скачать %s: %s", url, e)
        return ""


async def _fetch_json(session: aiohttp.ClientSession, url: str, headers: dict | None = None):
    try:
        async with session.get(url, headers=headers or {}) as resp:
            resp.raise_for_status()
            return await resp.json(content_type=None)
    except Exception as e:  # noqa: BLE001
        log.error("Не удалось скачать %s: %s", url, e)
        return None


async def _fetch_skipa(session, cidr_url: str, range_url: str) -> ThreatSource:
    cidr_text = await _fetch_text(session, cidr_url)
    range_text = await _fetch_text(session, range_url)
    src = ThreatSource(
        name="skipa",
        display_name="CyberOK/Skipa/ГРЧЦ/НКЦКИ",
        networks=_parse_cidr_list(cidr_text) if cidr_text else [],
        ranges=_parse_range_list(range_text) if range_text else [],
    )
    return src


async def _fetch_cidr_list_source(session, name: str, display_name: str, url: str) -> ThreatSource:
    text = await _fetch_text(session, url)
    nets = _parse_generic_cidr_list(text) if text else []
    return ThreatSource(name=name, display_name=display_name or name, networks=nets)


async def _fetch_abuseipdb_source(session, name: str, display_name: str, api_key: str, min_confidence: int) -> ThreatSource:
    if not api_key:
        log.warning("Источник %r (AbuseIPDB) пропущен: не задан api_key в config.yaml", name)
        return ThreatSource(name=name, display_name=display_name or name)

    url = f"https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum={min_confidence}"
    headers = {"Key": api_key, "Accept": "application/json"}
    data = await _fetch_json(session, url, headers)
    nets = []
    if data and "data" in data:
        for entry in data["data"]:
            ip = entry.get("ipAddress")
            if not ip:
                continue
            try:
                nets.append(ipaddress.ip_network(f"{ip}/32", strict=False))
            except ValueError:
                continue
    return ThreatSource(name=name, display_name=display_name or name, networks=nets)


async def fetch_threat_db(config) -> ThreatDB:
    """
    Тянет все источники (встроенный skipa + config.extra_sources) параллельно
    и собирает единую базу.
    """
    timeout = aiohttp.ClientTimeout(total=45)
    sources: dict[str, ThreatSource] = {}

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = [_fetch_skipa(session, config.cidr_list_url, config.range_list_url)]
        task_names = ["skipa"]

        for extra in config.extra_sources:
            if not extra.get("enabled", True):
                continue
            name = extra.get("name", "extra")
            src_type = extra.get("type", "cidr_list")
            display_name = extra.get("display_name", name)

            if src_type == "cidr_list":
                tasks.append(_fetch_cidr_list_source(session, name, display_name, extra.get("url", "")))
            elif src_type == "abuseipdb":
                tasks.append(
                    _fetch_abuseipdb_source(
                        session, name, display_name,
                        extra.get("api_key", ""), int(extra.get("min_confidence", 90)),
                    )
                )
            else:
                log.warning("Неизвестный тип источника %r у %r, пропускаю", src_type, name)
                continue
            task_names.append(name)

        results = await asyncio.gather(*tasks, return_exceptions=True)

    for name, result in zip(task_names, results):
        if isinstance(result, Exception):
            log.error("Источник %r упал с ошибкой: %s", name, result)
            continue
        sources[name] = result
        log.info("Источник %r (%s): %d записей", name, result.display_name, result.line_count())

    db = ThreatDB(sources=sources, last_update_ts=time.time())
    log.info("Обновлена база угроз: %d источников, %d записей всего", len(sources), db.source_line_count)
    return db


# ---------------------------------------------------------------------------
# Кэш на диске
# ---------------------------------------------------------------------------

def load_cache():
    path = _default_cache_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return ThreatDB.from_json(data)
    except Exception as e:  # noqa: BLE001
        log.warning("Не удалось прочитать кэш %s: %s", path, e)
        return None


def save_cache(db: ThreatDB) -> None:
    path = _default_cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(db.to_json(), ensure_ascii=False, indent=2), encoding="utf-8")


def needs_update(db: ThreatDB | None, interval_days: int) -> bool:
    if db is None or not db.sources:
        return True
    age_days = (time.time() - db.last_update_ts) / 86400
    return age_days >= interval_days
