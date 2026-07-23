"""
Обогащение IP-адреса информацией для алерта:
- гео + ASN + организация -> ipinfo.io (MaxMind/IPinfo/Cloudflare данные под капотом)
- регистрационные данные -> RIPEstat API (RIPE NCC, публичный, без ключа)
- приватность (proxy/abuser/server) -> ipregistry.co (нужен бесплатный ключ)

Все запросы асинхронные, с таймаутами и мягкой деградацией: если какой-то
сервис недоступен или не настроен ключ - соответствующий блок просто не
включается в сообщение, вместо падения бота.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import aiohttp

log = logging.getLogger("skipa_watchdog.enrich")

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=10)


@dataclass
class EnrichedIP:
    ip: str

    # ipinfo.io блок
    country_code: str | None = None
    country_name: str | None = None
    region: str | None = None
    city: str | None = None
    asn: str | None = None
    org_name: str | None = None

    # RIPE (registration)
    ripe_country: str | None = None
    ripe_ip_netname: str | None = None
    ripe_as_country: str | None = None
    ripe_as_name: str | None = None
    ripe_as_org: str | None = None

    # ipregistry.co (privacy)
    is_proxy: bool | None = None
    is_abuser: bool | None = None
    is_server: bool | None = None


# Название страны по ISO-коду для тех случаев, когда сервис не отдаёт его сам
_COUNTRY_NAMES = {
    "RU": "Russia", "BY": "Belarus", "UA": "Ukraine", "KZ": "Kazakhstan",
    "US": "United States", "DE": "Germany", "NL": "Netherlands",
    "GB": "United Kingdom", "FR": "France", "CN": "China",
}


def country_flag(cc: str | None) -> str:
    """ISO-код страны -> эмодзи флага (regional indicator symbols)."""
    if not cc or len(cc) != 2:
        return "🏳️"
    cc = cc.upper()
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc)


async def _get_json(session: aiohttp.ClientSession, url: str, **kwargs):
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT, **kwargs) as resp:
            if resp.status != 200:
                log.debug("GET %s -> HTTP %s", url, resp.status)
                return None
            return await resp.json(content_type=None)
    except Exception as e:  # noqa: BLE001
        log.debug("GET %s не удался: %s", url, e)
        return None


async def _fetch_ipinfo(session: aiohttp.ClientSession, ip: str, token: str) -> dict | None:
    url = f"https://ipinfo.io/{ip}/json"
    if token:
        url += f"?token={token}"
    return await _get_json(session, url)


async def _fetch_ripe_whois(session: aiohttp.ClientSession, ip: str) -> dict | None:
    # RIPEstat: публичный API, ключ не нужен
    url = f"https://stat.ripe.net/data/whois/data.json?resource={ip}"
    return await _get_json(session, url)


async def _fetch_ripe_prefix_overview(session: aiohttp.ClientSession, ip: str) -> dict | None:
    url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"
    return await _get_json(session, url)


async def _fetch_ripe_as_overview(session: aiohttp.ClientSession, asn: str) -> dict | None:
    asn_num = asn.lstrip("ASas")
    url = f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn_num}"
    return await _get_json(session, url)


async def _fetch_ipregistry(session: aiohttp.ClientSession, ip: str, key: str) -> dict | None:
    if not key:
        return None
    url = f"https://api.ipregistry.co/{ip}?key={key}"
    return await _get_json(session, url)


async def enrich_ip(ip: str, ipinfo_token: str = "", ipregistry_key: str = "") -> EnrichedIP:
    result = EnrichedIP(ip=ip)

    async with aiohttp.ClientSession() as session:
        ipinfo_data = await _fetch_ipinfo(session, ip, ipinfo_token)
        if ipinfo_data:
            result.country_code = ipinfo_data.get("country")
            result.country_name = _COUNTRY_NAMES.get(result.country_code, result.country_code)
            result.region = ipinfo_data.get("region")
            result.city = ipinfo_data.get("city")
            org = ipinfo_data.get("org", "")  # формат "AS64500 Example Hosting GmbH"
            if org:
                parts = org.split(" ", 1)
                result.asn = parts[0]
                result.org_name = parts[1] if len(parts) > 1 else None

        whois_data = await _fetch_ripe_whois(session, ip)
        if whois_data:
            _parse_ripe_whois(result, whois_data)

        if result.asn:
            as_overview = await _fetch_ripe_as_overview(session, result.asn)
            if as_overview:
                _parse_ripe_as_overview(result, as_overview)

        ipreg_data = await _fetch_ipregistry(session, ip, ipregistry_key)
        if ipreg_data:
            _parse_ipregistry(result, ipreg_data)

    return result


def _parse_ripe_whois(result: EnrichedIP, whois_data: dict) -> None:
    try:
        records = whois_data["data"]["records"]
    except (KeyError, TypeError):
        return
    for record in records:
        for field in record:
            key = field.get("key", "").lower()
            value = field.get("value", "")
            if key == "netname" and not result.ripe_ip_netname:
                result.ripe_ip_netname = value
            elif key == "country" and not result.ripe_country:
                result.ripe_country = value.upper()


def _parse_ripe_as_overview(result: EnrichedIP, as_overview: dict) -> None:
    try:
        data = as_overview["data"]
    except (KeyError, TypeError):
        return
    holder = data.get("holder", "")  # обычно вида "EXAMPLE-AS, DE" или "EXAMPLE-AS example-hosting.example"
    if holder:
        result.ripe_as_name = holder
    # страна AS иногда можно вытащить из holder (последние 2 буквы после запятой)
    if "," in holder:
        maybe_cc = holder.split(",")[-1].strip().upper()
        if len(maybe_cc) == 2:
            result.ripe_as_country = maybe_cc


def _parse_ipregistry(result: EnrichedIP, data: dict) -> None:
    security = data.get("security", {}) or {}
    result.is_proxy = bool(security.get("is_proxy") or security.get("is_vpn") or security.get("is_tor"))
    result.is_abuser = bool(security.get("is_abuser") or security.get("is_attacker"))
    conn_type = (data.get("connection", {}) or {}).get("type", "")
    result.is_server = conn_type in ("hosting", "business") or bool(
        (data.get("connection", {}) or {}).get("is_hosting")
    )
