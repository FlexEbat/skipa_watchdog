"""
Обогащение IP-адреса информацией для алерта:
- гео + ASN + организация -> ipinfo.io (MaxMind/IPinfo/Cloudflare данные под капотом)
- регистрационные данные -> RIPEstat API (RIPE NCC, публичный, без ключа)
- приватность (proxy/abuser/server) -> ipregistry.co (нужен бесплатный ключ)

Все запросы - через bot/http_client.py (stdlib urllib в отдельном потоке,
без aiohttp), с мягкой деградацией: если какой-то сервис недоступен или не
настроен ключ - соответствующий блок просто не включается в сообщение,
вместо падения процесса.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from . import http_client

log = logging.getLogger("skipa_watchdog.enrich")


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


async def _fetch_ipinfo(ip: str, token: str) -> dict | None:
    url = f"https://ipinfo.io/{ip}/json"
    if token:
        url += f"?token={token}"
    return await http_client.get_json(url)


async def _fetch_ripe_whois(ip: str) -> dict | None:
    # RIPEstat: публичный API, ключ не нужен
    return await http_client.get_json(f"https://stat.ripe.net/data/whois/data.json?resource={ip}")


async def _fetch_ripe_as_overview(asn: str) -> dict | None:
    asn_num = asn.lstrip("ASas")
    return await http_client.get_json(
        f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn_num}"
    )


async def _fetch_ipregistry(ip: str, key: str) -> dict | None:
    if not key:
        return None
    return await http_client.get_json(f"https://api.ipregistry.co/{ip}?key={key}")


async def enrich_ip(ip: str, ipinfo_token: str = "", ipregistry_key: str = "") -> EnrichedIP:
    result = EnrichedIP(ip=ip)

    # ipinfo и ipregistry не зависят друг от друга - запускаем параллельно.
    # RIPE whois идёт следом, а AS-overview - только после него (нужен ASN
    # из ipinfo/whois), поэтому остаётся последовательным.
    ipinfo_data, ipreg_data = await asyncio.gather(
        _fetch_ipinfo(ip, ipinfo_token),
        _fetch_ipregistry(ip, ipregistry_key),
    )

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

    if ipreg_data:
        _parse_ipregistry(result, ipreg_data)

    whois_data = await _fetch_ripe_whois(ip)
    if whois_data:
        _parse_ripe_whois(result, whois_data)

    if result.asn:
        as_overview = await _fetch_ripe_as_overview(result.asn)
        if as_overview:
            _parse_ripe_as_overview(result, as_overview)

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
