
from __future__ import annotations

from html import escape

from .enrich import EnrichedIP, country_flag, _COUNTRY_NAMES


def _links_line(ip: str) -> str:
    links = [
        ("BGP", f"https://bgp.he.net/ip/{ip}"),
        ("Censys", f"https://search.censys.io/hosts/{ip}"),
        ("IPinfo", f"https://ipinfo.io/{ip}"),
        ("IPQS", f"https://www.ipqualityscore.com/ip-reputation-check/lookup/{ip}"),
        ("More", f"https://www.abuseipdb.com/check/{ip}"),
    ]
    return " | ".join(f'<a href="{url}">{name}</a>' for name, url in links)


def _bool_icon(value: bool | None) -> str:
    if value is None:
        return "❔"
    return "✅" if value else "❌"


def build_alert_message(ip: str, matched_source: str, data: EnrichedIP) -> str:
    lines = []
    lines.append("🚨 <b>УГРОЗА. СКАНЕР ОБНАРУЖЕН</b>")
    lines.append("")
    lines.append(f"IP: <code>{escape(ip)}</code>")
    lines.append(_links_line(ip))

    # ---- блок MaxMind & IPinfo & Cloudflare ----
    if data.country_code or data.city or data.org_name:
        flag = country_flag(data.country_code)
        geo_bits = [b for b in [data.country_name, data.region, data.city] if b]
        geo_line = f"{flag} {data.country_code or '??'} " + ", ".join(geo_bits)
        lines.append("▢ <b>MaxMind &amp; IPinfo &amp; Cloudflare:</b>")
        lines.append(escape(geo_line))
        if data.asn or data.org_name:
            lines.append(escape(f"{data.asn or '?'} / {data.org_name or 'unknown org'}"))

    # ---- блок Registration (RIPE) ----
    if data.ripe_country or data.ripe_as_name:
        lines.append("▢ <b>Registration (RIPE):</b>")
        if data.ripe_country:
            flag = country_flag(data.ripe_country)
            name = _COUNTRY_NAMES.get(data.ripe_country, data.ripe_country)
            lines.append(escape(f"{flag} {data.ripe_country} {name} (IP)"))
        if data.ripe_ip_netname:
            lines.append(escape(data.ripe_ip_netname))
        if data.ripe_as_country:
            flag = country_flag(data.ripe_as_country)
            name = _COUNTRY_NAMES.get(data.ripe_as_country, data.ripe_as_country)
            lines.append(escape(f"{flag} {data.ripe_as_country} {name} (AS)"))
        if data.ripe_as_name:
            lines.append(escape(data.ripe_as_name))

    # ---- блок Privacy info ----
    if data.is_proxy is not None or data.is_abuser is not None or data.is_server is not None:
        lines.append("▢ <b>Privacy info (ipregistry.co):</b>")
        lines.append(
            f"Proxy {_bool_icon(data.is_proxy)} | "
            f"Abuser {_bool_icon(data.is_abuser)} | "
            f"Server {_bool_icon(data.is_server)}"
        )

    lines.append("")
    lines.append(f"<i>Совпадение по базе: {escape(matched_source)}</i>")

    return "\n".join(lines)
