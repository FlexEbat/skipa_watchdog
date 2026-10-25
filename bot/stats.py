"""
Сводная статистика по обнаруженным сканам (для /stats и еженедельного
дайджеста) + график активности по часам суток.

График рисуется через matplotlib (Agg-backend, без GUI), но matplotlib -
НЕОБЯЗАТЕЛЬНАЯ зависимость (requirements-extras.txt): если он не установлен,
вместо картинки в текст добавляется текстовая гистограмма, а всё остальное
работает как обычно.
"""
from __future__ import annotations

import io
import time
from collections import Counter, defaultdict
from html import escape

from .events_store import load_events


def build_summary(events: list[dict]) -> dict:
    unique_ips = {e["ip"] for e in events}
    countries = Counter(e.get("country_code") or "??" for e in events)
    orgs = Counter(e.get("org_name") or "неизвестно" for e in events)
    sources = Counter(e.get("source_name") or "неизвестно" for e in events)
    ports = Counter(e.get("local_port") for e in events if e.get("local_port"))

    return {
        "total_hits": len(events),
        "unique_ips": len(unique_ips),
        "top_countries": countries.most_common(5),
        "top_orgs": orgs.most_common(5),
        "top_sources": sources.most_common(5),
        "top_ports": ports.most_common(5),
    }


def format_summary_text(summary: dict, period_label: str) -> str:
    lines = [f"📊 <b>Статистика Skipa Watchdog за {escape(period_label)}</b>", ""]
    lines.append(f"Всего срабатываний: {summary['total_hits']}")
    lines.append(f"Уникальных IP: {summary['unique_ips']}")

    if summary["top_countries"]:
        lines.append("")
        lines.append("<b>Топ стран:</b>")
        for cc, count in summary["top_countries"]:
            lines.append(f"  {escape(str(cc))}: {count}")

    if summary["top_orgs"]:
        lines.append("")
        lines.append("<b>Топ организаций/ASN:</b>")
        for org, count in summary["top_orgs"]:
            lines.append(f"  {escape(str(org))}: {count}")

    if summary["top_sources"]:
        lines.append("")
        lines.append("<b>По базам-источникам:</b>")
        for src, count in summary["top_sources"]:
            lines.append(f"  {escape(str(src))}: {count}")

    if summary["top_ports"]:
        lines.append("")
        lines.append("<b>Топ портов:</b>")
        for port, count in summary["top_ports"]:
            lines.append(f"  {port}: {count}")

    return "\n".join(lines)


def _counts_by_hour(events: list[dict]) -> list[int]:
    by_hour: dict[int, int] = defaultdict(int)
    for e in events:
        by_hour[time.localtime(e["ts"]).tm_hour] += 1
    return [by_hour.get(h, 0) for h in range(24)]


def render_hourly_chart(events: list[dict], days: int) -> bytes | None:
    """PNG-диаграмма срабатываний по часам суток (агрегация за период).
    None - если событий нет или matplotlib не установлен."""
    if not events:
        return None
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None

    counts = _counts_by_hour(events)
    hours = list(range(24))
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(hours, counts, color="#d9534f")
    ax.set_xlabel("Час суток")
    ax.set_ylabel("Срабатываний")
    ax.set_title(f"Активность сканеров по часам (последние {days} дн.)")
    ax.set_xticks(hours)
    ax.set_xticklabels([str(h) for h in hours], fontsize=7)
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120)
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def render_hourly_text(events: list[dict]) -> str:
    """Текстовая гистограмма по часам - запасной вариант без matplotlib."""
    if not events:
        return ""
    counts = _counts_by_hour(events)
    peak = max(counts) or 1
    rows = ["<b>По часам суток:</b>", "<pre>"]
    for hour, count in enumerate(counts):
        if count:
            rows.append(f"{hour:02d} {'█' * max(1, round(count / peak * 20))} {count}")
    rows.append("</pre>")
    return "\n".join(rows)


def stats_for_period(days: int) -> tuple[dict, bytes | None, str]:
    """Возвращает (сводка, PNG-график или None, текстовая гистограмма на случай
    отсутствия графика)."""
    since_ts = time.time() - days * 86400
    events = load_events(since_ts=since_ts)
    chart = render_hourly_chart(events, days)
    return build_summary(events), chart, ("" if chart else render_hourly_text(events))
