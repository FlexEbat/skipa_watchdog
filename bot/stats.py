"""
Вычисление сводной статистики по обнаруженным сканам (для /stats и
еженедельного дайджеста) + рендер часового графика активности через
matplotlib (Agg-backend, без GUI - на сервере его и не будет).
"""
from __future__ import annotations

import io
import time
from collections import Counter, defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

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
    lines = [f"📊 <b>Статистика Skipa Watchdog за {period_label}</b>", ""]
    lines.append(f"Всего срабатываний: {summary['total_hits']}")
    lines.append(f"Уникальных IP: {summary['unique_ips']}")

    if summary["top_countries"]:
        lines.append("")
        lines.append("<b>Топ стран:</b>")
        for cc, count in summary["top_countries"]:
            lines.append(f"  {cc}: {count}")

    if summary["top_orgs"]:
        lines.append("")
        lines.append("<b>Топ организаций/ASN:</b>")
        for org, count in summary["top_orgs"]:
            lines.append(f"  {org}: {count}")

    if summary["top_sources"]:
        lines.append("")
        lines.append("<b>По базам-источникам:</b>")
        for src, count in summary["top_sources"]:
            lines.append(f"  {src}: {count}")

    if summary["top_ports"]:
        lines.append("")
        lines.append("<b>Топ портов:</b>")
        for port, count in summary["top_ports"]:
            lines.append(f"  {port}: {count}")

    return "\n".join(lines)


def render_hourly_chart(events: list[dict], days: int) -> bytes | None:
    """Строит столбчатую диаграмму количества срабатываний по часам суток
    (агрегация по всем дням периода). Возвращает PNG в виде bytes, либо
    None, если событий нет (нечего рисовать)."""
    if not events:
        return None

    by_hour: dict[int, int] = defaultdict(int)
    for e in events:
        hour = time.localtime(e["ts"]).tm_hour
        by_hour[hour] += 1

    hours = list(range(24))
    counts = [by_hour.get(h, 0) for h in hours]

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


def stats_for_period(days: int) -> tuple[dict, bytes | None]:
    since_ts = time.time() - days * 86400
    events = load_events(since_ts=since_ts)
    summary = build_summary(events)
    chart = render_hourly_chart(events, days)
    return summary, chart
