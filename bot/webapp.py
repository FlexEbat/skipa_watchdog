"""
Простой веб-дашборд на чистом asyncio (без FastAPI/uvicorn): статус базы,
последние события, список блокировок, состояние мониторов (heartbeat).

Не предназначен для выкладывания в открытый интернет как есть: держите его на
127.0.0.1 (доступ через SSH-туннель: ssh -L 8080:localhost:8080 ...) либо за
reverse-proxy с TLS, и обязательно задайте dashboard.username/password -
тогда запрашивается HTTP Basic Auth (пароль сравнивается за постоянное время).
Только GET, размер запроса и время ожидания ограничены.
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import json
import logging
import time
from urllib.parse import parse_qs, urlsplit

from . import blocker
from .events_store import load_events
from .healthcheck import snapshot as heartbeat_snapshot

log = logging.getLogger("skipa_watchdog.webapp")

MAX_HEADER_BYTES = 16 * 1024
READ_TIMEOUT = 10


def _check_auth(config, header_value: str | None) -> bool:
    if not config.dashboard_username:
        return True  # авторизация не настроена - открыт всем, кто достучался до порта
    if not header_value or not header_value.lower().startswith("basic "):
        return False
    try:
        decoded = base64.b64decode(header_value[6:].strip(), validate=True)
    except Exception:  # noqa: BLE001
        return False
    expected = f"{config.dashboard_username}:{config.dashboard_password}".encode()
    return hmac.compare_digest(decoded, expected)


async def _api_status(get_db) -> dict:
    db = get_db()
    now = time.time()
    banned = await asyncio.to_thread(blocker.list_blocked_ips)
    return {
        "db_sources": dict(db.per_source_counts) if db else {},
        "total_records": db.source_line_count if db else 0,
        "last_update_ts": db.last_update_ts if db else None,
        "degraded": bool(db and db.degraded),
        "banned_ips": banned,
        "monitors": {name: round(now - ts, 1) for name, ts in heartbeat_snapshot().items()},
    }


async def _api_events(hours: int) -> list[dict]:
    hours = max(1, min(hours, 24 * 90))
    events = await asyncio.to_thread(load_events, time.time() - hours * 3600)
    events.sort(key=lambda e: e["ts"], reverse=True)
    return events[:500]


def _response(status: str, body: bytes, content_type: str, extra: list[str] | None = None) -> bytes:
    head = [
        f"HTTP/1.1 {status}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "Cache-Control: no-store",
        "X-Content-Type-Options: nosniff",
        "X-Frame-Options: DENY",
        "Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
        *(extra or []),
    ]
    return ("\r\n".join(head) + "\r\n\r\n").encode() + body


def _json(status: str, payload) -> bytes:
    return _response(status, json.dumps(payload, ensure_ascii=False).encode(), "application/json; charset=utf-8")


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, get_db, config) -> None:
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), READ_TIMEOUT)
        if len(raw) > MAX_HEADER_BYTES:
            raise ValueError("headers too large")
        lines = raw.decode("latin-1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        if method != "GET":
            out = _json("405 Method Not Allowed", {"error": "only GET"})
        elif not _check_auth(config, headers.get("authorization")):
            out = _response(
                "401 Unauthorized", "Неверный логин/пароль".encode(), "text/plain; charset=utf-8",
                ['WWW-Authenticate: Basic realm="Skipa Watchdog"'],
            )
        else:
            url = urlsplit(target)
            if url.path == "/":
                out = _response("200 OK", DASHBOARD_HTML.encode(), "text/html; charset=utf-8")
            elif url.path == "/api/status":
                out = _json("200 OK", await _api_status(get_db))
            elif url.path == "/api/events":
                try:
                    hours = int(parse_qs(url.query).get("hours", ["24"])[0])
                except ValueError:
                    hours = 24
                out = _json("200 OK", await _api_events(hours))
            else:
                out = _json("404 Not Found", {"error": "not found"})
        writer.write(out)
        await writer.drain()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, ConnectionError):
        pass
    except Exception:  # noqa: BLE001
        log.exception("Ошибка в обработчике дашборда")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def serve_dashboard(get_db, config) -> None:
    """Запускает HTTP-сервер дашборда и работает, пока задачу не отменят."""
    server = await asyncio.start_server(
        lambda r, w: _handle(r, w, get_db, config),
        host=config.dashboard_host, port=config.dashboard_port, limit=MAX_HEADER_BYTES,
    )
    log.info("Веб-дашборд запущен на http://%s:%s/", config.dashboard_host, config.dashboard_port)
    async with server:
        await server.serve_forever()


DASHBOARD_HTML = """
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Skipa Watchdog</title>
<style>
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#0f1115; color:#e6e6e6; margin:0; padding:24px; }
  h1 { font-size: 20px; margin-bottom: 4px; }
  .sub { color:#9aa0a6; margin-bottom: 24px; font-size: 13px; }
  .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap:16px; margin-bottom: 24px; }
  .card { background:#1a1d24; border-radius:10px; padding:16px; border:1px solid #2a2d35; }
  .card h2 { font-size:14px; color:#9aa0a6; margin:0 0 8px 0; text-transform:uppercase; letter-spacing:.04em; }
  .card .value { font-size:28px; font-weight:600; }
  table { width:100%; border-collapse: collapse; font-size:13px; }
  th, td { text-align:left; padding:6px 8px; border-bottom:1px solid #2a2d35; }
  th { color:#9aa0a6; font-weight:500; }
  .ok { color:#4caf50; } .warn { color:#ff9800; } .bad { color:#f44336; }
  code { background:#2a2d35; padding:2px 6px; border-radius:4px; }
</style>
</head>
<body>
  <h1>🛡️ Skipa Watchdog</h1>
  <div class="sub">Обновляется каждые 15 секунд</div>

  <div class="grid" id="summary-cards"></div>

  <div class="grid">
    <div class="card">
      <h2>Мониторы</h2>
      <table id="monitors-table"><tbody></tbody></table>
    </div>
    <div class="card">
      <h2>Забаненные IP</h2>
      <table id="banned-table"><tbody></tbody></table>
    </div>
  </div>

  <div class="card">
    <h2>Последние события (24ч)</h2>
    <table id="events-table">
      <thead><tr><th>Время</th><th>IP</th><th>База</th><th>Страна</th><th>Организация</th><th>Метод</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>

<script>
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function refresh() {
  try {
    const status = await (await fetch('/api/status')).json();
    const events = await (await fetch('/api/events?hours=24')).json();

    document.getElementById('summary-cards').innerHTML = `
      <div class="card"><h2>Записей в базе</h2><div class="value">${status.total_records}</div></div>
      <div class="card"><h2>Забанено сейчас</h2><div class="value">${status.banned_ips.length}</div></div>
      <div class="card"><h2>Событий за 24ч</h2><div class="value">${events.length}</div></div>
    `;

    const monTbody = document.querySelector('#monitors-table tbody');
    monTbody.innerHTML = Object.entries(status.monitors).map(([name, ago]) => {
      const cls = ago < 60 ? 'ok' : (ago < 300 ? 'warn' : 'bad');
      return `<tr><td>${esc(name)}</td><td class="${cls}">${ago}с назад</td></tr>`;
    }).join('') || '<tr><td colspan="2">нет данных</td></tr>';

    const banTbody = document.querySelector('#banned-table tbody');
    banTbody.innerHTML = status.banned_ips.map(ip => `<tr><td><code>${esc(ip)}</code></td></tr>`).join('')
      || '<tr><td>никто не забанен</td></tr>';

    const evTbody = document.querySelector('#events-table tbody');
    evTbody.innerHTML = events.slice(0, 100).map(e => {
      const dt = new Date(e.ts * 1000).toLocaleString('ru-RU');
      return `<tr><td>${esc(dt)}</td><td><code>${esc(e.ip)}</code></td><td>${esc(e.source_name)}</td>` +
             `<td>${esc(e.country_code)}</td><td>${esc(e.org_name)}</td><td>${esc(e.method)}</td></tr>`;
    }).join('') || '<tr><td colspan="6">пока пусто</td></tr>';
  } catch (e) {
    console.error('dashboard refresh failed', e);
  }
}
refresh();
setInterval(refresh, 15000);
</script>
</body>
</html>
"""
