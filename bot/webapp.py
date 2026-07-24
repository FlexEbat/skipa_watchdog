"""
Простой веб-дашборд на FastAPI - для тех, кому неудобно смотреть всё в
Telegram-чате. Показывает: статус базы IP, последние события, список
забаненных IP, состояние мониторов (heartbeat).

Не предназначен для выкладывания в открытый интернет как есть: либо
держите его за VPN/локальным доступом (host: 127.0.0.1 в конфиге + свой
SSH-туннель/reverse proxy), либо задайте dashboard.username/password в
config.yaml - тогда будет спрашиваться HTTP Basic Auth.
"""
from __future__ import annotations

import time

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from .banning import list_banned
from .events_store import load_events
from .healthcheck import snapshot as heartbeat_snapshot

security = HTTPBasic(auto_error=False)


def create_app(get_db, config) -> FastAPI:
    app = FastAPI(title="Skipa Watchdog Dashboard", docs_url=None, redoc_url=None)

    def check_auth(credentials: HTTPBasicCredentials | None = Depends(security)):
        if not config.dashboard_username:
            return  # авторизация не настроена - открыт всем, кто достучался до порта
        if (
            credentials is None
            or credentials.username != config.dashboard_username
            or credentials.password != config.dashboard_password
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверный логин/пароль",
                headers={"WWW-Authenticate": "Basic"},
            )

    @app.get("/api/status")
    async def api_status(_: None = Depends(check_auth)):
        db = get_db()
        heartbeats = heartbeat_snapshot()
        now = time.time()
        return JSONResponse({
            "db_sources": {
                name: src.line_count() for name, src in (db.sources.items() if db else {})
            },
            "total_records": db.source_line_count if db else 0,
            "last_update_ts": db.last_update_ts if db else None,
            "banned_ips": await list_banned(config.ban_ipset_name),
            "monitors": {
                name: round(now - ts, 1) for name, ts in heartbeats.items()
            },
        })

    @app.get("/api/events")
    async def api_events(hours: int = 24, _: None = Depends(check_auth)):
        since_ts = time.time() - hours * 3600
        events = load_events(since_ts=since_ts)
        events.sort(key=lambda e: e["ts"], reverse=True)
        return JSONResponse(events[:500])

    @app.get("/", response_class=HTMLResponse)
    async def index(_: None = Depends(check_auth)):
        return HTMLResponse(_DASHBOARD_HTML)

    return app


_DASHBOARD_HTML = """
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
      return `<tr><td>${name}</td><td class="${cls}">${ago}с назад</td></tr>`;
    }).join('') || '<tr><td colspan="2">нет данных</td></tr>';

    const banTbody = document.querySelector('#banned-table tbody');
    banTbody.innerHTML = status.banned_ips.map(ip => `<tr><td><code>${ip}</code></td></tr>`).join('')
      || '<tr><td>никто не забанен</td></tr>';

    const evTbody = document.querySelector('#events-table tbody');
    evTbody.innerHTML = events.slice(0, 100).map(e => {
      const dt = new Date(e.ts * 1000).toLocaleString('ru-RU');
      return `<tr><td>${dt}</td><td><code>${e.ip}</code></td><td>${e.source_name||''}</td>` +
             `<td>${e.country_code||''}</td><td>${e.org_name||''}</td><td>${e.method||''}</td></tr>`;
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
