# Skipa Watchdog

Telegram-бот, который **постоянно** мониторит сетевые подключения к вашему
серверу и присылает уведомление, если источник входит в базу IP-адресов
сканеров CyberOK/Skipa, ГРЧЦ и НКЦКИ из репозитория
[tread-lightly/CyberOK_Skipa_ips](https://github.com/tread-lightly/CyberOK_Skipa_ips).

База IP (`lists/skipa_cidr.txt` и `lists/skipa_range.txt`) обновляется
**раз в неделю** (настраивается), мониторинг соединений идёт непрерывно
(по умолчанию опрос раз в 5 секунд).

## Пример уведомления

```
🚨 УГРОЗА. СКАНЕР ОБНАРУЖЕН - IP

IP: 111.111.11.111
BGP | Censys | IPinfo | IPQS | More
▢ MaxMind & IPinfo & Cloudflare:
🇷🇺 RU Russia, Novosibirsk Oblast, Kudryashovskiy
AS12345 / Xxxx LLC
▢ Registration (RIPE):
🇷🇺 RU Russia (IP)
RU-XXXX-11223345
🇷🇺 RU Russia (AS)
XXXX-AS / XXXXX.com
▢ Privacy info (ipregistry.co):
Proxy ❌ | Abuser ❌ | Server ✅
```

## Установка

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp config.example.yaml config.yaml
nano config.yaml   # заполнить bot_token, chat_id, по желанию ipinfo_token / ipregistry_key
```

### Как получить нужные значения

- **bot_token** — создать бота у [@BotFather](https://t.me/BotFather), команда `/newbot`.
- **chat_id** — куда слать алерты. Проще всего: добавить бота в нужный чат/канал
  (для канала — админом), написать туда что угодно и посмотреть `chat_id` через
  `https://api.telegram.org/bot<TOKEN>/getUpdates`, либо через бота [@getmyid_bot](https://t.me/getmyid_bot).
- **ipinfo_token** (необязательно) — бесплатная регистрация на [ipinfo.io](https://ipinfo.io/signup),
  без токена тоже работает, но с более низким лимитом запросов в день.
- **ipregistry_key** (необязательно, для блока Privacy info) — бесплатный ключ на
  [ipregistry.co](https://ipregistry.co). Без ключа блок "Privacy info" просто не
  добавляется в сообщение — бот не падает.

## Запуск

```bash
python main.py
```

При первом запуске бот сразу скачает базу IP и закэширует её в `data/ip_cache.json`,
дальше будет обновлять её раз в неделю (`sources.update_interval_days` в конфиге).

## Команды бота в Telegram

- `/status` — сколько записей в базе, когда было последнее обновление
- `/update` — принудительно обновить базу IP прямо сейчас
- `/testalert [ip]` — прислать тестовое уведомление в нужном формате, удобно для проверки форматирования
- `/start` — краткая справка

Если в `config.yaml` задан `telegram.admin_ids`, команды будут работать только
для этих пользователей.

## Важно про права доступа

Мониторинг соединений использует `psutil.net_connections()`, который читает
`/proc/net/tcp` и `/proc/net/udp`. На большинстве Linux-дистрибутивов для
просмотра **чужих** сокетов (не только процессов текущего пользователя) нужны
права root — поэтому рекомендуется запускать бота от root или через systemd
с `AmbientCapabilities=CAP_NET_ADMIN` (см. `skipa-watchdog.service` ниже).

## Расширенный мониторинг (опционально, но надёжнее)

Опрос через `psutil` раз в несколько секунд может пропустить очень короткие
соединения (одиночный SYN от zmap/zgrab, который сразу же рвётся RST) —
это как раз то, чем печально славится Skipa. Для 100%-ного покрытия
рекомендуется дополнительно логировать входящие пакеты через iptables/nftables
и слать их напрямую в бота, например:

```bash
# логируем все новые входящие TCP-соединения через nftables
nft add rule inet filter input ct state new log prefix "CONN: " group 0
```

и добавить в `bot/monitor.py` парсер journald/syslog по этому префиксу — база
адресов (`ThreatDB.match`) и логика антиспама уже готовы к переиспользованию,
меняется только источник событий (файл-лог вместо `psutil`).

## Запуск как systemd-сервис

См. файл `skipa-watchdog.service`. Скопируйте его в `/etc/systemd/system/`,
поправьте пути, затем:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now skipa-watchdog
sudo journalctl -u skipa-watchdog -f
```

## Структура проекта

```
skipa_watchdog/
├── main.py                  # точка входа, команды бота, оркестрация job'ов
├── config.example.yaml      # шаблон конфига
├── config.yaml              # ваш конфиг
├── requirements.txt
├── bot/
│   ├── config.py            # загрузка config.yaml
│   ├── ip_lists.py          # скачивание/кэш/еженедельное обновление базы IP
│   ├── enrich.py            # ipinfo.io + RIPEstat + ipregistry.co
│   ├── formatter.py         # сборка текста алерта в нужном стиле
│   └── monitor.py           # непрерывный мониторинг соединений (psutil)
└── data/
    └── ip_cache.json        # локальный кэш базы (создаётся автоматически)
```
# skipa_watchdog
