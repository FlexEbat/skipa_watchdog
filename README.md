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
AS12345 / XXXX LLC
▢ Registration (RIPE):
🇷🇺 RU Russia (IP)
RU-XXXXX-1234567890
🇷🇺 RU Russia (AS)
XXXXX-AS / XXXX.com
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

## Расширенный мониторинг через nftables (надёжнее, ловит одиночные SYN)

Опрос через `psutil` раз в несколько секунд может пропустить очень короткие
соединения (одиночный SYN от zmap/zgrab, который сразу же рвётся RST) —
это как раз то, чем печально славится Skipa. Реализован второй, более
надёжный метод: логирование новых TCP-соединений через nftables прямо
в лог ядра (kernel ring buffer), который бот читает через `journalctl -k -f`.

### 1. Проверьте текущий rulebase

```bash
sudo nft list ruleset
```

Обычно на Debian/Ubuntu уже есть таблица `inet filter` с цепочкой `input`
(hook `input`, priority `filter`). Если её нет — создайте:

```bash
sudo nft add table inet filter
sudo nft add chain inet filter input '{ type filter hook input priority filter ; policy accept ; }'
```

### 2. Добавьте правило логирования

Важно поставить его **до** правил `drop`/`reject` (иначе то, что дропается
раньше — не долетит до лога), и с лимитом скорости, чтобы при реальной
атаке/скан-шторме не забить диск и CPU логированием:

```bash
sudo nft insert rule inet filter input tcp flags syn ct state new \
  limit rate 20/second log prefix "CONN: " flags all
```

`ct state new` + `tcp flags syn` — логируем именно момент установления
нового TCP-соединения (сам факт SYN), а не полный успешный коннект.
Никакого `group N` здесь не нужно — без `group` nftables пишет запись
напрямую в kernel log buffer, который читается через `journalctl -k` или
`dmesg`, без необходимости поднимать отдельный демон вроде ulogd.

### 3. Сохраните правило, чтобы оно пережило перезагрузку

```bash
sudo nft list ruleset | sudo tee /etc/nftables.conf
sudo systemctl enable --now nftables
```

### 4. Проверьте, что записи реально появляются

```bash
sudo journalctl -k -f
```
и с другого хоста дёрните любой порт (`curl <ваш_ip>` или `nc -zv <ваш_ip> 80`) —
должна появиться строка вида:

```
CONN: IN=eth0 OUT= MAC=... SRC=89.169.28.214 DST=1.2.3.4 LEN=60 ... PROTO=TCP SPT=54321 DPT=80 ... SYN
```

### 5. Включите этот метод в config.yaml

```yaml
monitoring:
  method: "kernel_log"   # "psutil" | "kernel_log" | "both"
  kernel_log_prefix: "CONN: "
```

`bot/monitor.py` уже содержит готовую функцию `tail_kernel_log_loop()`,
которая запускает `journalctl -k -f -o cat` как подпроцесс, построчно парсит
`SRC=` / `DPT=` регуляркой и прогоняет IP через ту же `ThreatDB.match()` и ту
же логику антиспама, что и метод через `psutil`. Меняется только источник
событий — весь остальной пайплайн (обогащение, форматирование, отправка)
переиспользуется без изменений.

**Права доступа:** чтение kernel-логов через `journalctl -k` требует root
либо членства в группе `systemd-journal`. Проще всего просто запускать бота
от root (см. `skipa-watchdog.service`).

Если у вас **iptables** вместо nftables — аналог:

```bash
sudo iptables -I INPUT -p tcp --syn -m conntrack --ctstate NEW \
  -m limit --limit 20/second -j LOG --log-prefix "CONN: " --log-level 4
```
это тоже пишется в kernel log buffer, парсер тот же самый.

## Запуск как systemd-сервис (продакшен)

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
