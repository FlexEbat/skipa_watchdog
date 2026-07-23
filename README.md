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

IP: 203.0.113.42
BGP | Censys | IPinfo | IPQS | More
▢ MaxMind & IPinfo & Cloudflare:
🇩🇪 DE Germany, Bavaria, Example City
AS64500 / Example Hosting GmbH
▢ Registration (RIPE):
🇩🇪 DE Germany (IP)
DE-EXAMPLE-20200101
🇩🇪 DE Germany (AS)
EXAMPLE-AS / example-hosting.example
▢ Privacy info (ipregistry.co):
Proxy ❌ | Abuser ❌ | Server ✅
```

*(в примере выше используются зарезервированные для документации значения —
`203.0.113.0/24` (RFC 5737) и `AS64500` (RFC 5398) — это не реальный IP или
организация, а стандартные "заглушки", которые нигде в интернете реально
не встречаются)*

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

- `/status` — сколько записей в базе, когда было последнее обновление, сколько алертов в очереди на повтор
- `/update` — принудительно обновить базу IP прямо сейчас
- `/testalert [ip]` — прислать тестовое уведомление в нужном формате (по умолчанию
  на примере `203.0.113.42`), удобно для проверки форматирования
- `/pending` — показать, сколько алертов сейчас застряло в очереди на повтор
  из-за недоступности Telegram (см. раздел "Если Telegram недоступен" ниже)
- `/start` — краткая справка

Если в `config.yaml` задан `telegram.admin_ids`, команды будут работать только
для этих пользователей.

## Если Telegram недоступен

Бот не теряет алерты, если временно не может достучаться до Telegram
(нет сети, сам Telegram лежит, истёк/отозван токен и т.п.):

- **Полный audit-журнал** — каждый обнаруженный скан всегда пишется в
  `data/alerts.log` (простой читаемый текст с датой/временем), независимо
  от того, ушло ли уведомление в Telegram. Это заодно и полная история всех
  срабатываний, если захочется что-то найти постфактум.
- **Очередь на повтор** — если сама отправка в Telegram упала с ошибкой,
  сообщение кладётся в `data/pending_telegram.jsonl` и бот автоматически
  пробует отправить его снова каждые `alerting.retry_interval_seconds`
  секунд (по умолчанию 300 = 5 минут), пока не получится. Ничего вручную
  переотправлять не нужно.
- Проверить, что сейчас висит в очереди, можно командой `/pending` в
  Telegram (сработает сразу после восстановления связи) либо посмотреть
  файл напрямую: `cat data/pending_telegram.jsonl`.
- Если нужен третий канал (email, webhook, локальный syslog и т.п.) —
  добавляется в `bot/fallback.py`: там уже есть `queue_pending_alert()` /
  `append_audit_log()`, туда можно дописать ещё один вызов рядом.

## Важно про права доступа

Мониторинг соединений использует `psutil.net_connections()`, который читает
`/proc/net/tcp` и `/proc/net/udp`. На большинстве Linux-дистрибутивов для
просмотра **чужих** сокетов (не только процессов текущего пользователя) нужны
права root — поэтому рекомендуется запускать бота от root или через systemd
с `AmbientCapabilities=CAP_NET_ADMIN` (см. `skipa-watchdog.service` ниже).

## Расширенный мониторинг через nftables/iptables (надёжнее, ловит одиночные SYN)

Опрос через `psutil` раз в несколько секунд может пропустить очень короткие
соединения (одиночный SYN от zmap/zgrab, который сразу же рвётся RST) —
это как раз то, чем печально славится Skipa. Реализован второй, более
надёжный метод: логирование новых TCP-соединений прямо в лог ядра (kernel
ring buffer), который бот читает через `journalctl -k -f`.

Ниже два варианта настройки — выберите тот, что соответствует вашему серверу.
Оба варианта пишут в лог ядра в одном и том же формате, поэтому дальше
конфиг бота и парсер (`tail_kernel_log_loop()`) одинаковые для обоих.

### Вариант A: чистый nftables (сервер без Docker, свой rulebase)

**1. Проверьте текущий rulebase**

```bash
sudo nft list ruleset
```

Обычно на Debian/Ubuntu уже есть таблица `inet filter` с цепочкой `input`
(hook `input`, priority `filter`). Если её нет — создайте:

```bash
sudo nft add table inet filter
sudo nft add chain inet filter input '{ type filter hook input priority filter ; policy accept ; }'
```

**2. Добавьте правило логирования**

Важно поставить его до правил `drop`/`reject` (иначе то, что дропается
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

**3. Сохраните правило, чтобы оно пережило перезагрузку**

```bash
sudo nft list ruleset | sudo tee /etc/nftables.conf
sudo systemctl enable --now nftables
```

**4. Проверьте, что записи реально появляются**

```bash
sudo journalctl -k -f
```

и с другого хоста дёрните любой порт (`curl <ваш_ip>` или `nc -zv <ваш_ip> 80`) —
должна появиться строка вида:

```
CONN: IN=eth0 OUT= MAC=... SRC=203.0.113.77 DST=203.0.113.10 LEN=60 ... PROTO=TCP SPT=54321 DPT=80 ... SYN
```

Если у вас классический **iptables** вместо nftables (и при этом нет Docker) —
аналог:

```bash
sudo iptables -I INPUT -p tcp --syn -m conntrack --ctstate NEW \
  -m limit --limit 20/second -j LOG --log-prefix "CONN: " --log-level 4
```
это тоже пишется в kernel log buffer, парсер тот же самый.

### Вариант B: сервер с Docker (бэкенд iptables-nft)

Если на сервере крутится Docker — он **сам управляет iptables** через
совместимый бэкенд `iptables-nft` (проверить: `sudo iptables -V` покажет
`(nf_tables)`). Таблицы у него называются `ip filter`/`ip nat` с пометкой
`managed by iptables-nft, do not touch!` — значит правила добавляются через
команду `iptables`, а не напрямую через `nft add rule` в эти таблицы (Docker
их периодически пересоздаёт/дополняет, самодельное nft-правило может
потеряться или сконфликтовать).

Кроме того, трафик на опубликованные порты контейнеров (те, что указаны
в `docker run -p` / `ports:` в compose) идёт **не через INPUT**, а через
`FORWARD → DOCKER-USER` (после DNAT, который меняет адрес назначения раньше,
чем принимается решение о маршрутизации). Поэтому правило логирования нужно
ставить в двух местах.

**1. Одноразово примените правила**

```bash
sudo bash install-logging-rules.sh
```

Скрипт идемпотентный (безопасно перезапускать) и добавляет:

```bash
# хостовые сервисы (SSH и всё, что слушает не через Docker)
iptables -I INPUT -p tcp --syn -m limit --limit 30/second --limit-burst 40 \
  -j LOG --log-prefix "CONN: " --log-level 4

# всё, что опубликовано через Docker (80/443/3000/8448/51821/turn-порты и т.д.)
iptables -I DOCKER-USER -p tcp --syn -m limit --limit 30/second --limit-burst 40 \
  -j LOG --log-prefix "CONN: " --log-level 4
```

`--syn` матчит именно первый пакет TCP-хендшейка — то есть буквально любую
попытку соединения, даже если дальше сразу RST. `-m limit` — защита от
переполнения kernel-лога при реальном шторме пакетов; сам трафик при этом
не блокируется (`-j LOG` не терминальное действие, пакет идёт дальше как
обычно).

**2. Поставьте это на автозапуск после Docker**

Правила из `DOCKER-USER` переживают рестарт демона Docker, но **не переживают
перезагрузку сервера** (после ребута Docker создаёт цепочку заново пустой).
Поэтому добавьте systemd-юнит, который применяет скрипт после старта Docker:

```bash
sudo cp skipa-watchdog-fw-rules.service /etc/systemd/system/
sudo nano /etc/systemd/system/skipa-watchdog-fw-rules.service  # поправить путь ExecStart
sudo systemctl daemon-reload
sudo systemctl enable --now skipa-watchdog-fw-rules
```

**3. Проверьте, что записи реально появляются**

```bash
sudo journalctl -k -f
```
и с другого хоста дёрните любой порт:

```bash
curl -m 2 http://<ваш_ip>       # для 80/443
nc -zv <ваш_ip> 3000            # для докер-порта
```

Должна появиться строка вида:

```
CONN: IN=eth0 OUT= MAC=... SRC=203.0.113.42 DST=172.20.0.9 LEN=60 ... PROTO=TCP SPT=54321 DPT=80 ... SYN
```

`DST=` для докер-трафика будет **внутренний** IP контейнера (172.x.x.x) —
это нормально, бот парсит только `SRC=`, там всегда настоящий внешний IP
сканера.

**Если Docker не используется** и iptables у вас "чистый" (без `DOCKER-USER`) —
скрипт сам это определит и пропустит второй шаг, останется только правило
в INPUT (по сути превращается в вариант A, но через iptables вместо nft).

#### Нужны ли для этого какие-то особые пакеты/права рядом с Docker?

Нет, ничего сверх того, что у вас уже стоит вместе с Docker:

- **Отдельный nftables-пакет не нужен и не запускается** — в варианте B мы
  работаем только через команду `iptables` (её ставит сам Docker как
  зависимость), `systemctl enable nftables` тут не при чём и может даже
  конфликтовать, если параллельно поднимется отдельный демон nftables со
  своим rulebase.
- **conntrack/nat модули ядра** уже загружены и используются самим Docker
  (для проброса портов), дополнительно включать их не нужно.
- **Специальных capabilities/пакетов для скрипта не требуется** — `iptables`
  и `-m limit` есть в стандартной поставке `iptables`/`iptables-nft`
  практически на любом дистрибутиве с Docker.
- Единственное, что важно соблюсти — **порядок запуска**: правило в
  `DOCKER-USER` можно поставить только после того, как Docker создал эту
  цепочку, поэтому systemd-юнит явно объявляет `After=docker.service` и
  `Requires=docker.service`. Если применить скрипт раньше старта Docker —
  он просто не найдёт `DOCKER-USER` и пропустит этот шаг (сам скрипт это
  проверяет и не упадёт, но правило не встанет, пока вы не перезапустите
  юнит уже после старта Docker).
- Для самого бота (не для правил) права нужны такие же, как без Docker:
  либо root, либо членство в группе `systemd-journal` для чтения
  `journalctl -k`.

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
├── main.py                          # точка входа, команды бота, оркестрация job'ов
├── config.example.yaml              # шаблон конфига
├── config.yaml                      # ваш конфиг
├── requirements.txt
├── install-logging-rules.sh         # ставит iptables-правила логирования (INPUT + DOCKER-USER)
├── skipa-watchdog-fw-rules.service  # systemd-юнит: применяет правила после старта Docker
├── skipa-watchdog.service           # systemd-юнит: сам бот
├── bot/
│   ├── config.py            # загрузка config.yaml
│   ├── ip_lists.py          # скачивание/кэш/еженедельное обновление базы IP
│   ├── enrich.py            # ipinfo.io + RIPEstat + ipregistry.co
│   ├── formatter.py         # сборка текста алерта в нужном стиле
│   ├── monitor.py           # мониторинг: psutil и/или чтение kernel-лога
│   └── fallback.py          # audit-лог + очередь на повтор при недоступности Telegram
└── data/
    ├── ip_cache.json            # локальный кэш базы (создаётся автоматически)
    ├── alerts.log                # audit-журнал всех обнаружений (создаётся автоматически)
    └── pending_telegram.jsonl    # очередь неотправленных алертов (создаётся автоматически)
```
