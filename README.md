# Skipa Watchdog

Telegram-бот, который **постоянно** мониторит сетевые подключения к вашему
серверу и присылает уведомление, если источник входит в одну из баз
IP-адресов угроз. Встроенная база — CyberOK/Skipa/ГРЧЦ/НКЦКИ из репозитория
[tread-lightly/CyberOK_Skipa_ips](https://github.com/tread-lightly/CyberOK_Skipa_ips),
плюс опционально любые дополнительные источники (Spamhaus DROP, FireHOL,
AbuseIPDB и т.д. — см. раздел "Дополнительные источники IP").

Базы обновляются **раз в неделю** (настраивается), мониторинг соединений
идёт непрерывно (по умолчанию опрос раз в 5 секунд).

Кроме уведомлений бот умеет: банить обнаруженные IP (кнопкой под алертом
или автоматически), присылать статистику с графиком и еженедельный дайджест,
экспортировать историю в файл, следить за собственным здоровьем и
показывать простой веб-дашборд.

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

База: CyberOK/Skipa/ГРЧЦ/НКЦКИ | Совпадение: 203.0.113.0/24

[🚫 Забанить]
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

Если планируете пользоваться функцией бана (кнопка/автобан) — дополнительно
понадобится системный пакет `ipset`:
```bash
sudo apt install ipset   # Debian/Ubuntu
```
Для веб-дашборда и `/stats` дополнительных системных пакетов не нужно — всё
через `pip install -r requirements.txt` (FastAPI/uvicorn/matplotlib уже в списке).

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

- `/status` — сколько записей в базе (по каждому источнику отдельно), когда было
  последнее обновление, сколько алертов в очереди на повтор, сколько IP забанено
- `/update` — принудительно обновить все базы IP прямо сейчас
- `/testalert [ip]` — прислать тестовое уведомление в нужном формате с кнопкой
  бана (по умолчанию на примере `203.0.113.42`), удобно для проверки форматирования
- `/pending` — показать, сколько алертов сейчас застряло в очереди на повтор
  из-за недоступности Telegram (см. раздел "Если Telegram недоступен" ниже)
- `/stats [дней]` — статистика за период (по умолчанию 7 дней): уникальные IP,
  топ стран/организаций/баз/портов + столбчатый график активности по часам
- `/export [дней]` — выгрузить все события за период текстовым файлом (для отчётности)
- `/banlist` — кто сейчас забанен
- `/unban <ip>` — снять бан с IP
- `/start` — краткая справка

Если в `config.yaml` задан `telegram.admin_ids`, команды и кнопка "Забанить"
будут работать только для этих пользователей.

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

## Бан IP (кнопка / автобан / fail2ban)

Под каждым алертом (если включено `banning.enabled: true`) появляется кнопка
**🚫 Забанить** — нажатие сразу добавляет IP в бан, без захода на сервер.

### Как это работает технически

Баны хранятся в **ipset** — специальном наборе IP в ядре Linux, а не в виде
отдельного iptables-правила на каждый IP:

- одно правило `iptables ... -m set --match-set skipa_watchdog_ban src -j DROP`
  матчит весь набор сразу, вместо тысяч отдельных правил;
- ipset умеет автоматическое **истечение бана по таймауту** — не нужен
  отдельный планировщик, чтобы снимать временные баны, ядро само вычищает
  протухшие записи.

### Настройка (один раз)

```bash
sudo bash install-logging-rules.sh
```

Этот же скрипт (см. раздел про мониторинг выше) теперь дополнительно:
1. создаёт ipset-набор `skipa_watchdog_ban` (нужен пакет `ipset`: `sudo apt install ipset`);
2. добавляет DROP-правило по этому набору **первым** правилом в `INPUT` и
   `DOCKER-USER` — забаненные IP режутся сразу, ещё до правила логирования
   (значит, повторные попытки уже забаненного IP не засоряют лог новыми "CONN:" строками).

Дальше включите в `config.yaml`:

```yaml
banning:
  enabled: true
  manual_ban_duration_minutes: 1440   # 24 часа, 0 = навсегда
```

### Автоматический бан всех IP из базы

```yaml
banning:
  enabled: true
  auto_ban_new_hits: true
  auto_ban_duration_minutes: 60   # временный бан на час, 0 = навсегда
```

⚠️ **Риск**: это забанит **любой** IP, попавший в любую из подключённых баз,
без подтверждения человеком. Если вы сами используете сканеры вроде Shodan/
Censys/своих pentest-инструментов — они тоже попадут под раздачу. Начните
с ручного бана кнопкой, включайте автобан только когда уверены в базах.

### Проверить/снять бан

```
/banlist          - кто сейчас забанен
/unban 203.0.113.42
```

или напрямую:
```bash
sudo ipset list skipa_watchdog_ban
sudo ipset del skipa_watchdog_ban 203.0.113.42
```

Все действия (бан/разбан, кем и когда) логируются в `data/bans.jsonl`.

### Интеграция с fail2ban

Есть два независимых способа, выберите один:

**Способ 1 — зеркалирование (проще, рекомендуется).** Бот банит сам через
ipset (как описано выше) и дополнительно регистрирует тот же бан в указанном
fail2ban jail, чтобы он был виден в общей картине:

```yaml
banning:
  fail2ban_jail: "sshd"   # или свой отдельный jail
```

Бот вызовет `fail2ban-client set <jail> banip <ip>` / `unbanip` при каждом
бане/разбане. Реальная блокировка трафика при этом всё равно идёт через
ipset-правило бота — fail2ban здесь только для единого обзора.

**Способ 2 — fail2ban как единственный источник правды.** Если хотите, чтобы
именно fail2ban управлял банами (своим механизмом), а бот только поставлял
события — в папке `fail2ban/` есть готовый filter + jail, которые читают
`data/alerts.log`:

```bash
sudo cp fail2ban/skipa-watchdog.conf /etc/fail2ban/filter.d/
sudo cp fail2ban/jail-skipa-watchdog.local /etc/fail2ban/jail.d/
sudo nano /etc/fail2ban/jail.d/jail-skipa-watchdog.local   # поправить logpath
sudo systemctl restart fail2ban
sudo fail2ban-client status skipa-watchdog
```

При этом способе отключите `banning.auto_ban_new_hits` в конфиге бота, чтобы
не банить дважды (кнопка "Забанить" продолжит работать через ipset как обычно).

## Дополнительные источники IP

Кроме встроенной базы Skipa/ГРЧЦ/НКЦКИ, можно подключить любые другие списки —
каждый показывается в алерте отдельной строкой ("База: Spamhaus DROP") и
матчится тем же движком. Включаются в `config.yaml -> sources.extra`:

```yaml
sources:
  extra:
    - name: "spamhaus_drop"
      display_name: "Spamhaus DROP"
      type: "cidr_list"
      url: "https://www.spamhaus.org/drop/drop.txt"
      enabled: true

    - name: "firehol_level1"
      display_name: "FireHOL Level 1"
      type: "cidr_list"
      url: "https://iplists.firehol.org/files/firehol_level1.netset"
      enabled: true

    - name: "abuseipdb"
      display_name: "AbuseIPDB Blacklist"
      type: "abuseipdb"
      api_key: "ваш_ключ_с_abuseipdb.com"
      min_confidence: 90
      enabled: true
```

Типы источников:
- **`cidr_list`** — простой текстовый список (по одному CIDR/IP на строку,
  комментарии после `#` или `;` игнорируются). Подходит для Spamhaus DROP,
  FireHOL и большинства публичных блок-листов "как есть".
- **`abuseipdb`** — JSON blacklist API [AbuseIPDB](https://www.abuseipdb.com/),
  нужен свой бесплатный `api_key` (регистрация на сайте).

Обновляются вместе со встроенной базой — раз в неделю (`update_interval_days`)
либо по команде `/update`.

## Статистика и еженедельный дайджест

**`/stats [дней]`** (по умолчанию 7) — присылает текстовую сводку и
столбчатый график активности по часам суток:

- всего срабатываний и сколько из них уникальных IP;
- топ-5 стран, организаций/ASN, баз-источников и портов.

Данные берутся из `data/events.jsonl` — структурированного журнала, который
пишется параллельно с человекочитаемым `data/alerts.log` при каждом
обнаружении (см. `bot/events_store.py`).

**Еженедельный дайджест** — та же сводка, но приходит сама по расписанию,
не дожидаясь команды:

```yaml
digest:
  enabled: true
  weekday: 0   # 0=понедельник ... 6=воскресенье
  hour: 9
  minute: 0
```

## Веб-дашборд

Простая страница на FastAPI для тех, кому не хочется листать Telegram-чат:
статус базы (по источникам), последние события за 24 часа, список
забаненных IP и состояние мониторов (когда каждый в последний раз "тикал").

```yaml
dashboard:
  enabled: true
  host: "127.0.0.1"   # только локально по умолчанию
  port: 8080
  username: ""        # если оба поля заданы - спросит HTTP Basic Auth
  password: ""
```

По умолчанию слушает только `127.0.0.1` — доступ снаружи через SSH-туннель:

```bash
ssh -L 8080:localhost:8080 user@ваш-сервер
```
и открыть `http://localhost:8080/` у себя в браузере. Если хотите открыть
наружу (`host: "0.0.0.0"`) — обязательно задайте `username`/`password`,
иначе дашборд будет доступен всем без авторизации.

## Health-check ("watchdog для watchdog'а")

Каждый цикл мониторинга (psutil-опрос, чтение kernel-лога) на каждой
итерации отмечается через внутренний heartbeat. Отдельная фоновая задача
проверяет, что все ожидаемые мониторы "тикали" не позже
`stale_after_minutes` назад:

```yaml
healthcheck:
  enabled: true
  stale_after_minutes: 15
  check_interval_minutes: 5
```

Если монитор завис или упал без явной ошибки в логах — придёт
предупреждение в Telegram (`⚠️ монитор kernel_log не подавал признаков
жизни...`), и повторное сообщение `✅ снова в порядке`, когда он
восстановится. Это ловит ситуации, когда сам процесс бота жив (и systemd
не перезапускает его), но конкретный внутренний цикл незаметно упал.

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
├── install-logging-rules.sh         # ipset + DROP-правила бана + LOG-правила (INPUT + DOCKER-USER)
├── skipa-watchdog-fw-rules.service  # systemd-юнит: применяет правила после старта Docker
├── skipa-watchdog.service           # systemd-юнит: сам бот
├── fail2ban/
│   ├── skipa-watchdog.conf          # пример filter для fail2ban (альтернативный способ бана)
│   └── jail-skipa-watchdog.local    # пример jail для fail2ban
├── bot/
│   ├── config.py            # загрузка config.yaml
│   ├── ip_lists.py          # мульти-источники: Skipa + Spamhaus/FireHOL/AbuseIPDB, кэш, обновление
│   ├── enrich.py             # ipinfo.io + RIPEstat + ipregistry.co
│   ├── formatter.py          # сборка текста алерта в нужном стиле
│   ├── monitor.py            # мониторинг: psutil и/или чтение kernel-лога + heartbeat
│   ├── fallback.py           # audit-лог + очередь на повтор при недоступности Telegram
│   ├── events_store.py       # структурированный журнал событий (для /stats, /export, дашборда)
│   ├── banning.py            # бан/разбан через ipset + опциональное зеркалирование в fail2ban
│   ├── healthcheck.py        # heartbeat-реестр мониторов ("watchdog для watchdog'а")
│   ├── stats.py              # подсчёт статистики + рендер графика (matplotlib)
│   └── webapp.py             # веб-дашборд (FastAPI)
└── data/
    ├── ip_cache.json              # локальный кэш базы (создаётся автоматически)
    ├── alerts.log                 # человекочитаемый audit-журнал (создаётся автоматически)
    ├── events.jsonl               # структурированный журнал событий (создаётся автоматически)
    ├── pending_telegram.jsonl     # очередь неотправленных алертов (создаётся автоматически)
    └── bans.jsonl                 # журнал банов/разбанов (создаётся автоматически)
```
