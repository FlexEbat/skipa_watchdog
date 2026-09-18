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

### Быстрая установка через install.sh (рекомендуется)

Единый установщик и менеджер: ставит бота и/или лёгкий service-режим,
разворачивает systemd-юниты, при каждом запуске проверяет систему на
Docker/Kubernetes и предлагает донастроить логирование сканов на их
цепочки (DOCKER-USER / KUBE-*).

```bash
git clone https://github.com/FlexEbat/skipa_watchdog.git
cd skipa_watchdog
sudo bash install.sh
```

Откроется интерактивное меню:

```
 1) Версия
 2) Проверка работоспособности
 3) Управление сервисами (start/stop/restart)
 4) Установка/удаление бота (Telegram)
 5) Установка/удаление сервиса (лёгкий режим, без Telegram)
 6) Логирование Docker/Kubernetes (DOCKER-USER / KUBE-*)
 7) Принудительно обновить базу IP
 8) Просмотр логов
 9) Редактировать конфиг
10) Полное удаление (бот + сервис + конфиги)
 0) Выход
```

Есть и неинтерактивный режим для автоматизации:

```bash
sudo bash install.sh install-bot     # поставить/обновить Telegram-бота
sudo bash install.sh install-svc     # поставить/обновить лёгкий сервис
sudo bash install.sh status          # краткий статус без меню
sudo bash install.sh fw-rules        # поставить правила логирования docker/k8s
```

**Бот и сервис - два независимых режима, которые могут стоять на одном
сервере одновременно** (разные venv, разные systemd-юниты, разные
конфиги: `config.yaml` у бота и `service.yaml` у сервиса):

- **bot** (`skipa-watchdog-bot.service`, `main.py`) - полноценный
  Telegram-бот со всеми командами (см. ниже), качается через `git clone`
  в `venv-bot` вместе с `python-telegram-bot`.
- **service** (`skipa-watchdog-svc.service`, `watchdog_service.py`) -
  лёгкий режим без Telegram и без `python-telegram-bot`
  (`requirements-service.txt`): просто пишет каждое обнаружение в
  `/var/log/skipa_watchdog/detections.log` (+ обычный процесс-лог в
  `skipa-watchdog-svc.log`). Годится, если Telegram-уведомления не нужны,
  а нужен только факт детектирования для своей системы алертинга/SIEM.
  Конфиг - `service.example.yaml` → `service.yaml`, в большинстве случаев
  можно ничего не менять.

### Установка вручную (без install.sh)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt          # для бота
# или: pip install -r requirements-service.txt   # для лёгкого сервиса

cp config.example.yaml config.yaml       # для бота
# или: cp service.example.yaml service.yaml       # для сервиса
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
python main.py               # режим bot
# или
python watchdog_service.py   # режим service (без Telegram)
```

При первом запуске бот сразу скачает базу IP и закэширует её в `data/ip_cache.json`,
дальше будет обновлять её раз в неделю (`sources.update_interval_days` в конфиге).

## Дополнительные списки (blacklist)

Помимо `skipa_cidr.txt`/`skipa_range.txt` из
[tread-lightly/CyberOK_Skipa_ips](https://github.com/tread-lightly/CyberOK_Skipa_ips),
по умолчанию подключён ещё один список (`sources.blacklist_url` в конфиге,
можно оставить пустым, чтобы отключить). Формат смешанный и определяется
построчно: CIDR (`1.2.3.0/24`), диапазон (`1.2.3.10-1.2.3.20`) или
одиночный IP - всё принимается автоматически. В алерте и в `/status`
видно, из какого именно источника пришло совпадение (`skipa_cidr: ...`,
`skipa_range: ...` или `blacklist: ...` - имя настраивается через
`sources.blacklist_name`).

## Команды бота в Telegram

- `/menu` — меню с инлайн-кнопками (статус, обновить базу, очередь, Docker/K8s, помощь)
- `/status` — сколько записей в базе (с разбивкой по источникам), когда было последнее обновление, сколько алертов в очереди на повтор
- `/update` — принудительно обновить базу IP прямо сейчас
- `/testalert [ip]` — прислать тестовое уведомление в нужном формате (по умолчанию
  на примере `203.0.113.42`), удобно для проверки форматирования
- `/pending` — показать, сколько алертов сейчас застряло в очереди на повтор
  из-за недоступности Telegram (см. раздел "Если Telegram недоступен" ниже)
- `/env` — показать, обнаружены ли Docker/Kubernetes и стоит ли на их
  цепочках логирование сканов (см. следующий раздел)
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

> Начиная с `install.sh`, определять Docker/Kubernetes и ставить правила
> логирования на нужные цепочки (`INPUT`, `DOCKER-USER`,
> `KUBE-EXTERNAL-SERVICES`/`KUBE-NODEPORTS`) можно одной командой:
> `sudo bash install.sh` (пункт меню 6) или `sudo bash install.sh fw-rules`.
> Раздел ниже описывает, что происходит "под капотом", и пригодится, если
> нужно настроить всё вручную или разобраться в деталях.

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

### Kubernetes (NodePort/LoadBalancer)

Трафик на `NodePort`/`LoadBalancer`-сервисы k8s тоже не проходит через
обычный `INPUT` — он маршрутизируется через служебные цепочки kube-proxy.
`install-logging-rules.sh` (и `install.sh`, пункт меню 6) определяют это
автоматически и ставят то же самое правило логирования на:

- `KUBE-EXTERNAL-SERVICES` — современные версии k8s (iptables-режим kube-proxy);
- `KUBE-NODEPORTS` — более старые версии.

**Важно:** если kube-proxy работает в режиме **ipvs** (проверяется через
`ipvsadm -L -n`), цепочек `KUBE-*` в iptables нет вообще — в этом случае
скрипт выводит предупреждение и пропускает k8s-часть, логирование
NodePort-трафика через этот механизм недоступно, остаётся только
мониторинг хоста (`INPUT`). Посмотреть текущее состояние (что обнаружено
и что уже заармлено) можно командой `/env` в боте или `sudo bash
install.sh status`.

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
  `DOCKER-USER`/`KUBE-*` можно поставить только после того, как Docker/kubelet
  создали соответствующие цепочки, поэтому systemd-юнит явно объявляет
  `After=docker.service` (и `After=kubelet.service`, если он есть). Если
  применить скрипт раньше их старта — он просто не найдёт нужные цепочки и
  пропустит этот шаг (сам скрипт это проверяет и не упадёт, но правило не
  встанет, пока вы не перезапустите юнит уже после их старта).
- Для самого бота/сервиса (не для правил) права нужны такие же, как без
  Docker: либо root, либо членство в группе `systemd-journal` для чтения
  `journalctl -k`.

## Запуск как systemd-сервис

Проще всего через `sudo bash install.sh` (пункты меню 4/5) — он сам
скопирует нужный юнит, подставит пути и включит автозапуск. Вручную:

```bash
# режим bot
sudo cp skipa-watchdog-bot.service /etc/systemd/system/
sudo nano /etc/systemd/system/skipa-watchdog-bot.service   # поправить путь ExecStart
sudo systemctl daemon-reload
sudo systemctl enable --now skipa-watchdog-bot
sudo journalctl -u skipa-watchdog-bot -f

# режим service (лёгкий, без Telegram) - можно параллельно с bot
sudo cp skipa-watchdog-svc.service /etc/systemd/system/
sudo nano /etc/systemd/system/skipa-watchdog-svc.service   # поправить путь ExecStart
sudo systemctl daemon-reload
sudo systemctl enable --now skipa-watchdog-svc
sudo journalctl -u skipa-watchdog-svc -f
```

## Структура проекта

```
skipa_watchdog/
├── main.py                          # точка входа бота, команды, оркестрация job'ов
├── watchdog_service.py              # точка входа "лёгкого" service-режима (без Telegram)
├── install.sh                       # установщик/менеджер: меню + неинтерактивные команды
├── config.example.yaml              # шаблон конфига бота
├── config.yaml                      # ваш конфиг бота
├── service.example.yaml             # шаблон конфига service-режима
├── service.yaml                     # ваш конфиг service-режима
├── requirements.txt                 # зависимости бота (с python-telegram-bot)
├── requirements-service.txt         # зависимости service-режима (без python-telegram-bot)
├── VERSION                          # версия проекта (читается /status и install.sh)
├── install-logging-rules.sh         # ставит iptables-правила логирования (INPUT + DOCKER-USER + KUBE-*)
├── skipa-watchdog-fw-rules.service  # systemd-юнит: применяет правила после старта Docker
├── skipa-watchdog-bot.service       # systemd-юнит: бот (main.py)
├── skipa-watchdog-svc.service       # systemd-юнит: сервис (watchdog_service.py)
├── bot/
│   ├── config.py            # загрузка config.yaml/service.yaml
│   ├── ip_lists.py          # скачивание/кэш/обновление базы IP (cidr + range + blacklist)
│   ├── env_detect.py        # определение Docker/Kubernetes, состояние правил логирования
│   ├── enrich.py            # ipinfo.io + RIPEstat + ipregistry.co
│   ├── formatter.py         # сборка текста алерта в нужном стиле
│   ├── monitor.py           # мониторинг: psutil и/или чтение kernel-лога
│   └── fallback.py          # audit-лог + очередь на повтор при недоступности Telegram
├── data/                             # (режим bot) создаётся автоматически
│   ├── ip_cache.json            # локальный кэш базы
│   ├── alerts.log                # audit-журнал всех обнаружений
│   └── pending_telegram.jsonl    # очередь неотправленных алертов
└── /var/log/skipa_watchdog/          # (режим service) создаётся автоматически
    ├── skipa-watchdog-svc.log        # общий лог процесса
    └── detections.log                 # audit-журнал всех обнаружений (аналог alerts.log)
```

