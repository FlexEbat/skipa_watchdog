# Skipa Watchdog

[English](README.en.md) · **Русский** · [简体中文](README.zh-CN.md)

[![tests](https://github.com/FlexEbat/skipa_watchdog/actions/workflows/tests.yml/badge.svg)](https://github.com/FlexEbat/skipa_watchdog/actions/workflows/tests.yml)
[![license: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/FlexEbat/badge.svg)](https://hub.xerj.org/contributors/FlexEbat)

Skipa Watchdog находит на вашем сервере подключения от известных сканеров
(CyberOK/Skipa, ГРЧЦ, НКЦКИ и дополнительные списки), блокирует их и/или присылает
уведомление. Защита работает на хосте и для сервисов, опубликованных через Docker и
Kubernetes.

- **Блокировка в ядре.** Весь список загружается в `ipset`, сканер отсекается на
  первом пакете.
- **Один конфиг.** `config.yaml` читают оба варианта установки.
- **Telegram по желанию.** Без него всё работает через локальные логи.
- **Самовосстановление.** После перезагрузки, рестарта Docker или `ufw reload`
  правила возвращаются сами (в варианте с Telegram).
- **Защита от самоблокировки.** Служебные сети и ваши SSH-сессии заблокировать нельзя.

## Содержание

- [Варианты установки](#варианты-установки)
- [Быстрый старт](#быстрый-старт)
- [Как это работает](#как-это-работает)
- [Конфигурация](#конфигурация)
- [Защита от самоблокировки](#защита-от-самоблокировки)
- [Docker и Kubernetes](#docker-и-kubernetes)
- [Telegram](#telegram)
- [Дополнительные возможности](#дополнительные-возможности)
- [Эксплуатация](#эксплуатация)
- [Безопасность](#безопасность)
- [Вопросы и проблемы](#вопросы-и-проблемы)
- [Разработка](#разработка)
- [Лицензия](#лицензия)

## Варианты установки

| | Только сервис | Сервис + Telegram |
| --- | --- | --- |
| Реализация | bash, `iptables`, `ipset` | `watchdog.py` (Python 3.10+), venv |
| Python | не нужен | нужен |
| Блокировка | в ядре, список обновляет systemd-таймер | в ядре, процесс сам обновляет и чинит правила |
| Уведомления | запись в `detections.log` | `detections.log` и сообщения в Telegram |
| Кнопка «Забанить», `/stats`, дашборд, health-check | нет | да |
| Дополнительные источники (`sources.extra`) | нет | да |

Начать можно с первого варианта и подключить Telegram позже из меню. Обратно на чистый
bash переключиться нельзя: удалите установку и поставьте заново.

## Быстрый старт

Нужен root и `git` (если его нет, `install.sh` доустановит сам).

```bash
curl -fsSL https://raw.githubusercontent.com/FlexEbat/skipa_watchdog/main/install.sh -o install.sh
sudo bash install.sh
```

Установщик покажет описание, спросит вариант установки и применит правила `iptables`.
Код ставится в `/opt/skipa_watchdog`, логи пишутся в `/var/log/skipa_watchdog`.
Дальше управляйте командой:

```bash
sudo skipa-watchdog
```

В меню у каждого пункта есть выход (`0`), а каждое изменяющее действие просит
подтверждения. Пункты: проверка работоспособности, управление сервисом, настройки
обнаружения, Telegram, Docker/Kubernetes, заблокированные IP, обновление базы, логи,
редактирование конфига, обновление проекта, удаление.

Без меню:

```bash
sudo bash install.sh install       # установить или обновить
sudo bash install.sh status        # краткий статус
sudo bash install.sh fw-rules      # применить правила Docker/Kubernetes
sudo bash install.sh check-lists   # проверить новые версии списков
sudo bash install.sh uninstall     # удалить (с предложением убрать правила и ipset)
```

**Сразу после установки впишите свой SSH-IP** в `monitoring.ignore_ips` в
`/opt/skipa_watchdog/config.yaml`, если он статический.

<details>
<summary>Установка вручную, без install.sh</summary>

Только сервис:

```bash
sudo apt install ipset curl
cp config.example.yaml config.yaml && chmod 600 config.yaml
sudo bash service/sync-lists.sh config.yaml          # заполнить ipset
sudo bash service/setup-ipset-rules.sh config.yaml   # правила iptables
sudo bash service/notify-tail.sh config.yaml         # (опционально) запись detections.log
```

С Telegram:

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt -r requirements-telegram.txt
cp config.example.yaml config.yaml && chmod 600 config.yaml   # заполнить telegram.*
sudo bash install-firewall-rules.sh
python watchdog.py config.yaml
```

</details>

## Как это работает

```
списки IP ──► база (кэш data/ip_cache.json) ──► ipset skipa-db ──► отсечение в ядре
                      │
 poll (/proc/net/tcp, conntrack) ─┐
                                  ├─► совпадение ─► блокировка + detections.log + Telegram
 kernel_log (LOG-правило) ────────┘                 (что именно, решает action.mode)
```

**Обнаружение** (`monitoring.method`):

| метод | как | что видит |
| --- | --- | --- |
| `poll` | читает `/proc/net/tcp` и conntrack ядра раз в `poll_interval_seconds` | входящие соединения, трафик на порты контейнеров Docker, короткие сканы |
| `kernel_log` | читает журнал ядра, куда пишет LOG-правило iptables | каждый первый пакет сканера, мгновенно |
| `both` (по умолчанию) | оба | всё перечисленное |

**Блокировка.** Правила лежат в отдельной цепочке `SKIPA-BLOCK`, на которую ведут
переходы из `INPUT`, `DOCKER-USER` и `KUBE-*`. Если установлен `ipset`, вся база
загружена в набор `skipa-db`, динамические блокировки (с таймаутом) лежат в
`skipa-dyn`, свои адреса в `skipa-allow`. Без `ipset` на каждый IP создаётся отдельное
правило `DROP`.

**Режимы действия** (`action.mode`):

| режим | блокировка | уведомление |
| --- | --- | --- |
| `block_notify` (по умолчанию) | да | да |
| `block` | да | только запись в журнал |
| `notify` | нет | да |

## Конфигурация

Единый файл `config.yaml` (шаблон: [`config.example.yaml`](config.example.yaml), все
параметры там описаны комментариями). Вариант «только сервис» читает из него подмножество,
которое отмечено в последней колонке.

| ключ | по умолчанию | назначение | bash |
| --- | --- | --- | --- |
| `action.mode` | `block_notify` | режим действия | да |
| `action.block_timeout_hours` | `72` | срок автоблокировки, `0` — бессрочно | нет |
| `action.preload_db` | `true` | загружать всю базу в ipset заранее | нет |
| `sources.active_list` | `merged` | какие списки использовать: `list1`, `list2`, `merged` | да |
| `sources.primary_list_url` / `blacklist_url` | см. шаблон | адреса списков | да |
| `sources.update_interval_days` | `7` | как часто обновлять базу | да |
| `sources.extra` | пусто | дополнительные источники | нет |
| `monitoring.method` | `both` | `poll`, `kernel_log`, `both` | нет |
| `monitoring.ignore_ips` | пусто | адреса, которые не блокируются | да |
| `monitoring.alert_cooldown_minutes` | `60` | не повторять запись по одному IP чаще | да |
| `monitoring.use_conntrack` | `true` | `poll` читает ещё и conntrack | нет |
| `monitoring.auto_allowlist` | `true` | не блокировать IP текущих SSH-сессий | нет |
| `telegram.bot_token`, `chat_id`, `admin_ids` | пусто | подключение Telegram | нет |
| `firewall.log_limit`, `log_burst` | `30/second`, `40` | лимит LOG-правила | да |
| `logging.log_dir` | `/var/log/skipa_watchdog` | каталог логов | да |

Источники по умолчанию:

- **Список 1** — [tread-lightly/CyberOK_Skipa_ips](https://github.com/tread-lightly/CyberOK_Skipa_ips)
  (CyberOK/Skipa, ГРЧЦ, НКЦКИ).
- **Список 2** — blacklist от [sngvy](https://gist.github.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8)
  (CIDR, диапазоны и одиночные IP; включает сети сканеров вроде Censys).

Оба скачиваются всегда, `active_list` выбирает, какие записи попадут в базу. Если
источник недоступен или вернул вдвое меньше записей, чем раньше, используется его прошлая
версия, а неполная база перепроверяется через час. Сети шире `/16` из списков отбрасываются.

Менять настройки можно из меню (пункт 3: источник списка, режим действия, метод обнаружения; пункт 9: правка файла) или вручную; после правки примените
изменения через меню либо `sudo systemctl restart skipa-watchdog`.

## Защита от самоблокировки

Списки внешние, а блокировка автоматическая, поэтому заблокировать нельзя:

- loopback, частные сети (`10/8`, `172.16/12`, `192.168/16`) и link-local;
- адреса из `monitoring.ignore_ips`;
- IP с открытыми SSH-сессиями на `monitoring.ssh_ports` (`monitoring.auto_allowlist`);
- сети короче `/16` (в том числе `0.0.0.0/0`), IPv6 и всё, что пересекается с allowlist.

Метод `poll` учитывает только входящие соединения: исходящие подключения самого сервера
сканерами не считаются.

## Docker и Kubernetes

Трафик на опубликованные порты контейнеров идёт через цепочку `FORWARD`, а не `INPUT`.
Поэтому переход в `SKIPA-BLOCK` ставится и в `DOCKER-USER`, и (если есть) в
`KUBE-EXTERNAL-SERVICES`, `KUBE-NODEPORTS`. Установщик находит их сам; повторно применить
правила можно из меню (пункт 5) или `sudo bash install.sh fw-rules`. Отключить цепочки:
`environment.docker_scan: false`, `environment.k8s_scan: false`.

В `/proc/net/tcp` хоста такой трафик не виден, поэтому `poll` читает conntrack ядра
(нужен root), а `kernel_log` работает через LOG-правило на `DOCKER-USER`.

## Telegram

Подключается из меню (пункт 4) или в `config.yaml`: `telegram.bot_token` (от
[@BotFather](https://t.me/BotFather)), `chat_id` и `admin_ids`. Пустой `admin_ids` означает,
что команды принимаются только из чата `chat_id`. Если Telegram недоступен напрямую,
задайте `telegram.proxy` (для `socks5://` нужен `pip install "python-telegram-bot[socks]"`).

Недоступный Telegram не останавливает защиту: слой поднимается в фоне с повторами, а
неотправленные алерты ждут в очереди (до 500 штук, до недели).

| команда | действие |
| --- | --- |
| `/menu`, `/status` | меню, состояние базы, правил и мониторов |
| `/update` | обновить базу сейчас |
| `/blocklist` (`/banlist`) | список блокировок |
| `/block <ip или сеть> [часы]` | заблокировать (по умолчанию бессрочно) |
| `/unblock <ip>` (`/unban`) | разблокировать |
| `/stats [дней]`, `/export [дней]` | статистика с графиком и выгрузка событий |
| `/testalert [ip]` | тестовое уведомление |
| `/pending`, `/env` | очередь неотправленных алертов, окружение Docker/Kubernetes |

Пример уведомления (значения из диапазонов для документации, RFC 5737 и RFC 5398):

```
🚨 УГРОЗА. СКАНЕР ОБНАРУЖЕН - IP

IP: 203.0.113.42
▢ MaxMind & IPinfo & Cloudflare:
🇩🇪 DE Germany, Bavaria, Example City
AS64500 / Example Hosting GmbH
База: Skipa | Совпадение: 203.0.113.0/24

🚫 IP заблокирован.
```

## Дополнительные возможности

Работают в варианте с Telegram и включаются в `config.yaml`.

- **Дополнительные источники** (`sources.extra`): Spamhaus DROP, FireHOL, AbuseIPDB или свой
  список. Каждый показывается в алерте под своим именем.
- **Бан по кнопке** (`banning.enabled`): под алертом появляется «🚫 Забанить»
  (срок `manual_ban_duration_minutes`). `auto_ban_new_hits` банит каждый найденный IP сам,
  `fail2ban_jail` дублирует бан в fail2ban. История пишется в `data/bans.jsonl`. Альтернатива:
  фильтр и jail в [`fail2ban/`](fail2ban), которые банят по `detections.log`.
- **Статистика** (`/stats`, `/export`, еженедельный дайджест `digest.*`): события пишутся
  в `data/events.jsonl`. График рисует `matplotlib` (`pip install -r requirements-extras.txt`),
  без него приходит текстовая гистограмма.
- **Дашборд** (`dashboard.enabled`): страница со статусом базы, событиями, блокировками и
  состоянием мониторов. Слушает `127.0.0.1`, открывайте через SSH-туннель
  `ssh -L 8080:localhost:8080 user@server`. Вне localhost задайте `username`/`password`
  (HTTP Basic Auth) и держите за прокси с TLS.
- **Health-check** (`healthcheck.*`): если монитор молчит дольше `stale_after_minutes`,
  приходит предупреждение, а при восстановлении — сообщение об этом.

## Эксплуатация

**Логи.**

| что | где |
| --- | --- |
| обнаружения | `/var/log/skipa_watchdog/detections.log` |
| процесс | `/var/log/skipa_watchdog/skipa-watchdog.log`, `journalctl -u skipa-watchdog` |
| списки и таймер (только сервис) | `journalctl -u skipa-watchdog-sync-lists -u skipa-watchdog-notify` |

**Перезагрузка и правила.** Вариант с Telegram сам проверяет и чинит переходы и ipset раз
в `monitoring.guard_interval_seconds` (60 с), дополнительно ставится юнит
`skipa-watchdog-fw-rules.service`. В варианте «только сервис» `skipa-watchdog-sync-lists.timer`
перезаполняет ipset через 10 минут после загрузки и затем по расписанию, а `iptables`-правила
нужно сохранять средствами системы (`iptables-persistent`) или запускать
`sudo bash install.sh fw-rules` после перезагрузки.

**Ручная блокировка.** Из меню (пункт 6), командой `/block` в Telegram либо
`sudo bash /opt/skipa_watchdog/service/blockctl.sh {block|unblock|list} [ip]`.
Блокировки варианта с Telegram сохраняются в `data/blocked_ips.json` и восстанавливаются при
старте.

**Служба.** `skipa-watchdog.service` запускается от root без песочницы: ему нужны
`iptables`, `ipset`, чтение conntrack и запись в каталог установки и логи.

**Обновление.** Пункт 10 меню или `sudo bash install.sh install`. Если `git pull` не проходит (история в репозитории изменилась), установщик предложит перейти на актуальную версию: `config.yaml` и `data/` не затрагиваются.

**Удаление.** Пункт 11 меню. Установщик отдельно спросит, убрать ли правила `iptables`
и наборы `ipset`.

## Безопасность

- `config.yaml` содержит токен бота: установщик выставляет права `600`.
- Токен бота и ключи API маскируются в журналах (`skipa-watchdog.log`, `journalctl`).
- Команды бота принимают только администраторы (`admin_ids`, либо чат `chat_id`).
- Защита от самоблокировки описана выше. Если вас всё же отрезало, зайдите через консоль
  хоста и выполните `sudo skipa-watchdog`: пункт 6 снимает блокировку конкретного IP, пункт 11
  удаляет проект вместе с правилами.
- Данные внешних API (организация, ASN) экранируются в Telegram и на странице дашборда, а из текстовых
  журналов из них убираются переводы строк и управляющие символы (иначе владелец сети мог бы подсунуть
  fail2ban поддельную строку с чужим IP).
- Дашборд без `username` открыт всем, кто достучался до порта: не публикуйте его в интернет. Если
  `dashboard.host` не петлевой, а логина нет, дашборд сам слушает только `127.0.0.1` и пишет об этом в журнал.
- Об уязвимостях сообщайте владельцу репозитория лично, не в публичных issue.

## Вопросы и проблемы

**Пришёл алерт на IP, которого «нет в правилах».** Проверьте, входит ли адрес в какой-то из
списков, включая диапазоны во втором списке:

```bash
sudo ipset test skipa-scanners 66.132.186.215        # только сервис
sudo ipset test skipa-db 66.132.186.215              # сервис + Telegram (ipset)
```

Сети сканеров в списках шире одного адреса: например, `66.132.186.215` входит в
`66.132.186.0/24` из второго списка. Сработавшая сеть указана в алерте и в `detections.log`.
Запись создаёт любой пакет от сканера: в варианте «только сервис» LOG-правило срабатывает
на все протоколы (в `detections.log` видно `proto=UDP port=3478`), а пакет после записи
отбрасывается.

**Меню пишет, что INPUT не подключён, хотя правила стоят.** Обновите проект
(пункт 10). Проверка раньше искала правила только в старой форме, теперь она ищет любые
правила проекта в цепочке.

**Сервис не запускается.** `journalctl -u skipa-watchdog -n 50`. Частые причины: нет
`ipset` (сервис работает в упрощённом режиме iptables), неверный `config.yaml`, занят порт
дашборда.

**Ложное срабатывание на легитимный сканер** (например, ваш мониторинг безопасности):
добавьте его IP в `monitoring.ignore_ips`.

**Блокировка не работает для контейнеров.** Откройте пункт 5 меню → «Показать текущие
правила»: переход в `SKIPA-BLOCK` должен быть и в `DOCKER-USER`. Docker, запущенный после
сервиса, подхватывается в течение минуты.

## Разработка

```bash
python3 -m unittest discover -s tests -t .     # 80+ тестов, root не нужен
shellcheck -S warning service/*.sh install-firewall-rules.sh
```

Тесты подменяют `iptables` и `ipset` имитацией ([`tests/fakes.py`](tests/fakes.py)); CI
запускает их на Python 3.10–3.13 вместе с `bash -n` и `shellcheck`.

Структура:

```
watchdog.py            точка входа варианта с Telegram
install.sh             установщик и меню
bot/                   Python-модули (мониторинг, блокировка, списки, Telegram, дашборд)
service/               bash-вариант и общая библиотека чтения config.yaml
fail2ban/              фильтр и jail (альтернативный способ бана)
tests/                 тесты
config.example.yaml    шаблон единого конфига
```

## Лицензия

[GNU GPLv3](LICENSE). Производные работы распространяются под той же лицензией с открытым
исходным кодом.
