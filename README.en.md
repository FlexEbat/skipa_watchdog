# Skipa Watchdog

**English** · [Русский](README.md) · [简体中文](README.zh-CN.md)

[![tests](https://github.com/FlexEbat/skipa_watchdog/actions/workflows/tests.yml/badge.svg)](https://github.com/FlexEbat/skipa_watchdog/actions/workflows/tests.yml)
[![license: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/FlexEbat/badge.svg)](https://hub.xerj.org/contributors/FlexEbat)

Skipa Watchdog blocks connections from known scanners (CyberOK/Skipa, GRCHTs, NKTsKI and extra lists) on
your server and, optionally, notifies you in Telegram or Matrix. Protection covers the host and services
published through Docker and Kubernetes.

- **Blocking in the kernel.** The lists are loaded into `ipset`, and a scanner is dropped on its first
  packet. There is no long-running process for blocking.
- **Bash only.** `iptables`, `ipset`, `curl`, `systemd`. Python is needed neither to install nor to run.
- **Fully automatic.** The list refreshes on a timer and blocking happens by itself; there is no manual
  block or unblock. The only manual lever is the allowlist.
- **Optional notifications.** Telegram and/or Matrix, one message per wave of scans. Without them the local
  logs still work.
- **Self-healing.** After a reboot the ipset sets and rules come back on their own.
- **Self-lockout protection.** Service networks and your own SSH sessions cannot be blocked.

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [Self-lockout protection](#self-lockout-protection)
- [Docker and Kubernetes](#docker-and-kubernetes)
- [Notifications: Telegram and Matrix](#notifications-telegram-and-matrix)
- [Extra sources](#extra-sources)
- [Operations](#operations)
- [Upgrading from the Python bot](#upgrading-from-the-python-bot)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## Quick start

You need root and `git` (`install.sh` installs it, plus `iptables`, `ipset` and `curl`, if missing).

```bash
curl -fsSL https://raw.githubusercontent.com/FlexEbat/skipa_watchdog/main/install.sh -o install.sh
sudo bash install.sh
```

The installer shows a description, downloads the lists, builds the `ipset` and applies the `iptables`
rules. The code goes to `/opt/skipa_watchdog`, logs go to `/var/log/skipa_watchdog`. Then manage it with:

```bash
sudo skipa-watchdog
```

Menu items: 1 health check, 2 service management, 3 detection settings, 4 notifications, 5 Docker/Kubernetes,
6 blocked IPs (view only), 7 allowlist, 8 statistics, 9 update the database, 10 logs, 11 edit the config,
12 update the project, 13 uninstall. On every launch the menu checks whether a new version is out and offers
to install it.

Without the menu:

```bash
sudo bash install.sh install       # install or update
sudo bash install.sh status        # short status
sudo bash install.sh fw-rules      # apply Docker/Kubernetes rules
sudo bash install.sh check-lists   # check for new list versions
sudo bash install.sh test-notify   # send a test message to Telegram/Matrix
sudo bash install.sh stats [days]  # detection statistics
sudo bash install.sh uninstall     # remove (offers to drop rules and ipsets)
```

**Right after installing, add your SSH IP** to the allowlist (menu item 7) if it is static.

<details>
<summary>Manual install without install.sh</summary>

```bash
sudo apt install ipset curl
cp config.example.yaml config.yaml && chmod 600 config.yaml
sudo bash service/sync-lists.sh config.yaml          # fill the ipset
sudo bash service/setup-ipset-rules.sh config.yaml   # iptables rules
sudo bash service/notify-tail.sh config.yaml         # (optional) detections.log and notifications
```

</details>

## How it works

```
IP lists ──► sync-lists.sh (timer) ──► ipset skipa-scanners ──► DROP in the kernel (INPUT, DOCKER-USER, KUBE-*)
                                                  │
                                 LOG rule ──► kernel log ──► notify-tail.sh ──► detections.log
                                                                           └──► Telegram / Matrix
```

**Blocking.** `iptables` rules match the source address against `ipset` sets: `skipa-scanners` (the lists),
`skipa-manual` (permanent blocks carried over from an older version) and `skipa-allow` (the allowlist). The
kernel decides everything; no userspace process is involved in blocking.

**Detection and notifications.** A LOG rule writes a scanner's first packet to the kernel log, and
`skipa-watchdog-notify.service` reads it (`journalctl -k`), writes `detections.log` and sends the
notification. The same IP is not logged or sent more often than once per `alert_cooldown_minutes`.

**Action modes** (`action.mode`, menu item 3):

| mode | blocking | logging and notifications |
| --- | --- | --- |
| `block_notify` (default) | yes | yes |
| `block` | yes | no (the `notify` daemon is not started) |
| `notify` | no | yes |

## Configuration

A single `config.yaml` (template: [`config.example.yaml`](config.example.yaml), every option is documented
in comments). The easiest way to change it is the menu; after editing by hand, apply the changes (menu item
11 offers to do it).

| key | default | purpose |
| --- | --- | --- |
| `action.mode` | `block_notify` | action mode |
| `sources.active_list` | `merged` | which lists to use: `list1`, `list2`, `merged` |
| `sources.primary_list_url`, `blacklist_url` | see template | list URLs |
| `sources.update_interval_days` | `7` | how often to refresh the database |
| `sources.min_prefix` | `20` | widest network accepted from lists (prefix length); use `16` for Spamhaus DROP |
| `sources.allow_insecure_http` | `false` | allow plain http list downloads (https only by default) |
| `sources.min_entries` | `10` | minimum entries in a source on the FIRST download (guards against a three-line junk list) |
| `sources.extra` | empty | extra sources |
| `firewall.keep_established_tcp` | `false` | do not cut established TCP sessions: block only new TCP connections (SYN) and all non-TCP traffic. Careful: a scanner that already opened a session keeps working inside it. Re-apply rules after changing (item 5) |
| `firewall.log_limit`, `log_burst` | `30/second`, `40` | LOG rule rate limit |
| `monitoring.ignore_ips` | empty | addresses that are never blocked |
| `monitoring.auto_allowlist`, `ssh_ports` | `true`, `[22]` | do not block IPs of current SSH sessions |
| `monitoring.alert_cooldown_minutes` | `60` | do not repeat an entry for the same IP more often |
| `monitoring.kernel_log_prefix` | `CONN: ` | LOG rule prefix in the kernel log |
| `telegram.*`, `matrix.*` | empty | notification channels |
| `notifications.batch_seconds`, `batch_max` | `30`, `20` | how long to collect messages and how many addresses to list |
| `notifications.language` | `ru` | message text language: `ru` or `en` |
| `environment.docker_scan`, `k8s_scan` | `true` | whether to attach rules to `DOCKER-USER` and `KUBE-*` |
| `logging.log_dir` | `/var/log/skipa_watchdog` | log directory |

Default sources:

- **List 1** — [tread-lightly/CyberOK_Skipa_ips](https://github.com/tread-lightly/CyberOK_Skipa_ips)
  (CyberOK/Skipa, GRCHTs, NKTsKI).
- **List 2** — a blacklist by [sngvy](https://gist.github.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8)
  (CIDRs, ranges and single IPs; includes scanner networks such as Censys).

Both are always downloaded; `active_list` picks which entries go into the set. If a source is unreachable or
returns half as many entries as before, its previous version is used. Networks wider than
`sources.min_prefix` are dropped, and a source that covers more than ~4 million addresses in total is
rejected, so a bloated third-party list cannot block half the internet. Lists are downloaded over https only
and a redirect to http is refused. Entries like `1.2.3.0/24/junk` are discarded entirely.

## Self-lockout protection

The lists are external and blocking is automatic, so these can never be blocked:

- loopback, private networks (`10/8`, `172.16/12`, `192.168/16`) and link-local;
- addresses from `monitoring.ignore_ips`;
- IPs with open SSH sessions on `monitoring.ssh_ports` (`monitoring.auto_allowlist`), added once a minute by
  `skipa-watchdog-allow-ssh.timer`;
- networks shorter than `/16` (including `0.0.0.0/0`), IPv6 and anything that overlaps the allowlist.

## Docker and Kubernetes

Traffic to published container ports goes through the `FORWARD` chain, not `INPUT`. So the rules are attached
to `DOCKER-USER` and, if present, `KUBE-EXTERNAL-SERVICES` and `KUBE-NODEPORTS`. The installer finds them on
its own; re-apply the rules from the menu (item 5) or with `sudo bash install.sh fw-rules`. To turn the
chains off: `environment.docker_scan: false`, `environment.k8s_scan: false`.

## Notifications: Telegram and Matrix

Notifications are send-only: there are no chat commands, no bot to manage, and no Python. Everything is done
by `curl` from bash. Set up with menu item 4 (tokens are typed without echo and format-checked before they
are written to `config.yaml`) and verify with `sudo bash install.sh test-notify`.

**Telegram.** Create a bot with [@BotFather](https://t.me/BotFather), add it to a chat or channel and give
the token and `chat_id` (negative for groups). If Telegram is not reachable directly, set `telegram.proxy`
(`http://`, `https://`, `socks5://`, `socks5h://`).

**Matrix.** You need the homeserver address (`https://matrix.example.org`; `http` is allowed only for
localhost), an `access_token` of a user or bot, and a `room_id` like `!abc:example.org` (not a `#room`
alias). The user must already be a member of the room.

Both channels can be enabled at once. What is guaranteed:

- **One message per wave.** Detections are collected for `notifications.batch_seconds` (30 by default) and
  sent as a list of up to `batch_max` addresses; the rest is a trailing "and N more" line.
- **Queue with retries.** A message is first put in a queue (`/var/lib/skipa_watchdog/notify-spool`), one
  file per channel. Network errors and 5xx responses are retried in order; on 429 the `retry_after` pause is
  honoured (at most 60 s). If the server answers 400/401/403/404 (wrong token, chat or room) the message is
  dropped with a line in `skipa-watchdog.log` instead of piling up forever. Messages older than a day and
  anything beyond 200 files are dropped. Matrix gets the same `txnId` on a retry, so there are no duplicates.
- **Secrets stay out of `ps`.** The URL with the token and the `Authorization` header are passed to `curl`
  through stdin (`-K -`), not as arguments.
- **Plain text.** No HTML or Markdown, so there is nothing to escape.

Example message:

```
Skipa Watchdog @ my-server
Scanners detected: 3 (blocked by the kernel)
• 203.0.113.42  TCP/22
• 203.0.113.43  TCP/443
• 198.51.100.7  UDP/3478
```

The message text is Russian by default; set `notifications.language: "en"` for English. Notifications are sent by the `skipa-watchdog-notify` daemon,
which runs only when `action.mode` includes notifying (`notify`, `block_notify`). If you enable a channel while
the mode is `block`, the menu offers to switch to `block_notify`.

## Extra sources

`sources.extra` in `config.yaml`: Spamhaus DROP, FireHOL, AbuseIPDB or your own list. Types are `cidr_list`
(a plain text list, comments with `#` and `;`) and `abuseipdb` (needs your own `api_key`, field
`min_confidence`); each can set `min_entries`. They take part regardless of `active_list` as long as
`enabled: true`. IPv4 only: IPv6 entries are skipped with a log line.

Fail2ban can be used instead of kernel blocking: the filter and jail in [`fail2ban/`](fail2ban) ban based on
`detections.log`.

## Operations

**Logs.**

| what | where |
| --- | --- |
| detections | `/var/log/skipa_watchdog/detections.log` |
| process, notification errors | `/var/log/skipa_watchdog/skipa-watchdog.log` |
| list and daemon | `journalctl -u skipa-watchdog-sync-lists -u skipa-watchdog-notify` |

Log rotation (`/etc/logrotate.d/skipa-watchdog`) is installed by the installer.

**Reboot and rules.** ipset sets and rules live only in kernel memory, so they are saved and restored at boot
(`/var/lib/skipa_watchdog/ipsets.save`, updated after every sync and every allowlist change):

- `skipa-watchdog-ipset.service` — early, before `netfilter-persistent`: restores the sets (or creates empty
  ones if there is no file). This matters: if saved rules reference `skipa-*` while the sets do not exist
  yet, `iptables-restore` rejects the whole rules file and the server is left without a firewall at all;
- `skipa-watchdog-rules.service` — later, after Docker and kubelet (they need the `DOCKER-USER` and `KUBE-*`
  chains): applies the rules and verifies the result;
- `skipa-watchdog-sync-lists.timer` refreshes the lists 10 minutes after boot and then on schedule.

A single unit will not do: `After=docker.service` together with `Before=netfilter-persistent.service` forms
an ordering cycle, and systemd would break it by deleting a random job.

All set operations (timer, menu item 9, `blockctl.sh`, rule application, boot) run under one `flock`
(`/var/lib/skipa_watchdog/ipset.lock`), so they never overlap. After applying the rules the script verifies
the sets exist and that rules are present in `INPUT`, `DOCKER-USER` and `KUBE-*`, and reports the result
(`✓`/`✗`); menu item 1 shows the same.

**Allowlist.** Menu item 7 or `sudo bash service/blockctl.sh allow|unallow|allowlist [ip]`: written to
`config.yaml` and to the `ipset` immediately. There is no manual block or unblock: everything is automatic.

**Units.** They run as root (they need `iptables`, `ipset` and the kernel log). systemd restrictions that do
not get in the way are enabled: `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `ProtectSystem=full`,
`RestrictNamespaces`, `RestrictAddressFamilies` and so on; the notification daemon additionally has
`ProtectKernelModules`/`ProtectKernelTunables`. A strict sandbox is not used for the units that call
`iptables`: it loads kernel modules, and the sandbox broke startup on some systems.

**Updating.** On every launch of the panel (`sudo skipa-watchdog`) it checks whether a new version is out and
offers to install it; declining is not permanent: a reminder stays in the menu header.
`SKIPA_NO_UPDATE_CHECK=1` turns the check off once, `sudo bash install.sh check-update` checks without
prompts (exit code 10 means an update is available). Manually: menu item 12 or `sudo bash install.sh install`.
If `git pull` fails (the repository history changed), the installer offers to move to the current version:
`config.yaml` and `data/` are not touched.

**Uninstalling.** Menu item 13. The installer separately asks whether to remove the `iptables` rules and
`ipset` sets.

## Upgrading from the Python bot

Starting with 4.0 Python is gone from the project. If you had the "service + Telegram bot" variant, updating
(`sudo skipa-watchdog` → item 12, or `sudo bash install.sh install`) moves it to bash by itself with no gap in
protection: the bash units and `ipset` rules come up first, and only then are the bot's unit, the
`SKIPA-BLOCK` chain and the `skipa-dyn`/`skipa-db` sets removed, and the venv is deleted.

- **Kept:** `config.yaml` (the Telegram token and `chat_id` keep working as notifications), `data/`, the
  allowlist and permanent manual blocks (they move into `skipa-manual`).
- **Gone:** time-limited blocks (including auto-blocks; they would expire anyway), chat commands (`/block`,
  `/allow`, `/stats` and others), the "Ban" button, the dashboard, alert enrichment (country, ASN), the weekly
  digest and the bot's health check. The allowlist replaces manual blocking; the rest is no longer needed.

## Security

- `config.yaml` holds tokens: the installer sets mode `600`, and warns if it holds secrets with other
  permissions.
- Tokens are passed to `curl` via stdin, not as arguments, and are not visible in `ps`.
- Values entered in the menu are format-checked before they are written (Telegram token, `chat_id`,
  `homeserver`, `room_id`), and writing to `config.yaml` does not expand `\n` and rejects quotes, backslashes
  and newlines that could be used to smuggle in extra keys.
- The kernel log is stripped of control characters before it goes to `detections.log` (otherwise adjacent
  entries could be forged for fail2ban).
- Self-lockout protection is described above. If you still get locked out, log in through the host console and
  run `sudo skipa-watchdog`: add your IP to the allowlist (item 7); item 13 removes the project with its rules.
- Updating the project is a `git pull` from the repository as root: whoever controls the repository controls
  your servers. Enable 2FA on the GitHub account, and point `SKIPA_REPO_URL` at your own fork if you want to
  read changes before updating.
- Report vulnerabilities to the repository owner privately, not in public issues.

## Troubleshooting

**A notification came for an IP that is "not in the rules".** Check whether the address belongs to one of the
lists, including ranges in the second list:

```bash
sudo ipset test skipa-scanners 66.132.186.215
```

Scanner networks in the lists are wider than one address: for example `66.132.186.215` falls inside
`66.132.186.0/24` from the second list. Any packet from a scanner creates an entry: the LOG rule fires on all
protocols (`detections.log` shows `proto=UDP port=3478`), and the packet is dropped after logging.

**Notifications do not arrive.** Menu item 4 → "Send a test message" reports each channel: "delivered",
"server rejected the request" (wrong token, `chat_id` or room) or "no connection". Also check that
`action.mode` is not `block` and that the daemon is alive: `systemctl status skipa-watchdog-notify`. Sending
errors go to `skipa-watchdog.log`. Menu item 1 shows the size of the queue of unsent messages.

**False positive on a legitimate scanner** (for example your security monitoring): add its IP to the
allowlist (item 7).

**Blocking does not work for containers.** Open menu item 5 → "Show current rules": the rules must also be in
`DOCKER-USER`. If Docker started later, re-apply the rules (item 5; at boot `skipa-watchdog-rules.service`
does it).

## Development

```bash
python3 -m unittest discover -s tests -t .     # 100+ tests, no root needed
shellcheck -S warning install.sh service/*.sh
```

The project itself is pure bash; Python is needed only by the tests (they run the bash scripts) and PyYAML to
check `config.yaml`. The tests replace `iptables`, `ipset`, `curl` and `journalctl` with fakes
([`tests/netfake.py`](tests/netfake.py) and stub scripts inside the tests) and never touch the real firewall
or network. The end-to-end scenario on real `ipset`/`iptables` (reboot, `iptables-restore`, flock) is opt-in
because it changes the host's sets and rules:
`SKIPA_REAL_NETFILTER_TESTS=1 python3 -m unittest tests.test_real_netfilter` as root in a disposable
environment.

Layout:

```
install.sh             installer and menu
service/               scripts: lists, rules, notifications, config.yaml reader, allowlist
fail2ban/              filter and jail (alternative way to ban)
tests/                 tests
config.example.yaml    config template
```

## License

[GNU GPLv3](LICENSE). Derivative works are distributed under the same open-source license.
