## Настройка через браузер (рекомендуется)

Теперь токены и параметры SSH можно ввести через веб-интерфейс, без `export` и
редактирования конфигурационных файлов:

```sh
go run . -fleet -web-addr 127.0.0.1:8080
```

1. Откройте `http://127.0.0.1:8080/fleet/settings` и войдите администратором.
2. Заполните Hetzner Robot, при необходимости Hetzner Cloud, или Selectel.
3. Укажите SSH-пользователя, абсолютный путь к ключу (или оставьте пустым для
   ssh-agent) и интервал.
4. Нажмите **«Проверить API и сохранить»** либо **«Сохранить»**.
5. Откройте `/fleet`: новый опрос запускается без перезапуска.

Пустые поля паролей/токенов сохраняют прежние секреты. Для удаления
сохранённых данных поставьте отдельный флажок провайдера. API-проверка не
подключается к хостам по SSH: корректность SSH будет показана лампочкой
после опроса. Требуется предварительно проверить SSH host fingerprints
и добавить их в `known_hosts` на машине с chicha-pulse.

Секреты шифруются AES-GCM; файл и отдельный ключ доступны владельцу
с правами `0600`. По умолчанию используются пользовательские
конфигурационные каталоги ОС. Для системной службы задайте путь
`CHICHA_FLEET_SETTINGS_FILE=/var/lib/chicha-pulse/fleet-settings.enc` и
выдайте пользователю службы права на каталог. Оба файла необходимо
резервировать вместе.

Доступ к странице настроек имеют только администраторы. Внешний доступ
разрешайте исключительно через HTTPS или VPN. Сервисная учётная запись
Selectel с паролем предпочтительна временного IAM-токена: токен будет
обновляться при каждом новом цикле инвентаризации.

---

# Live fleet dashboard

In addition to the one-shot export below, chicha-pulse now has a built-in,
continuously refreshed **/fleet** dashboard. The existing monitoring, Nagios
import, authentication, roles and main homepage remain available.

### Start the web dashboard

Configure provider credentials as shown below, make sure the monitor machine
can log into each target with a verified SSH host key, then run:

```sh
go run . -fleet -web-addr 127.0.0.1:8080 \
  -fleet-ssh-user inventory \
  -fleet-ssh-key ~/.ssh/id_ed25519 \
  -fleet-interval 90s
```

Open http://127.0.0.1:8080/fleet using the existing chicha-pulse HTTP
Basic Auth credentials (on first setup, the generated superuser credentials
appear in the startup log). Serve over HTTPS or a trusted VPN when accessed
remotely; **never transmit Basic Auth over plain HTTP across the internet**.

Each host has a live green (last SSH succeeded), red (failed) or amber (not
verified, e.g. host key or credentials missing) indicator. Clicking it opens:

* OS, CPU, memory and disk inventory, RAID, SMART health and filesystem mounts;
* process list (PID, executable name, CPU and RAM) without process arguments;
* running services, listening ports, interface addresses and routing tables;
* application versions and up to 2,000 installed system packages;
* recent load, CPU, memory, disk, network RX/TX charts (120 in-memory samples).
  CPU/network sampling requires two Linux counter reads. OpenBSD support is
  best-effort and excludes unavailable Linux-only counters.

The panel polls `/fleet/data` every 15 seconds. This is a **snapshot-based**
SSH collector, not the Prometheus node_exporter binary. History is currently
held in memory and is lost after restart. For long-term retention, a Prometheus
server can scrape the authenticated `/fleet/metrics` endpoint. The endpoint
requires monitoring view credentials and must not be public.

Status is **SSH reachability**, not a substitute for application checks:
a green host can still have a failed service. Nagios service status remains
on the primary dashboard. The full read-only scan is run periodically; no
agent needs to be installed on monitored servers.

---

# Cloud provider fleet inventory (Hetzner and Selectel)

The standalone command `go run ./cmd/fleet-inventory` discovers dedicated servers in Hetzner Robot and Selectel, and optionally virtual machines from Hetzner Cloud. It probes reachable hosts over SSH using read-only commands and outputs JSON or CSV. It does not modify the existing chicha-pulse Nagios monitoring service.

## Credentials

Set any combination of providers. **Never commit tokens or passwords.**

```sh
# Hetzner dedicated servers: Robot Webservice user, NOT SSH credentials
export HETZNER_ROBOT_USER='webservice-user'
export HETZNER_ROBOT_PASSWORD='your-webservice-password'

# Optional: one Hetzner Cloud project (read-only project API token)
export HETZNER_CLOUD_TOKEN='your-cloud-token'

# Selectel: account IAM service user (automatically fetch a new short-lived token)
export SELECTEL_ACCOUNT_ID='123456'
export SELECTEL_USER='ip-inventory'
export SELECTEL_PASSWORD='your-iam-password'

# Alternative Selectel authorization: a previously obtained IAM token
# export SELECTEL_TOKEN='your-iam-token'
```

Get Hetzner Robot Webservice credentials in Robot; Hetzner Cloud API tokens in the project security settings. Get Selectel account-scoped IAM service-user credentials under IAM in my.selectel.ru. Grant read-only rights where available. SSH credentials are separate from all provider API credentials.

## Usage

```sh
cd chicha-pulse
umask 077

# First verify the API inventory without connecting to any hosts.
go run ./cmd/fleet-inventory -api-only > fleet.json

# Then probe servers via your existing SSH key or ssh-agent.
go run ./cmd/fleet-inventory -ssh-user inventory -ssh-key ~/.ssh/id_ed25519 > fleet.json

# Server summary for spreadsheets.
go run ./cmd/fleet-inventory -format csv -workers 8 > fleet.csv
```

Flags: `-api-only`, `-format json|csv`, `-ssh-user`, `-ssh-key`, `-ssh-port`, `-workers` (1–32), `-ssh-timeout` (e.g. `30s`).

### What gets collected

* Provider, server ID/name/status/datacenter, main IP, attached public/local IPs and routed CIDRs.
* OS and kernel, hostname and uptime.
* Memory, filesystems, disk devices, Linux md RAID, OpenBSD `bioctl` summary, and SMART overall health when `smartctl` and permissions are available.
* Interface IPs, routes, started services, listening TCP/UDP sockets.

The remote probe performs no modifications, installations, privilege escalation, restarts or configuration updates. Unavailable commands produce empty sections. Linux, OpenBSD and FreeBSD are supported on a best-effort basis; some checks require read permissions.

### Safety and limitations

* OpenSSH enforces `StrictHostKeyChecking=yes`; the host must already be registered in your `known_hosts`, with the fingerprint verified out of band. Never blindly accept unknown host keys.
* SSH probes default to provider main IPv4; hosts without one are included with a per-host skip error. The API can expose IPs no longer configured in the server OS.
* Token/auth/network/API failures are not swallowed: output retains other providers and errors go to stderr and JSON `errors`; the command exits nonzero.
* This first step covers Hetzner dedicated servers, one Hetzner Cloud project per token, and Selectel dedicated servers. It does not yet cover Selectel cloud VMs or Hetzner Storage Boxes.
* Routed subnets are recorded as prefixes, never expanded into imaginary individual assignments.
* The CSV is a flat summary; JSON retains detailed SSH sections. Both expose sensitive infrastructure metadata; store with mode 0600 and do not check them into Git.
* The existing long-running monitoring process, Nagios import and web UI are unchanged. Integration into their shared inventory can be added after provider-specific testing on real accounts.
