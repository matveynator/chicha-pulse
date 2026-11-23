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
