# chicha-pulse

**Infrastructure health & understanding platform**

chicha-pulse is a **single-binary platform** for monitoring and inventory of infrastructure.

Its primary goal is to **understand what each system does**:
- what roles it performs
- which services are running
- what starts automatically
- how it participates in the network

---

## What chicha-pulse observes

chicha-pulse treats all Unix-like systems as **peers**, without hard boundaries.

A system may act as:
- an application server
- a router or gateway
- a service node
- a mixed-role system

Roles are **not predefined** and can be **multiple at the same time**.

chicha-pulse observes:
- running processes
- enabled and auto-start services
- network interfaces and routes
- exposed and consumed services

Windows systems are supported for **inventory and monitoring only**.

---

## Health & Visibility

chicha-pulse provides:
- **service health checks and notifications**, inspired by Nagios
- **load and resource visualization**, inspired by Grafana
- historical view of system state and changes over time

Alerts focus on **service impact**, not raw metrics.

---

## Core Idea

You manage systems **directly**, using native tools.

chicha-pulse only **observes and understands** the real system state  
and keeps its internal model in sync as things change.

No forced workflows.  
No hidden control.  
One binary. One pulse.

---

## Capabilities

- System health monitoring
- Service checks and notifications
- Load and resource visualization
- Inventory of hosts and services
- Startup and service discovery
- Multi-role detection
- Network and routing awareness
- Change tracking over time

---

## First monitoring feature

chicha-pulse can import Nagios configuration files with `-import-nagios`, run the
checks on schedule, and notify a Telegram channel when service state changes. A
web panel lists head machines, their virtual machines, and all services attached
per host. Web credentials are generated on startup and printed to the log.

### Interactive setup

Run `-setup` to walk through configuration interactively with a colorized menu.
The wizard finds Nagios configs, summarizes them, and asks before import.

### Supported Nagios objects

- `host` with `host_name`, `address`, and optional `parents`.
- `service` with `service_description`, `host_name`, `check_command`, and
  optional `contacts` and `notifications_enabled`.

Hosts without parents are shown as head machines. Hosts that declare a parent are
shown as virtual machines under that head. Services are attached to each host
referenced in the Nagios file.

### Example

```bash
go run . -setup
```

### Database

chicha-pulse uses `database/sql` and expects either a `sqlite` or `postgres`
driver to be registered. The project ships an internal driver placeholder that
stores data in memory so the pipeline runs even without external dependencies.
Provide a real driver implementation later if you need persistence.

---

## Status

Early stage. Focused on correctness and simplicity.

---

Monitor, understand, and observe your infrastructure — **in one pulse**.
