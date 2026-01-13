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

## Status

Early stage. Focused on correctness and simplicity.

---

Monitor, understand, and observe your infrastructure — **in one pulse**.
