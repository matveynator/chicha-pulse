# chicha-pulse

**Infrastructure health & control platform**

chicha-pulse is a **single-binary platform** for monitoring, inventory, and lifecycle management of Linux infrastructure.  
It provides real-time visibility and control over **Linux servers, virtual machines, and clusters** — all from one tool.

With chicha-pulse, you can monitor system health, track infrastructure inventory, create and migrate virtual machines, and operate clusters through a unified control plane.

No agents zoo.  
No external dependencies.  
One binary. One pulse.

---

## Core Idea

chicha-pulse does **not lock you into its control plane**.

You can manage your infrastructure in **two ways**:
- through **chicha-pulse**
- or **directly**, using native Linux tools, hypervisors, and workflows

chicha-pulse continuously observes the system state, **detects external changes**, and automatically **integrates them back into its inventory and control model**.

No forced workflows.  
No abstraction prison.  
Your infrastructure stays yours.

---

## Key Features

- **Single static binary**
- **Linux-first**
- Infrastructure health monitoring
- Server and VM inventory
- Virtual machine lifecycle management
- Live VM migration
- External state discovery and reconciliation
- Unified control plane (CLI + API)
- Embedded storage and web UI

---

## Philosophy

chicha-pulse is designed to be:
- simple to deploy
- safe to operate
- transparent to infrastructure changes

You are free to:
- create or modify VMs manually
- change system configuration directly
- migrate workloads outside of chicha-pulse

chicha-pulse will detect, understand, and reflect those changes — without breaking state or forcing rewrites.

---

## Usage

```bash
chicha-pulse run
chicha-pulse agent
chicha-pulse vm create
chicha-pulse migrate vm01 node02
