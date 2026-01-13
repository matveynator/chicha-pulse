package model

// This file keeps the inventory model tiny so other packages can focus on their own logic.

// ---- Core structures ----

// Service describes a single Nagios-like check that runs on a host.
type Service struct {
	Name         string
	CheckCommand string
	HostName     string
	Notes        string
}

// Host models a system that can hold services and relate to parent systems.
type Host struct {
	Name     string
	Address  string
	Parents  []string
	Services []Service
}

// Inventory is an in-memory model of the infrastructure.
type Inventory struct {
	Hosts map[string]*Host
}

// ---- Constructors ----

// NewInventory returns an empty inventory so callers can safely add data.
func NewInventory() Inventory {
	return Inventory{Hosts: make(map[string]*Host)}
}

// ---- Copy helpers ----

// Clone makes a deep copy to keep the store goroutine as the single writer.
func (inv Inventory) Clone() Inventory {
	clone := NewInventory()
	for name, host := range inv.Hosts {
		hostCopy := Host{
			Name:    host.Name,
			Address: host.Address,
			Parents: append([]string(nil), host.Parents...),
		}
		if len(host.Services) > 0 {
			hostCopy.Services = make([]Service, len(host.Services))
			copy(hostCopy.Services, host.Services)
		}
		clone.Hosts[name] = &hostCopy
	}
	return clone
}
