package model

import "time"

// This file keeps the inventory model tiny so other packages can focus on their own logic.

// ---- Core structures ----

// Service describes a single Nagios-like check that runs on a host.
type Service struct {
	Name                 string
	CheckCommand         string
	HostName             string
	Notes                string
	NotificationsEnabled bool
	Contacts             []string
	CheckIntervalMinutes int
	SSHUser              string
	SSHKeyPath           string
	SSHPort              int
	SSHCommand           string
}

// Host models a system that can hold services and relate to parent systems.
type Host struct {
	Name           string
	Address        string
	Parents        []string
	DetectedParent string
	DefaultGateway string
	OSName         string
	OSVersion      string
	OSLogo         string
	Group          string
	Services       []Service
}

// ServiceStatus stores the most recent check result for a service.
type ServiceStatus struct {
	Status    int
	Output    string
	CheckedAt time.Time
}

// Inventory is an in-memory model of the infrastructure.
type Inventory struct {
	Hosts    map[string]*Host
	Groups   map[string]struct{}
	Statuses map[string]ServiceStatus
	Commands map[string]string
	Activity ActivityStats
}

// ActivityStats summarizes current check activity so the UI can show live state.
type ActivityStats struct {
	Planned int
	Running int
}

// ---- Constructors ----

// NewInventory returns an empty inventory so callers can safely add data.
func NewInventory() Inventory {
	return Inventory{
		Hosts:    make(map[string]*Host),
		Groups:   make(map[string]struct{}),
		Statuses: make(map[string]ServiceStatus),
		Commands: make(map[string]string),
	}
}

// ---- Copy helpers ----

// Clone makes a deep copy to keep the store goroutine as the single writer.
func (inv Inventory) Clone() Inventory {
	clone := NewInventory()
	for name, host := range inv.Hosts {
		hostCopy := Host{
			Name:           host.Name,
			Address:        host.Address,
			Parents:        append([]string(nil), host.Parents...),
			DetectedParent: host.DetectedParent,
			DefaultGateway: host.DefaultGateway,
			OSName:         host.OSName,
			OSVersion:      host.OSVersion,
			OSLogo:         host.OSLogo,
			Group:          host.Group,
		}
		if len(host.Services) > 0 {
			hostCopy.Services = make([]Service, len(host.Services))
			copy(hostCopy.Services, host.Services)
		}
		clone.Hosts[name] = &hostCopy
	}
	for group := range inv.Groups {
		clone.Groups[group] = struct{}{}
	}
	for key, status := range inv.Statuses {
		clone.Statuses[key] = status
	}
	for name, command := range inv.Commands {
		clone.Commands[name] = command
	}
	clone.Activity = inv.Activity
	return clone
}
