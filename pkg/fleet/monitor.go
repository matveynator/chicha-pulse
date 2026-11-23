package fleet

// Monitor owns the live fleet snapshot in one goroutine. Provider and SSH work
// happens in a separate goroutine, so HTTP snapshots never wait for a scan.
import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Sample struct {
	At               time.Time `json:"at"`
	Load1            float64   `json:"load1"`
	MemoryUsedPct    float64   `json:"memory_used_pct"`
	RootDiskUsedPct  float64   `json:"root_disk_used_pct"`
}

type HostState struct {
	Host       Host      `json:"host"`
	Status     string    `json:"status"` // online, offline or unknown
	LastProbe  time.Time `json:"last_probe,omitempty"`
	LastOnline time.Time `json:"last_online,omitempty"`
	SSH        Probe     `json:"ssh"`
	History    []Sample  `json:"history,omitempty"`
}

type FleetSnapshot struct {
	UpdatedAt time.Time   `json:"updated_at,omitempty"`
	Hosts     []HostState `json:"hosts"`
	Errors    []string    `json:"errors,omitempty"`
}

type Monitor struct {
	requests chan chan FleetSnapshot
}

func StartMonitor(ctx context.Context, cfg Config, ssh SSHOptions, interval time.Duration) *Monitor {
	if interval < 15*time.Second {
		interval = 90 * time.Second
	}
	m := &Monitor{requests: make(chan chan FleetSnapshot)}
	results := make(chan FleetSnapshot, 1)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			hosts, errors := Discover(ctx, cfg)
			current := FleetSnapshot{UpdatedAt: time.Now().UTC(), Errors: errors}
			scanned := Scan(ctx, hosts, ssh)
			for _, r := range scanned {
				status := "offline"
				if r.SSH.Error == "" {
					status = "online"
				} else if strings.HasPrefix(r.SSH.Error, "no main IPv4") || strings.Contains(r.SSH.Error, "Host key verification failed") || strings.Contains(r.SSH.Error, "Permission denied") {
					status = "unknown"
				}
				current.Hosts = append(current.Hosts, HostState{Host: r.Host, SSH: r.SSH, Status: status, LastProbe: time.Now().UTC()})
			}
			select {
			case <-ctx.Done():
				return
			case results <- current:
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	go func() {
		current := FleetSnapshot{Hosts: []HostState{}}
		for {
			select {
			case <-ctx.Done():
				return
			case response := <-m.requests:
				response <- cloneFleetSnapshot(current)
			case latest := <-results:
				previous := make(map[string]HostState, len(current.Hosts))
				for _, h := range current.Hosts {
					previous[h.Host.Provider+"/"+h.Host.ID] = h
				}
				// Keep previously known assets visible when a provider API fails.
				// Never keep them green: their last discovery is no longer trustworthy.
				present := make(map[string]bool, len(latest.Hosts))
				for _, host := range latest.Hosts { present[host.Host.Provider+"/"+host.Host.ID] = true }
				for key, old := range previous {
					if present[key] || !providerFailed(latest.Errors, old.Host.Provider) { continue }
					old.Status = "unknown"
					old.SSH.Error = "provider discovery failed; previous metadata preserved"
					latest.Hosts = append(latest.Hosts, old)
				}
				for i := range latest.Hosts {
					next := &latest.Hosts[i]
					if strings.HasPrefix(next.SSH.Error, "provider discovery failed") { continue }
					if old, exists := previous[next.Host.Provider+"/"+next.Host.ID]; exists {
						next.History = append(next.History, old.History...)
						next.LastOnline = old.LastOnline
					}
					if next.Status == "online" {
						next.LastOnline = next.LastProbe
						if sample, ok := parseSample(next.SSH.Sections["metrics"], next.LastProbe); ok {
							next.History = append(next.History, sample)
						}
					}
					if len(next.History) > 120 {
						next.History = next.History[len(next.History)-120:]
					}
				}
				sort.Slice(latest.Hosts, func(i, j int) bool {
					if latest.Hosts[i].Host.Provider != latest.Hosts[j].Host.Provider {
						return latest.Hosts[i].Host.Provider < latest.Hosts[j].Host.Provider
					}
					return latest.Hosts[i].Host.Name < latest.Hosts[j].Host.Name
				})
				current = latest
			}
		}
	}()
	return m
}

func (m *Monitor) Snapshot(ctx context.Context) (FleetSnapshot, error) {
	result := make(chan FleetSnapshot, 1)
	select {
	case <-ctx.Done():
		return FleetSnapshot{}, ctx.Err()
	case m.requests <- result:
	}
	select {
	case <-ctx.Done():
		return FleetSnapshot{}, ctx.Err()
	case v := <-result:
		return v, nil
	}
}

func cloneFleetSnapshot(v FleetSnapshot) FleetSnapshot {
	out := FleetSnapshot{UpdatedAt: v.UpdatedAt, Errors: append([]string(nil), v.Errors...), Hosts: make([]HostState, len(v.Hosts))}
	for i, h := range v.Hosts {
		out.Hosts[i] = h
		out.Hosts[i].Host.Addresses = append([]Address(nil), h.Host.Addresses...)
		out.Hosts[i].Host.Subnets = append([]string(nil), h.Host.Subnets...)
		out.Hosts[i].Host.Warnings = append([]string(nil), h.Host.Warnings...)
		out.Hosts[i].History = append([]Sample(nil), h.History...)
		out.Hosts[i].SSH.Sections = make(map[string]string, len(h.SSH.Sections))
		for k, value := range h.SSH.Sections {
			out.Hosts[i].SSH.Sections[k] = value
		}
	}
	return out
}

func parseSample(raw string, at time.Time) (Sample, bool) {
	s := Sample{At: at}
	if raw == "" {
		return s, false
	}
	var memTotal, memAvailable float64
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) != 2 {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if err != nil {
			continue
		}
		switch parts[0] {
		case "load1":
			s.Load1 = value
		case "mem_total_kb":
			memTotal = value
		case "mem_available_kb":
			memAvailable = value
		case "root_disk_pct":
			s.RootDiskUsedPct = value
		}
	}
	if memTotal > 0 {
		s.MemoryUsedPct = (memTotal - memAvailable) / memTotal * 100
	}
	if s.MemoryUsedPct < 0 {
		s.MemoryUsedPct = 0
	}
	return s, true
}

func providerFailed(errors []string, provider string) bool {
	prefix := provider + ":"
	if provider == "hetzner-cloud" { prefix = "hetzner cloud:" }
	for _, message := range errors {
		if strings.HasPrefix(message, prefix) { return true }
	}
	return false
}
