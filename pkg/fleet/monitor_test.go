package fleet

import (
	"math"
	"testing"
	"time"
)

func TestParseSample(t *testing.T) {
	s, ok := parseSample("load1=1.50\nmem_total_kb=1000\nmem_available_kb=250\nroot_disk_pct=82\ncpu_total_ticks=300\ncpu_idle_ticks=150\nnet_rx_bytes=1024\nnet_tx_bytes=4096\n", time.Unix(1, 0))
	if !ok || math.Abs(s.Load1-1.5)>0.001 || math.Abs(s.MemoryUsedPct-75)>0.001 || s.RootDiskUsedPct != 82 || s.CPUTotalTicks != 300 || s.NetworkTXBytes != 4096 {
		t.Fatalf("unexpected sample: %+v", s)
	}
}

func TestCloneFleetSnapshotIndependent(t *testing.T) {
	original := FleetSnapshot{Hosts: []HostState{{Host: Host{Provider:"hetzner", ID:"1", Addresses:[]Address{{IP:"192.0.2.1",Scope:"public"}}}, SSH:Probe{Sections:map[string]string{"uname":"Linux"}}, History:[]Sample{{Load1:1}}}}}
	copy := cloneFleetSnapshot(original)
	copy.Hosts[0].Host.Addresses[0].IP = "203.0.113.9"
	copy.Hosts[0].History[0].Load1 = 999
	copy.Hosts[0].SSH.Sections["uname"] = "bad"
	if original.Hosts[0].Host.Addresses[0].IP != "192.0.2.1" || original.Hosts[0].History[0].Load1 != 1 || original.Hosts[0].SSH.Sections["uname"] != "Linux" {
		t.Fatalf("original changed: %+v", original)
	}
}

func TestProviderFailed(t *testing.T) {
	for _, test := range []struct{ provider, message string; want bool }{
		{"hetzner", "hetzner: permission denied", true},
		{"hetzner-cloud", "hetzner cloud: API 429", true},
		{"selectel", "selectel: timeout", true},
		{"hetzner-cloud", "hetzner: 401", false},
	} {
		got := providerFailed([]string{test.message}, test.provider)
		if got != test.want {t.Fatalf("providerFailed(%q,%q)=%v", test.provider,test.message,got)}
	}
}
