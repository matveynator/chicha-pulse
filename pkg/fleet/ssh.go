package fleet

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type SSHOptions struct {
	User    string
	KeyPath string
	Port    int
	Timeout time.Duration
	Workers int
}

type Probe struct {
	Sections map[string]string `json:"sections,omitempty"`
	Error    string            `json:"error,omitempty"`
}

type Result struct {
	Host Host  `json:"host"`
	SSH  Probe `json:"ssh"`
}

// Scan fans out independent, bounded SSH probes and reassembles results in host order.
func Scan(ctx context.Context, hosts []Host, opts SSHOptions) []Result {
	if opts.User == "" {
		opts.User = "root"
	}
	if opts.Port == 0 {
		opts.Port = 22
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 25 * time.Second
	}
	if opts.Workers <= 0 {
		opts.Workers = 8
	}
	if opts.Workers > 32 {
		opts.Workers = 32
	}
	type job struct {
		index int
		host  Host
	}
	type response struct {
		index int
		probe Probe
	}
	jobs := make(chan job)
	responses := make(chan response, len(hosts))
	for i := 0; i < opts.Workers; i++ {
		go func() {
			for item := range jobs {
				probe := probeHost(ctx, item.host, opts)
				responses <- response{index: item.index, probe: probe}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for i, h := range hosts {
			jobs <- job{index: i, host: h}
		}
	}()
	results := make([]Result, len(hosts))
	for i, h := range hosts {
		results[i].Host = h
	}
	for range hosts {
		r := <-responses
		results[r.index].SSH = r.probe
	}
	return results
}

// A fixed POSIX shell script, passed as stdin, avoids interpolation of provider metadata.
// Missing utilities are expected across Linux/OpenBSD/FreeBSD and do not fail the probe.
const readOnlyScript = `
section() { printf '\n__CHICHA_SECTION_%s__\n' "$1"; }
section uname; uname -srm 2>/dev/null
section hostname; hostname 2>/dev/null
section os; if test -r /etc/os-release; then cat /etc/os-release; else uname -srv 2>/dev/null; fi
section uptime; uptime 2>/dev/null
section memory; if command -v free >/dev/null 2>&1; then free -b; else sysctl hw.physmem hw.usermem 2>/dev/null; fi
section filesystem; df -Pk 2>/dev/null | head -80
section disks; if command -v lsblk >/dev/null 2>&1; then lsblk -b -o NAME,SIZE,TYPE,MODEL,FSTYPE 2>/dev/null | head -80; else sysctl hw.disknames 2>/dev/null; fi
section raid; if test -r /proc/mdstat; then cat /proc/mdstat; fi
if command -v bioctl >/dev/null 2>&1; then bioctl -s 2>/dev/null | head -40; fi
section smart
if command -v smartctl >/dev/null 2>&1; then
  smartctl --scan 2>/dev/null | head -16 | while read -r dev rest; do
    case "$dev" in /dev/*) printf 'DEVICE %s\n' "$dev"; smartctl -H "$dev" 2>/dev/null | head -20;; esac
  done
fi
section addresses; if command -v ip >/dev/null 2>&1; then ip -o address show 2>/dev/null | head -120; else ifconfig -a 2>/dev/null | head -120; fi
section routes; if command -v ip >/dev/null 2>&1; then ip route show 2>/dev/null | head -80; ip -6 route show 2>/dev/null | head -80; else netstat -rn 2>/dev/null | head -120; fi
section services; if command -v systemctl >/dev/null 2>&1; then systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | head -100; elif command -v rcctl >/dev/null 2>&1; then rcctl ls started 2>/dev/null | head -100; else service -e 2>/dev/null | head -100; fi
section listeners; if command -v ss >/dev/null 2>&1; then ss -lntu 2>/dev/null | head -100; else netstat -an 2>/dev/null | head -100; fi
`
func probeHost(ctx context.Context, h Host, opts SSHOptions) Probe {
	if h.MainIP == "" {
		return Probe{Error: "no main IPv4 known; SSH skipped"}
	}
	taskCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	args := []string{
		"-o", "BatchMode=yes", "-o", "NumberOfPasswordPrompts=0", "-o", "StrictHostKeyChecking=yes",
		"-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1",
		"-p", strconv.Itoa(opts.Port),
	}
	if opts.KeyPath != "" {
		args = append(args, "-i", opts.KeyPath, "-o", "IdentitiesOnly=yes")
	}
	args = append(args, "--", opts.User+"@"+h.MainIP, "sh", "-s")
	cmd := exec.CommandContext(taskCtx, "ssh", args...)
	cmd.Stdin = strings.NewReader(readOnlyScript)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		if taskCtx.Err() != nil {
			return Probe{Error: taskCtx.Err().Error()}
		}
		detail := strings.TrimSpace(stderr.String())
		if len(detail) > 300 {
			detail = detail[:300]
		}
		return Probe{Error: fmt.Sprintf("SSH: %v: %s", err, detail)}
	}
	parsed := parseSections(stdout.String())
	if parsed["uname"] == "" {
		return Probe{Error: "SSH responded but no uname section was returned"}
	}
	return Probe{Sections: parsed}
}

func parseSections(raw string) map[string]string {
	sections := make(map[string]string)
	name := ""
	var lines []string
	flush := func() {
		if name != "" {
			sections[name] = strings.TrimSpace(strings.Join(lines, "\n"))
		}
	}
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "__CHICHA_SECTION_") && strings.HasSuffix(line, "__") {
			flush()
			name = strings.TrimSuffix(strings.TrimPrefix(line, "__CHICHA_SECTION_"), "__")
			lines = nil
		} else if name != "" {
			lines = append(lines, line)
		}
	}
	flush()
	return sections
}
