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

section hardware; if command -v lscpu >/dev/null 2>&1; then lscpu 2>/dev/null | head -55; else sysctl hw.model hw.ncpu hw.physmem hw.disknames 2>/dev/null; fi
section processes; ps -axo pid,comm,%cpu,%mem 2>/dev/null | head -300
section versions
for program in nginx apache2 httpd postgres psql mysql mariadb docker podman redis-server php node python3 go caddy sshd; do
  if command -v "$program" >/dev/null 2>&1; then
    case "$program" in
      nginx|sshd) version=$("$program" -V 2>&1 | head -1);;
      redis-server) version=$("$program" -v 2>&1 | head -1);;
      go) version=$("$program" version 2>&1 | head -1);;
      caddy) version=$("$program" version 2>&1 | head -1);;
      *) version=$("$program" --version 2>&1 | head -1);;
    esac
    printf '%s: %s\n' "$program" "$version"
  fi
done
section packages
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | head -2000
elif command -v pkg_info >/dev/null 2>&1; then
  pkg_info -q 2>/dev/null | head -2000
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa 2>/dev/null | head -2000
fi
section metrics
if test -r /proc/loadavg; then awk '{print "load1="$1}' /proc/loadavg; else sysctl -n vm.loadavg 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+[.][0-9]+$/) {print "load1="$i; exit}}'; fi
if test -r /proc/meminfo; then awk '/^MemTotal:/ {print "mem_total_kb="$2} /^MemAvailable:/ {print "mem_available_kb="$2}' /proc/meminfo; else
  sysctl -n hw.physmem 2>/dev/null | awk '{print "mem_total_kb="int($1/1024)}'
fi
df -Pk / 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5);print "root_disk_pct="$5}'

if test -r /proc/stat; then awk '/^cpu / {total=0;for(i=2;i<=NF;i++) total+=$i;print "cpu_total_ticks="total;print "cpu_idle_ticks="$5}' /proc/stat; fi
if test -r /proc/net/dev; then awk 'NR>2 {gsub(/:/," ");if($1!="lo"){rx+=$2;tx+=$10}} END {print "net_rx_bytes="rx;print "net_tx_bytes="tx}' /proc/net/dev; fi

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
