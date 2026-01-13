package topology

// Package topology discovers host relationships and OS metadata over SSH.

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"chicha-pulse/pkg/model"
	"chicha-pulse/pkg/store"
)

// ---- Public API ----

// Start refreshes topology data periodically so the UI can show live hierarchy.
func Start(ctx context.Context, st *store.Store) {
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		refresh(ctx, st)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refresh(ctx, st)
			}
		}
	}()
}

// ---- Refresh orchestration ----

func refresh(ctx context.Context, st *store.Store) {
	snapshot, err := st.Snapshot(ctx)
	if err != nil {
		return
	}
	ipToHost := buildIPIndex(snapshot)
	jobs := make(chan hostJob)
	results := make(chan hostResult, len(snapshot.Hosts))
	workerCount := runtime.NumCPU()
	if workerCount < 2 {
		workerCount = 2
	}

	startWorkers(ctx, workerCount, jobs, results, ipToHost)

	go func() {
		defer close(jobs)
		for _, host := range snapshot.Hosts {
			job := buildHostJob(host)
			select {
			case <-ctx.Done():
				return
			case jobs <- job:
			}
		}
	}()

	for i := 0; i < len(snapshot.Hosts); i++ {
		select {
		case <-ctx.Done():
			return
		case result := <-results:
			if result.hostName == "" {
				continue
			}
			_ = st.UpdateHostMeta(
				ctx,
				result.hostName,
				result.defaultGateway,
				result.detectedParent,
				result.osName,
				result.osVersion,
				result.osLogo,
			)
		}
	}
}

func buildIPIndex(snapshot model.Inventory) map[string]string {
	// Index host addresses to resolve parent relationships quickly.
	index := make(map[string]string, len(snapshot.Hosts))
	for _, host := range snapshot.Hosts {
		if host.Address != "" {
			index[strings.TrimSpace(host.Address)] = host.Name
			continue
		}
		if host.Name != "" {
			index[strings.TrimSpace(host.Name)] = host.Name
		}
	}
	return index
}

// ---- Worker pipeline ----

type hostJob struct {
	hostName string
	target   string
	user     string
	keyPath  string
	port     int
}

type hostResult struct {
	hostName       string
	defaultGateway string
	detectedParent string
	osName         string
	osVersion      string
	osLogo         string
}

func startWorkers(ctx context.Context, count int, jobs <-chan hostJob, results chan<- hostResult, ipToHost map[string]string) {
	for i := 0; i < count; i++ {
		go func() {
			for job := range jobs {
				result := collectHostMeta(ctx, job, ipToHost)
				select {
				case <-ctx.Done():
					return
				case results <- result:
				}
			}
		}()
	}
}

func buildHostJob(host *model.Host) hostJob {
	// Use the first SSH-capable service as a hint for connection details.
	user := "root"
	port := 22
	keyPath := ""
	for _, service := range host.Services {
		if service.SSHUser != "" {
			user = service.SSHUser
		}
		if service.SSHPort != 0 {
			port = service.SSHPort
		}
		if service.SSHKeyPath != "" {
			keyPath = service.SSHKeyPath
		}
		if service.SSHUser != "" || service.SSHPort != 0 || service.SSHKeyPath != "" {
			break
		}
	}
	target := host.Address
	if target == "" {
		target = host.Name
	}
	return hostJob{
		hostName: host.Name,
		target:   target,
		user:     user,
		keyPath:  keyPath,
		port:     port,
	}
}

// ---- SSH data collection ----

func collectHostMeta(ctx context.Context, job hostJob, ipToHost map[string]string) hostResult {
	if job.target == "" || job.hostName == "" {
		return hostResult{}
	}
	output, err := runSSH(ctx, job, metadataCommand())
	if err != nil {
		return hostResult{hostName: job.hostName}
	}
	routeBlock, osReleaseBlock, debianBlock := splitMetadata(output)
	defaultGateway, srcCandidates := parseRoutes(routeBlock)
	osName, osVersion := parseOSRelease(osReleaseBlock, debianBlock)
	parent := detectParent(defaultGateway, srcCandidates, ipToHost)
	return hostResult{
		hostName:       job.hostName,
		defaultGateway: defaultGateway,
		detectedParent: parent,
		osName:         osName,
		osVersion:      osVersion,
		osLogo:         osLogo(osName),
	}
}

func metadataCommand() string {
	// Emit markers so we can split route and OS data reliably.
	return strings.Join([]string{
		"ip r",
		"echo __OS_RELEASE__",
		"cat /etc/os-release 2>/dev/null",
		"echo __DEBIAN_VERSION__",
		"cat /etc/debian_version 2>/dev/null",
	}, "\n")
}

func runSSH(ctx context.Context, job hostJob, command string) (string, error) {
	// Use the system ssh client so we only depend on the standard library.
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-p", fmt.Sprintf("%d", job.port),
	}
	if job.keyPath != "" {
		args = append(args, "-i", job.keyPath)
	}
	target := fmt.Sprintf("%s@%s", job.user, job.target)
	args = append(args, target, "sh", "-c", command)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// ---- Parsing helpers ----

func splitMetadata(output string) (string, string, string) {
	parts := strings.Split(output, "__OS_RELEASE__")
	if len(parts) < 2 {
		return output, "", ""
	}
	routeBlock := strings.TrimSpace(parts[0])
	osParts := strings.Split(parts[1], "__DEBIAN_VERSION__")
	if len(osParts) < 2 {
		return routeBlock, strings.TrimSpace(parts[1]), ""
	}
	return routeBlock, strings.TrimSpace(osParts[0]), strings.TrimSpace(osParts[1])
}

func parseRoutes(output string) (string, []string) {
	var defaultGateway string
	var srcCandidates []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "default via ") {
			fields := strings.Fields(line)
			for i := 0; i < len(fields)-1; i++ {
				if fields[i] == "via" {
					defaultGateway = fields[i+1]
					break
				}
			}
		}
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "src" {
				srcCandidates = append(srcCandidates, fields[i+1])
			}
		}
	}
	return defaultGateway, srcCandidates
}

func parseOSRelease(osReleaseBlock, debianBlock string) (string, string) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(osReleaseBlock))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"")
		values[key] = value
	}
	name := values["NAME"]
	version := values["VERSION_ID"]
	if version == "" {
		version = values["VERSION"]
	}
	if name == "" && debianBlock != "" {
		name = "Debian"
		version = strings.TrimSpace(debianBlock)
	}
	return name, version
}

func detectParent(defaultGateway string, srcCandidates []string, ipToHost map[string]string) string {
	if parent, ok := ipToHost[strings.TrimSpace(defaultGateway)]; ok {
		return parent
	}
	for _, candidate := range srcCandidates {
		if parent, ok := ipToHost[strings.TrimSpace(candidate)]; ok {
			return parent
		}
	}
	return ""
}

func osLogo(name string) string {
	// Use simple emoji logos so the UI stays dependency-free.
	switch strings.ToLower(name) {
	case "debian":
		return "🌀"
	case "ubuntu":
		return "🟠"
	case "centos":
		return "🟣"
	case "fedora":
		return "🔵"
	case "arch":
		return "🔷"
	default:
		return "🖥️"
	}
}
