package checker

// Package checker runs checks with worker goroutines so scheduling stays responsive.

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"chicha-pulse/pkg/model"
	"chicha-pulse/pkg/store"
	"golang.org/x/crypto/ssh"
)

// Job is a unit of work derived from Nagios configuration so checks can run concurrently.
type Job struct {
	HostName      string
	HostAddress   string
	ServiceName   string
	CheckCommand  string
	Interval      time.Duration
	SSHUser       string
	SSHKeyPath    string
	SSHPort       int
	SSHCommand    string
	HostReachable bool
	PingOutput    string
}

// Result captures the output and status so downstream stages can notify and store data.
type Result struct {
	HostName     string
	ServiceName  string
	CheckCommand string
	Status       int
	Output       string
	CheckedAt    time.Time
}

// ---- Public pipeline ----

// Start launches the scheduler and worker pool with channels to avoid shared-state locks.
func Start(ctx context.Context, st *store.Store) <-chan Result {
	jobCh := make(chan Job)
	resultCh := make(chan Result, runtime.NumCPU())
	workerDone := make(chan struct{})

	startScheduler(ctx, st, jobCh)
	startWorkers(ctx, jobCh, resultCh, workerDone)
	closeResults(ctx, workerDone, resultCh)

	return resultCh
}

// ---- Scheduler ----

func startScheduler(ctx context.Context, st *store.Store, jobCh chan<- Job) {
	go func() {
		defer close(jobCh)
		nextRun := make(map[string]time.Time)
		pingCache := make(map[string]pingResult)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				publishJobs(ctx, st, jobCh, nextRun, pingCache, now)
			}
		}
	}()
}

func publishJobs(ctx context.Context, st *store.Store, jobCh chan<- Job, nextRun map[string]time.Time, pingCache map[string]pingResult, now time.Time) {
	snapshot, err := st.Snapshot(ctx)
	if err != nil {
		return
	}
	for _, host := range snapshot.Hosts {
		ping := cachedPing(ctx, host, pingCache, now)
		if !ping.Reachable {
			address := host.Address
			if address == "" {
				address = host.Name
			}
			log.Printf("ping failed host=%s address=%s; only ssh checks will attempt a connect", host.Name, address)
		}
		for _, service := range host.Services {
			if !ping.Reachable && !isSSHService(service) {
				continue
			}
			key := host.Name + "/" + service.Name
			interval := intervalForService(service.CheckIntervalMinutes)
			if dueAt, ok := nextRun[key]; ok && now.Before(dueAt) {
				continue
			}
			job := Job{
				HostName:      host.Name,
				HostAddress:   host.Address,
				ServiceName:   service.Name,
				CheckCommand:  service.CheckCommand,
				Interval:      interval,
				SSHUser:       service.SSHUser,
				SSHKeyPath:    service.SSHKeyPath,
				SSHPort:       service.SSHPort,
				SSHCommand:    service.SSHCommand,
				HostReachable: ping.Reachable,
				PingOutput:    ping.Output,
			}
			nextRun[key] = now.Add(interval)
			select {
			case <-ctx.Done():
				return
			case jobCh <- job:
			}
		}
	}
}

func intervalForService(minutes int) time.Duration {
	if minutes <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(minutes) * time.Minute
}

type pingResult struct {
	CheckedAt time.Time
	Reachable bool
	Output    string
}

func cachedPing(ctx context.Context, host *model.Host, cache map[string]pingResult, now time.Time) pingResult {
	key := host.Name
	if host.Address != "" {
		key = host.Address
	}
	if cached, ok := cache[key]; ok && now.Sub(cached.CheckedAt) < 30*time.Second {
		return cached
	}
	result := pingHost(ctx, host)
	cache[key] = result
	return result
}

func pingHost(ctx context.Context, host *model.Host) pingResult {
	address := host.Address
	if address == "" {
		address = host.Name
	}
	command := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", address)
	output, err := command.CombinedOutput()
	result := pingResult{
		CheckedAt: time.Now(),
		Reachable: err == nil,
		Output:    strings.TrimSpace(string(output)),
	}
	if result.Reachable {
		log.Printf("ping ok host=%s address=%s", host.Name, address)
	} else {
		log.Printf("ping fail host=%s address=%s output=%q", host.Name, address, result.Output)
	}
	return result
}

// ---- Workers ----

func startWorkers(ctx context.Context, jobCh <-chan Job, resultCh chan<- Result, workerDone chan<- struct{}) {
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}

	for i := 0; i < workers; i++ {
		go func() {
			defer func() { workerDone <- struct{}{} }()
			for job := range jobCh {
				result := runCheck(ctx, job)
				select {
				case <-ctx.Done():
					return
				case resultCh <- result:
				}
			}
		}()
	}
}

func closeResults(ctx context.Context, workerDone <-chan struct{}, resultCh chan<- Result) {
	go func() {
		defer close(resultCh)
		workers := runtime.NumCPU()
		if workers < 1 {
			workers = 1
		}
		completed := 0
		for completed < workers {
			select {
			case <-ctx.Done():
				return
			case <-workerDone:
				completed++
			}
		}
	}()
}

// ---- Command execution ----

func runCheck(ctx context.Context, job Job) Result {
	command := expandCommand(strings.TrimSpace(job.CheckCommand), job)
	needsSSH := job.SSHCommand != "" || strings.Contains(command, "check_by_ssh") || isLegacyCheckSSHCommand(command)
	result := Result{
		HostName:     job.HostName,
		ServiceName:  job.ServiceName,
		CheckCommand: job.CheckCommand,
		CheckedAt:    time.Now(),
	}
	if !job.HostReachable && !needsSSH {
		result.Status = 2
		result.Output = "host unreachable (ping failed)"
		if job.PingOutput != "" {
			result.Output = result.Output + ": " + job.PingOutput
		}
		return result
	}
	if command == "" {
		result.Status = 3
		result.Output = "empty check command"
		return result
	}

	if isLegacyCheckSSHCommand(command) {
		return runLegacySSHCheck(ctx, job, result, command)
	}
	if job.SSHCommand != "" || strings.Contains(command, "check_by_ssh") {
		return runSSHCheck(ctx, job, result)
	}
	if strings.Contains(command, "check_tcp") {
		return runTCPCheck(ctx, job, result)
	}

	log.Printf("check start host=%s service=%s command=%q", job.HostName, job.ServiceName, command)
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	output, err := cmd.CombinedOutput()
	result.Output = strings.TrimSpace(string(output))
	if err != nil {
		exitCode := cmd.ProcessState.ExitCode()
		if exitCode == -1 {
			exitCode = 2
		}
		result.Status = exitCode
		if result.Output == "" {
			result.Output = err.Error()
		}
		log.Printf("check error host=%s service=%s status=%d output=%q", job.HostName, job.ServiceName, result.Status, result.Output)
		return result
	}

	result.Status = 0
	if result.Output == "" {
		result.Output = "ok"
	}
	log.Printf("check ok host=%s service=%s output=%q", job.HostName, job.ServiceName, result.Output)
	return result
}

func runSSHCheck(ctx context.Context, job Job, result Result) Result {
	address := job.HostAddress
	port := job.SSHPort
	if port == 0 {
		port = 22
	}
	if address == "" {
		address = job.HostName
	}
	remoteCommand := job.SSHCommand
	if remoteCommand == "" {
		remoteCommand = "uptime"
	}
	remoteCommand = expandCommand(remoteCommand, job)
	log.Printf("ssh check host=%s address=%s port=%d user=%s command=%q", job.HostName, address, port, job.SSHUser, remoteCommand)

	if !job.HostReachable {
		if err := preflightTCP(ctx, address, port, "ssh"); err != nil {
			result.Status = 2
			result.Output = "ping failed; ssh services on this host will stay down until it responds"
			if job.PingOutput != "" {
				result.Output = result.Output + ": " + job.PingOutput
			}
			log.Printf("ssh skipped host=%s address=%s reason=ping_failed", job.HostName, address)
			return result
		}
		log.Printf("ssh preflight ok host=%s address=%s port=%d despite ping failure", job.HostName, address, port)
	} else if err := preflightTCP(ctx, address, port, "ssh"); err != nil {
		result.Status = 2
		result.Output = err.Error()
		return result
	}

	config, err := sshConfig(job)
	if err != nil {
		result.Status = 2
		result.Output = err.Error()
		log.Printf("ssh connect fail host=%s address=%s port=%d err=%q", job.HostName, address, port, result.Output)
		return result
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(address, fmt.Sprintf("%d", port)), config)
	if err != nil {
		result.Status = 2
		result.Output = err.Error()
		log.Printf("ssh connect fail host=%s address=%s port=%d err=%q", job.HostName, address, port, result.Output)
		return result
	}
	defer client.Close()
	log.Printf("ssh connect ok host=%s address=%s port=%d", job.HostName, address, port)

	session, err := client.NewSession()
	if err != nil {
		result.Status = 2
		result.Output = err.Error()
		log.Printf("ssh exec fail host=%s address=%s port=%d err=%q", job.HostName, address, port, result.Output)
		return result
	}
	defer session.Close()

	output, err := session.CombinedOutput(remoteCommand)
	result.Output = strings.TrimSpace(string(output))
	if err != nil {
		result.Status = 2
		if result.Output == "" {
			result.Output = err.Error()
		}
		log.Printf("ssh exec fail host=%s address=%s port=%d output=%q", job.HostName, address, port, result.Output)
		return result
	}

	result.Status = 0
	if result.Output == "" {
		result.Output = "ok"
	}
	log.Printf("ssh exec ok host=%s address=%s port=%d output=%q", job.HostName, address, port, result.Output)
	return result
}

func runLegacySSHCheck(ctx context.Context, job Job, result Result, command string) Result {
	target, remoteCommand, err := parseCheckSSHCommand(command)
	if err != nil {
		result.Status = 3
		result.Output = err.Error()
		return result
	}
	host := hostFromTarget(target)
	log.Printf("ssh check (legacy) host=%s target=%s command=%q", job.HostName, target, remoteCommand)
	if !job.HostReachable {
		if err := preflightTCP(ctx, host, 22, "ssh"); err != nil {
			result.Status = 2
			result.Output = "ping failed; ssh services on this host will stay down until it responds"
			if job.PingOutput != "" {
				result.Output = result.Output + ": " + job.PingOutput
			}
			log.Printf("ssh skipped host=%s address=%s reason=ping_failed", job.HostName, host)
			return result
		}
		log.Printf("ssh preflight ok host=%s address=%s port=%d despite ping failure", job.HostName, host, 22)
	} else if err := preflightTCP(ctx, host, 22, "ssh"); err != nil {
		result.Status = 2
		result.Output = err.Error()
		return result
	}
	cmd := exec.CommandContext(ctx, "ssh", target, remoteCommand)
	output, err := cmd.CombinedOutput()
	result.Output = strings.TrimSpace(string(output))
	if err != nil {
		exitCode := cmd.ProcessState.ExitCode()
		if exitCode == -1 {
			exitCode = 2
		}
		result.Status = exitCode
		if result.Output == "" {
			result.Output = err.Error()
		}
		log.Printf("ssh error host=%s target=%s status=%d output=%q", job.HostName, target, result.Status, result.Output)
		return result
	}
	result.Status = 0
	if result.Output == "" {
		result.Output = "ok"
	}
	log.Printf("ssh ok host=%s target=%s output=%q", job.HostName, target, result.Output)
	return result
}

func expandCommand(command string, job Job) string {
	// Replace Nagios-style host macros so checks run with resolved targets.
	address := job.HostAddress
	if address == "" {
		address = job.HostName
	}
	expanded := strings.ReplaceAll(command, "$HOSTADDRESS$", address)
	expanded = strings.ReplaceAll(expanded, "$HOSTNAME$", job.HostName)
	return expanded
}

func isSSHService(service model.Service) bool {
	// SSH checks need a connection attempt even when ping fails to show what is reachable.
	command := strings.TrimSpace(service.CheckCommand)
	return service.SSHCommand != "" || strings.Contains(command, "check_by_ssh") || isLegacyCheckSSHCommand(command)
}

func isLegacyCheckSSHCommand(command string) bool {
	// Some configs still call check_ssh; detect it so we can run the native ssh command.
	fields := strings.Fields(command)
	for _, field := range fields {
		if strings.HasSuffix(field, "check_ssh") || strings.Contains(field, "/check_ssh") {
			return true
		}
	}
	return false
}

func parseCheckSSHCommand(command string) (string, string, error) {
	// Preserve the user@host token and the remote command so we can use the native ssh client.
	fields := strings.Fields(command)
	for index, field := range fields {
		if strings.HasSuffix(field, "check_ssh") || strings.Contains(field, "/check_ssh") {
			if index+1 >= len(fields) {
				return "", "", fmt.Errorf("missing ssh target")
			}
			target := fields[index+1]
			if index+2 >= len(fields) {
				return "", "", fmt.Errorf("missing ssh remote command")
			}
			remoteCommand := strings.Join(fields[index+2:], " ")
			return target, remoteCommand, nil
		}
	}
	return "", "", fmt.Errorf("missing check_ssh command")
}

func hostFromTarget(target string) string {
	// Split user@host so TCP preflight checks the real host.
	if strings.Contains(target, "@") {
		parts := strings.SplitN(target, "@", 2)
		return parts[1]
	}
	return target
}

func sshConfig(job Job) (*ssh.ClientConfig, error) {
	keyPath := strings.TrimSpace(job.SSHKeyPath)
	if keyPath == "" {
		return nil, fmt.Errorf("missing ssh key path")
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, err
	}
	user := job.SSHUser
	if user == "" {
		user = "root"
	}
	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}, nil
}

func runTCPCheck(ctx context.Context, job Job, result Result) Result {
	address := job.HostAddress
	if address == "" {
		address = job.HostName
	}
	port := extractPort(job.CheckCommand)
	if port == "" {
		result.Status = 3
		result.Output = "missing port"
		return result
	}
	log.Printf("tcp check host=%s address=%s port=%s", job.HostName, address, port)
	portNumber := parsePort(port)
	if err := preflightTCP(ctx, address, portNumber, "tcp"); err != nil {
		result.Status = 2
		result.Output = err.Error()
		return result
	}
	result.Status = 0
	result.Output = "ok"
	return result
}

func preflightTCP(ctx context.Context, address string, port int, label string) error {
	if port <= 0 {
		return fmt.Errorf("%s preflight failed: invalid port", label)
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, fmt.Sprintf("%d", port)))
	if err != nil {
		log.Printf("%s preflight fail address=%s port=%d err=%q", label, address, port, err.Error())
		return fmt.Errorf("%s preflight failed: %s", label, err.Error())
	}
	_ = conn.Close()
	log.Printf("%s preflight ok address=%s port=%d", label, address, port)
	return nil
}

func extractPort(command string) string {
	fields := strings.Fields(command)
	for index, field := range fields {
		if field == "-p" && index+1 < len(fields) {
			return fields[index+1]
		}
	}
	for index, field := range fields {
		if field == "--port" && index+1 < len(fields) {
			return fields[index+1]
		}
	}
	return ""
}

func parsePort(value string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0
	}
	return parsed
}
