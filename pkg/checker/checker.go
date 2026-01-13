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
	"sync/atomic"
	"time"

	"chicha-pulse/pkg/model"
	"chicha-pulse/pkg/sshkeys"
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
	SessionID     uint64
	Sequence      int
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
		sessionID := nextSessionID()
		sequence := 0
		ping := cachedPing(ctx, host, pingCache, now)
		address := host.Address
		if address == "" {
			address = host.Name
		}
		log.Printf("session start host=%s address=%s session=%d", host.Name, address, sessionID)
		if !ping.Reachable {
			log.Printf("ping failed host=%s address=%s session=%d; only ssh checks will attempt a connect", host.Name, address, sessionID)
		}
		for _, service := range host.Services {
			if !ping.Reachable && !isSSHService(service) {
				log.Printf("check blocked host=%s service=%s session=%d reason=ping_failed", host.Name, service.Name, sessionID)
				continue
			}
			key := host.Name + "/" + service.Name
			interval := intervalForService(service.CheckIntervalMinutes)
			if dueAt, ok := nextRun[key]; ok && now.Before(dueAt) {
				continue
			}
			sequence++
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
				SessionID:     sessionID,
				Sequence:      sequence,
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

// Session IDs are monotonically increasing so log streams can be correlated.
var sessionCounter uint64

func nextSessionID() uint64 {
	return atomic.AddUint64(&sessionCounter, 1)
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
	log.Printf("session=%d host=%s service=%s seq=%d step=start", job.SessionID, job.HostName, job.ServiceName, job.Sequence)
	if !job.HostReachable && !needsSSH {
		result.Status = 2
		result.Output = "host unreachable (ping failed)"
		if job.PingOutput != "" {
			result.Output = result.Output + ": " + job.PingOutput
		}
		log.Printf("session=%d host=%s service=%s seq=%d step=blocked reason=ping_failed", job.SessionID, job.HostName, job.ServiceName, job.Sequence)
		return result
	}
	if command == "" {
		result.Status = 3
		result.Output = "empty check command"
		log.Printf("session=%d host=%s service=%s seq=%d step=blocked reason=empty_command", job.SessionID, job.HostName, job.ServiceName, job.Sequence)
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

	log.Printf("session=%d host=%s service=%s seq=%d step=exec command=%q", job.SessionID, job.HostName, job.ServiceName, job.Sequence, command)
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
		log.Printf("session=%d host=%s service=%s seq=%d step=error status=%d output=%q", job.SessionID, job.HostName, job.ServiceName, job.Sequence, result.Status, result.Output)
		return result
	}

	result.Status = 0
	if result.Output == "" {
		result.Output = "ok"
	}
	log.Printf("session=%d host=%s service=%s seq=%d step=ok output=%q", job.SessionID, job.HostName, job.ServiceName, job.Sequence, result.Output)
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
	log.Printf("session=%d host=%s service=%s seq=%d step=ssh-start address=%s port=%d user=%s command=%q", job.SessionID, job.HostName, job.ServiceName, job.Sequence, address, port, job.SSHUser, remoteCommand)

	if !job.HostReachable {
		if err := preflightTCP(ctx, address, port, "ssh", job.SessionID); err != nil {
			result.Status = 2
			result.Output = "ping failed; ssh services on this host will stay down until it responds"
			if job.PingOutput != "" {
				result.Output = result.Output + ": " + job.PingOutput
			}
			log.Printf("session=%d host=%s service=%s seq=%d step=blocked reason=ping_failed address=%s", job.SessionID, job.HostName, job.ServiceName, job.Sequence, address)
			return result
		}
		log.Printf("session=%d host=%s service=%s seq=%d step=ssh-preflight-ok address=%s port=%d despite ping failure", job.SessionID, job.HostName, job.ServiceName, job.Sequence, address, port)
	} else if err := preflightTCP(ctx, address, port, "ssh", job.SessionID); err != nil {
		result.Status = 2
		result.Output = err.Error()
		return result
	}

	config, err := sshConfig(ctx, job)
	if err != nil {
		result.Status = 2
		result.Output = err.Error()
		log.Printf("session=%d host=%s service=%s seq=%d step=ssh-connect-fail address=%s port=%d err=%q", job.SessionID, job.HostName, job.ServiceName, job.Sequence, address, port, result.Output)
		return result
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(address, fmt.Sprintf("%d", port)), config)
	if err != nil {
		result.Status = 2
		result.Output = err.Error()
		log.Printf("session=%d host=%s service=%s seq=%d step=ssh-connect-fail address=%s port=%d err=%q", job.SessionID, job.HostName, job.ServiceName, job.Sequence, address, port, result.Output)
		return result
	}
	defer client.Close()
	log.Printf("session=%d host=%s service=%s seq=%d step=ssh-connect-ok address=%s port=%d", job.SessionID, job.HostName, job.ServiceName, job.Sequence, address, port)

	session, err := client.NewSession()
	if err != nil {
		result.Status = 2
		result.Output = err.Error()
		log.Printf("session=%d host=%s service=%s seq=%d step=ssh-exec-fail address=%s port=%d err=%q", job.SessionID, job.HostName, job.ServiceName, job.Sequence, address, port, result.Output)
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
		log.Printf("session=%d host=%s service=%s seq=%d step=ssh-exec-fail address=%s port=%d output=%q", job.SessionID, job.HostName, job.ServiceName, job.Sequence, address, port, result.Output)
		return result
	}

	result.Status = 0
	if result.Output == "" {
		result.Output = "ok"
	}
	log.Printf("session=%d host=%s service=%s seq=%d step=ssh-exec-ok address=%s port=%d output=%q", job.SessionID, job.HostName, job.ServiceName, job.Sequence, address, port, result.Output)
	return result
}

func runLegacySSHCheck(ctx context.Context, job Job, result Result, command string) Result {
	target, remoteCommand, err := parseCheckSSHCommand(command)
	if err != nil {
		result.Status = 3
		result.Output = err.Error()
		return result
	}
	remoteCommand = expandCommand(remoteCommand, job)
	host := hostFromTarget(target)
	log.Printf("session=%d host=%s service=%s seq=%d step=ssh-legacy-start target=%s command=%q", job.SessionID, job.HostName, job.ServiceName, job.Sequence, target, remoteCommand)
	if !job.HostReachable {
		if err := preflightTCP(ctx, host, 22, "ssh", job.SessionID); err != nil {
			result.Status = 2
			result.Output = "ping failed; ssh services on this host will stay down until it responds"
			if job.PingOutput != "" {
				result.Output = result.Output + ": " + job.PingOutput
			}
			log.Printf("session=%d host=%s service=%s seq=%d step=blocked reason=ping_failed address=%s", job.SessionID, job.HostName, job.ServiceName, job.Sequence, host)
			return result
		}
		log.Printf("session=%d host=%s service=%s seq=%d step=ssh-preflight-ok address=%s port=%d despite ping failure", job.SessionID, job.HostName, job.ServiceName, job.Sequence, host, 22)
	} else if err := preflightTCP(ctx, host, 22, "ssh", job.SessionID); err != nil {
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
		log.Printf("session=%d host=%s service=%s seq=%d step=ssh-legacy-error target=%s status=%d output=%q", job.SessionID, job.HostName, job.ServiceName, job.Sequence, target, result.Status, result.Output)
		return result
	}
	result.Status = 0
	if result.Output == "" {
		result.Output = "ok"
	}
	log.Printf("session=%d host=%s service=%s seq=%d step=ssh-legacy-ok target=%s output=%q", job.SessionID, job.HostName, job.ServiceName, job.Sequence, target, result.Output)
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
			remoteCommand := normalizeRemoteCommand(strings.Join(fields[index+2:], " "))
			return target, remoteCommand, nil
		}
	}
	return "", "", fmt.Errorf("missing check_ssh command")
}

func normalizeRemoteCommand(command string) string {
	// Normalize quoted commands so ssh receives the real remote command.
	trimmed := strings.TrimSpace(command)
	unescaped := strings.ReplaceAll(trimmed, "\\\"", "\"")
	unescaped = strings.ReplaceAll(unescaped, "\\'", "'")
	if len(unescaped) < 2 {
		return unescaped
	}
	first := unescaped[0]
	last := unescaped[len(unescaped)-1]
	if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
		unquoted, err := strconv.Unquote(unescaped)
		if err == nil {
			return unquoted
		}
		return strings.Trim(unescaped, "\"'")
	}
	return unescaped
}

func hostFromTarget(target string) string {
	// Split user@host so TCP preflight checks the real host.
	if strings.Contains(target, "@") {
		parts := strings.SplitN(target, "@", 2)
		return parts[1]
	}
	return target
}

func sshConfig(ctx context.Context, job Job) (*ssh.ClientConfig, error) {
	authMethods, err := buildAuthMethods(ctx, job)
	if err != nil {
		return nil, err
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("missing ssh key path")
	}
	user := job.SSHUser
	if user == "" {
		user = "root"
	}
	return &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}, nil
}

func buildAuthMethods(ctx context.Context, job Job) ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod
	if keyPath := strings.TrimSpace(job.SSHKeyPath); keyPath != "" {
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, err
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if len(authMethods) >= 3 {
		return authMethods, nil
	}
	keyring, err := sshkeys.LoadKeyringFromSettings(ctx)
	if err != nil {
		return nil, err
	}
	for _, record := range keyring {
		signer, err := parseKeySigner(record.PrivateKey, record.Passphrase)
		if err != nil {
			continue
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
		if len(authMethods) >= 3 {
			break
		}
	}
	return authMethods, nil
}

func parseKeySigner(keyData []byte, passphrase []byte) (ssh.Signer, error) {
	// Try both encrypted and unencrypted parsing so existing keys still work.
	if len(passphrase) > 0 {
		if signer, err := ssh.ParsePrivateKeyWithPassphrase(keyData, passphrase); err == nil {
			return signer, nil
		}
	}
	return ssh.ParsePrivateKey(keyData)
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
		log.Printf("session=%d host=%s service=%s seq=%d step=blocked reason=missing_port", job.SessionID, job.HostName, job.ServiceName, job.Sequence)
		return result
	}
	log.Printf("session=%d host=%s service=%s seq=%d step=tcp-start address=%s port=%s", job.SessionID, job.HostName, job.ServiceName, job.Sequence, address, port)
	portNumber := parsePort(port)
	if err := preflightTCP(ctx, address, portNumber, "tcp", job.SessionID); err != nil {
		result.Status = 2
		result.Output = err.Error()
		return result
	}
	result.Status = 0
	result.Output = "ok"
	log.Printf("session=%d host=%s service=%s seq=%d step=tcp-ok", job.SessionID, job.HostName, job.ServiceName, job.Sequence)
	return result
}

func preflightTCP(ctx context.Context, address string, port int, label string, sessionID uint64) error {
	if port <= 0 {
		return fmt.Errorf("%s preflight failed: invalid port", label)
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, fmt.Sprintf("%d", port)))
	if err != nil {
		if shouldLogPreflight(preflightKey{SessionID: sessionID, Address: address, Port: port, Label: label}) {
			log.Printf("session=%d %s preflight fail address=%s port=%d err=%q", sessionID, label, address, port, err.Error())
		}
		return fmt.Errorf("%s preflight failed: %s", label, err.Error())
	}
	_ = conn.Close()
	if shouldLogPreflight(preflightKey{SessionID: sessionID, Address: address, Port: port, Label: label}) {
		log.Printf("session=%d %s preflight ok address=%s port=%d", sessionID, label, address, port)
	}
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

// ---- Preflight log coordination ----

type preflightKey struct {
	SessionID uint64
	Address   string
	Port      int
	Label     string
}

type preflightLogRequest struct {
	Key   preflightKey
	Reply chan bool
}

var preflightLogCh = make(chan preflightLogRequest)

func init() {
	// Run a single goroutine to track preflight logs without mutexes.
	go func() {
		seen := make(map[preflightKey]bool)
		for request := range preflightLogCh {
			if seen[request.Key] {
				request.Reply <- false
				continue
			}
			seen[request.Key] = true
			request.Reply <- true
		}
	}()
}

func shouldLogPreflight(key preflightKey) bool {
	// Use a channel round-trip so log spam is reduced per session.
	reply := make(chan bool, 1)
	preflightLogCh <- preflightLogRequest{Key: key, Reply: reply}
	return <-reply
}
