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
	"strings"
	"time"

	"chicha-pulse/pkg/store"
	"golang.org/x/crypto/ssh"
)

// Job is a unit of work derived from Nagios configuration so checks can run concurrently.
type Job struct {
	HostName     string
	HostAddress  string
	ServiceName  string
	CheckCommand string
	Interval     time.Duration
	SSHUser      string
	SSHKeyPath   string
	SSHPort      int
	SSHCommand   string
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
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				publishJobs(ctx, st, jobCh, nextRun, now)
			}
		}
	}()
}

func publishJobs(ctx context.Context, st *store.Store, jobCh chan<- Job, nextRun map[string]time.Time, now time.Time) {
	snapshot, err := st.Snapshot(ctx)
	if err != nil {
		return
	}
	for _, host := range snapshot.Hosts {
		for _, service := range host.Services {
			key := host.Name + "/" + service.Name
			interval := intervalForService(service.CheckIntervalMinutes)
			if dueAt, ok := nextRun[key]; ok && now.Before(dueAt) {
				continue
			}
			job := Job{
				HostName:     host.Name,
				HostAddress:  host.Address,
				ServiceName:  service.Name,
				CheckCommand: service.CheckCommand,
				Interval:     interval,
				SSHUser:      service.SSHUser,
				SSHKeyPath:   service.SSHKeyPath,
				SSHPort:      service.SSHPort,
				SSHCommand:   service.SSHCommand,
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
	command := strings.TrimSpace(job.CheckCommand)
	result := Result{
		HostName:     job.HostName,
		ServiceName:  job.ServiceName,
		CheckCommand: job.CheckCommand,
		CheckedAt:    time.Now(),
	}
	if command == "" {
		result.Status = 3
		result.Output = "empty check command"
		return result
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
	log.Printf("ssh check host=%s address=%s port=%d user=%s command=%q", job.HostName, address, port, job.SSHUser, remoteCommand)

	config, err := sshConfig(job)
	if err != nil {
		result.Status = 2
		result.Output = err.Error()
		return result
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(address, fmt.Sprintf("%d", port)), config)
	if err != nil {
		result.Status = 2
		result.Output = err.Error()
		return result
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		result.Status = 2
		result.Output = err.Error()
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
		return result
	}

	result.Status = 0
	if result.Output == "" {
		result.Output = "ok"
	}
	return result
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
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, port))
	if err != nil {
		result.Status = 2
		result.Output = err.Error()
		return result
	}
	_ = conn.Close()
	result.Status = 0
	result.Output = "ok"
	return result
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
