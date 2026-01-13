package checker

// Package checker runs checks with worker goroutines so scheduling stays responsive.

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"chicha-pulse/pkg/store"
)

// Job is a unit of work derived from Nagios configuration so checks can run concurrently.
type Job struct {
	HostName     string
	ServiceName  string
	CheckCommand string
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
func Start(ctx context.Context, st *store.Store, interval time.Duration) <-chan Result {
	jobCh := make(chan Job)
	resultCh := make(chan Result, runtime.NumCPU())
	workerDone := make(chan struct{})

	startScheduler(ctx, st, interval, jobCh)
	startWorkers(ctx, jobCh, resultCh, workerDone)
	closeResults(ctx, workerDone, resultCh)

	return resultCh
}

// ---- Scheduler ----

func startScheduler(ctx context.Context, st *store.Store, interval time.Duration, jobCh chan<- Job) {
	go func() {
		defer close(jobCh)
		publishJobs(ctx, st, jobCh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				publishJobs(ctx, st, jobCh)
			}
		}
	}()
}

func publishJobs(ctx context.Context, st *store.Store, jobCh chan<- Job) {
	snapshot, err := st.Snapshot(ctx)
	if err != nil {
		return
	}
	for _, host := range snapshot.Hosts {
		for _, service := range host.Services {
			job := Job{
				HostName:     host.Name,
				ServiceName:  service.Name,
				CheckCommand: service.CheckCommand,
			}
			select {
			case <-ctx.Done():
				return
			case jobCh <- job:
			}
		}
	}
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
		return result
	}

	result.Status = 0
	if result.Output == "" {
		result.Output = "ok"
	}
	return result
}
