package alert

// Package alert tracks state transitions so notifications only fire on change.

import (
	"context"
	"fmt"

	"chicha-pulse/pkg/checker"
)

// Event is an alert payload emitted when a service changes state.
type Event struct {
	HostName       string
	ServiceName    string
	Status         int
	PreviousStatus int
	Recovered      bool
	Output         string
}

// ---- Alert pipeline ----

// Start watches results in one goroutine to keep state transitions deterministic.
func Start(ctx context.Context, results <-chan checker.Result) <-chan Event {
	alerts := make(chan Event, 8)
	go func() {
		defer close(alerts)
		last := make(map[string]int)
		for {
			select {
			case <-ctx.Done():
				return
			case result, ok := <-results:
				if !ok {
					return
				}
				key := fmt.Sprintf("%s/%s", result.HostName, result.ServiceName)
				previous, seen := last[key]
				last[key] = result.Status
				if !seen && result.Status == 0 {
					// Skip initial OK states so we only notify on real problems.
					continue
				}
				if seen && previous == result.Status {
					continue
				}
				recovered := seen && previous != 0 && result.Status == 0
				if result.Status == 0 && !recovered {
					// Avoid sending OK transitions unless they are true recoveries.
					continue
				}
				alerts <- Event{
					HostName:       result.HostName,
					ServiceName:    result.ServiceName,
					Status:         result.Status,
					PreviousStatus: previous,
					Recovered:      recovered,
					Output:         result.Output,
				}
			}
		}
	}()

	return alerts
}
