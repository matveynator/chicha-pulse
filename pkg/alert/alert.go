package alert

// Package alert tracks state transitions so notifications only fire on change.

import (
	"context"
	"fmt"

	"chicha-pulse/pkg/checker"
)

// Event is an alert payload emitted when a service changes state.
type Event struct {
	HostName    string
	ServiceName string
	Status      int
	Output      string
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
				if !seen || previous != result.Status {
					last[key] = result.Status
					alerts <- Event{
						HostName:    result.HostName,
						ServiceName: result.ServiceName,
						Status:      result.Status,
						Output:      result.Output,
					}
				}
			}
		}
	}()

	return alerts
}
