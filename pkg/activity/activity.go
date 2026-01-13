package activity

// Package activity aggregates check scheduling events into UI-friendly stats.

import (
	"context"
	"time"

	"chicha-pulse/pkg/model"
)

// ---- Event types ----

// EventKind describes how a check moves through the scheduler.
type EventKind int

const (
	EventPlanned EventKind = iota
	EventStarted
	EventFinished
)

// Event captures a single scheduler transition so we can count planned and running work.
type Event struct {
	Kind        EventKind
	HostName    string
	ServiceName string
	ScheduledAt time.Time
}

type activityKey struct {
	hostName    string
	serviceName string
}

// ---- Public API ----

// Start consumes scheduler events and emits ActivityStats snapshots without locking.
func Start(ctx context.Context, events <-chan Event) <-chan model.ActivityStats {
	output := make(chan model.ActivityStats, 1)
	go func() {
		defer close(output)
		state := newActivityState()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-events:
				if !ok {
					return
				}
				state.apply(event)
				state.flush(ctx, output)
			case <-ticker.C:
				state.expire(time.Now())
				state.flush(ctx, output)
			}
		}
	}()
	return output
}

// ---- State management ----

type activityState struct {
	running map[activityKey]struct{}
	planned map[activityKey]time.Time
	last    model.ActivityStats
}

func newActivityState() *activityState {
	return &activityState{
		running: make(map[activityKey]struct{}),
		planned: make(map[activityKey]time.Time),
	}
}

func (state *activityState) apply(event Event) {
	key := activityKey{hostName: event.HostName, serviceName: event.ServiceName}
	switch event.Kind {
	case EventPlanned:
		state.planned[key] = event.ScheduledAt
	case EventStarted:
		delete(state.planned, key)
		state.running[key] = struct{}{}
	case EventFinished:
		delete(state.running, key)
	}
}

func (state *activityState) expire(now time.Time) {
	// Drop planned entries that are too old so "planned soon" stays accurate.
	const window = time.Minute
	for key, scheduledAt := range state.planned {
		if now.Sub(scheduledAt) > window {
			delete(state.planned, key)
		}
	}
}

func (state *activityState) stats() model.ActivityStats {
	return model.ActivityStats{
		Planned: len(state.planned),
		Running: len(state.running),
	}
}

func (state *activityState) flush(ctx context.Context, output chan<- model.ActivityStats) {
	stats := state.stats()
	if stats == state.last {
		return
	}
	state.last = stats
	select {
	case <-ctx.Done():
		return
	case output <- stats:
	default:
	}
}
