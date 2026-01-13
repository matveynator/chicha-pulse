package store

import (
	"context"

	"chicha-pulse/pkg/model"
	"chicha-pulse/pkg/nagiosimport"
)

// This package keeps inventory mutations in a single goroutine to avoid locks.

// ---- Requests ----

type snapshotRequest struct {
	response chan model.Inventory
}

type updateRequest struct {
	object nagiosimport.Object
}

// ---- Store ----

// Store keeps the inventory inside one goroutine so callers never race over shared state.
type Store struct {
	requests chan snapshotRequest
	updates  chan updateRequest
}

// New creates the store and starts the loop that owns the inventory.
func New(ctx context.Context) *Store {
	st := &Store{
		requests: make(chan snapshotRequest),
		updates:  make(chan updateRequest),
	}
	go st.run(ctx)
	return st
}

// Apply sends a parsed Nagios object to the store without using locks.
func (st *Store) Apply(ctx context.Context, object nagiosimport.Object) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case st.updates <- updateRequest{object: object}:
		return nil
	}
}

// Snapshot retrieves a cloned inventory to avoid exposing internal pointers.
func (st *Store) Snapshot(ctx context.Context) (model.Inventory, error) {
	request := snapshotRequest{response: make(chan model.Inventory, 1)}
	select {
	case <-ctx.Done():
		return model.Inventory{}, ctx.Err()
	case st.requests <- request:
	}
	select {
	case <-ctx.Done():
		return model.Inventory{}, ctx.Err()
	case snapshot := <-request.response:
		return snapshot, nil
	}
}

// ---- Internal loop ----

func (st *Store) run(ctx context.Context) {
	inventory := model.NewInventory()

	for {
		select {
		case <-ctx.Done():
			return
		case update := <-st.updates:
			applyObject(&inventory, update.object)
		case request := <-st.requests:
			request.response <- inventory.Clone()
		}
	}
}

// ---- Inventory helpers ----

func applyObject(inventory *model.Inventory, object nagiosimport.Object) {
	switch object.Kind {
	case nagiosimport.KindHost:
		applyHost(inventory, object.Host)
	case nagiosimport.KindService:
		applyService(inventory, object.Service, object.HostNames)
	}
}

// applyHost updates or creates a host while keeping existing services intact.
func applyHost(inventory *model.Inventory, host model.Host) {
	existing, ok := inventory.Hosts[host.Name]
	if !ok {
		inventory.Hosts[host.Name] = &model.Host{
			Name:    host.Name,
			Address: host.Address,
			Parents: append([]string(nil), host.Parents...),
		}
		return
	}
	existing.Address = host.Address
	existing.Parents = append([]string(nil), host.Parents...)
}

// applyService adds a service to every referenced host, creating placeholders when needed.
func applyService(inventory *model.Inventory, service model.Service, hostNames []string) {
	for _, hostName := range hostNames {
		host, ok := inventory.Hosts[hostName]
		if !ok {
			host = &model.Host{Name: hostName}
			inventory.Hosts[hostName] = host
		}
		service.HostName = hostName
		if serviceExists(host.Services, service.Name) {
			continue
		}
		host.Services = append(host.Services, service)
	}
}

func serviceExists(services []model.Service, name string) bool {
	for _, service := range services {
		if service.Name == name {
			return true
		}
	}
	return false
}
