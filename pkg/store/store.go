package store

import (
	"context"
	"fmt"
	"strings"

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

type statusRequest struct {
	key    string
	status model.ServiceStatus
}

type groupRequest struct {
	name string
}

type assignRequest struct {
	hostName string
	group    string
}

type serviceUpdateRequest struct {
	hostName    string
	serviceName string
	command     string
	notes       string
	interval    int
	sshUser     string
	sshKeyPath  string
	sshCommand  string
	response    chan error
}

type serviceAddRequest struct {
	hostName    string
	serviceName string
	command     string
	notes       string
	interval    int
	sshUser     string
	sshKeyPath  string
	sshCommand  string
	response    chan error
}

type subscribeRequest struct {
	response chan chan model.Inventory
}

type unsubscribeRequest struct {
	stream chan model.Inventory
}

type hostMetaRequest struct {
	hostName       string
	defaultGateway string
	detectedParent string
	osName         string
	osVersion      string
	osLogo         string
}

type activityRequest struct {
	stats model.ActivityStats
}

// ---- Store ----

// Store keeps the inventory inside one goroutine so callers never race over shared state.
type Store struct {
	requests      chan snapshotRequest
	updates       chan updateRequest
	statusUpdates chan statusRequest
	groupAdds     chan groupRequest
	groupAssigns  chan assignRequest
	serviceEdits  chan serviceUpdateRequest
	serviceAdds   chan serviceAddRequest
	subscribes    chan subscribeRequest
	unsubscribes  chan unsubscribeRequest
	hostMeta      chan hostMetaRequest
	activity      chan activityRequest
}

// New creates the store and starts the loop that owns the inventory.
func New(ctx context.Context) *Store {
	st := &Store{
		requests:      make(chan snapshotRequest),
		updates:       make(chan updateRequest),
		statusUpdates: make(chan statusRequest),
		groupAdds:     make(chan groupRequest),
		groupAssigns:  make(chan assignRequest),
		serviceEdits:  make(chan serviceUpdateRequest),
		serviceAdds:   make(chan serviceAddRequest),
		subscribes:    make(chan subscribeRequest),
		unsubscribes:  make(chan unsubscribeRequest),
		hostMeta:      make(chan hostMetaRequest),
		activity:      make(chan activityRequest),
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

// UpdateStatus records the latest check result for a service without exposing shared state.
func (st *Store) UpdateStatus(ctx context.Context, key string, status model.ServiceStatus) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case st.statusUpdates <- statusRequest{key: key, status: status}:
		return nil
	}
}

// AddGroup creates a new group name that can be assigned to hosts.
func (st *Store) AddGroup(ctx context.Context, name string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case st.groupAdds <- groupRequest{name: name}:
		return nil
	}
}

// AssignHostGroup links a host to a group name for UI filtering.
func (st *Store) AssignHostGroup(ctx context.Context, hostName, group string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case st.groupAssigns <- assignRequest{hostName: hostName, group: group}:
		return nil
	}
}

// UpdateService edits a monitoring task without racing over the shared inventory.
func (st *Store) UpdateService(ctx context.Context, hostName, serviceName, command, notes string, interval int, sshUser, sshKeyPath, sshCommand string) error {
	response := make(chan error, 1)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case st.serviceEdits <- serviceUpdateRequest{
		hostName:    hostName,
		serviceName: serviceName,
		command:     command,
		notes:       notes,
		interval:    interval,
		sshUser:     sshUser,
		sshKeyPath:  sshKeyPath,
		sshCommand:  sshCommand,
		response:    response,
	}:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-response:
		return err
	}
}

// AddService creates a new monitoring task and fails when host/service identity is invalid.
func (st *Store) AddService(ctx context.Context, hostName, serviceName, command, notes string, interval int, sshUser, sshKeyPath, sshCommand string) error {
	response := make(chan error, 1)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case st.serviceAdds <- serviceAddRequest{
		hostName:    hostName,
		serviceName: serviceName,
		command:     command,
		notes:       notes,
		interval:    interval,
		sshUser:     sshUser,
		sshKeyPath:  sshKeyPath,
		sshCommand:  sshCommand,
		response:    response,
	}:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-response:
		return err
	}
}

// Subscribe delivers inventory snapshots so consumers can react without polling.
func (st *Store) Subscribe(ctx context.Context) (<-chan model.Inventory, func()) {
	response := make(chan chan model.Inventory, 1)
	select {
	case <-ctx.Done():
		return closedInventoryStream(), func() {}
	case st.subscribes <- subscribeRequest{response: response}:
	}
	select {
	case <-ctx.Done():
		return closedInventoryStream(), func() {}
	case stream := <-response:
		stop := func() {
			select {
			case st.unsubscribes <- unsubscribeRequest{stream: stream}:
			default:
			}
		}
		return stream, stop
	}
}

// UpdateHostMeta records metadata discovered via SSH so the topology stays current.
func (st *Store) UpdateHostMeta(ctx context.Context, name, defaultGateway, detectedParent, osName, osVersion, osLogo string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case st.hostMeta <- hostMetaRequest{
		hostName:       name,
		defaultGateway: defaultGateway,
		detectedParent: detectedParent,
		osName:         osName,
		osVersion:      osVersion,
		osLogo:         osLogo,
	}:
		return nil
	}
}

// UpdateActivity stores live scheduling stats so the UI can render real-time counts.
func (st *Store) UpdateActivity(ctx context.Context, stats model.ActivityStats) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case st.activity <- activityRequest{stats: stats}:
		return nil
	}
}

// ---- Internal loop ----

func (st *Store) run(ctx context.Context) {
	inventory := model.NewInventory()
	subscribers := map[chan model.Inventory]struct{}{}

	for {
		select {
		case <-ctx.Done():
			return
		case update := <-st.updates:
			applyObject(&inventory, update.object)
			publishSnapshot(inventory, subscribers)
		case status := <-st.statusUpdates:
			inventory.Statuses[status.key] = status.status
			publishSnapshot(inventory, subscribers)
		case group := <-st.groupAdds:
			if group.name != "" {
				inventory.Groups[group.name] = struct{}{}
			}
			publishSnapshot(inventory, subscribers)
		case assignment := <-st.groupAssigns:
			host, ok := inventory.Hosts[assignment.hostName]
			if !ok {
				host = &model.Host{Name: assignment.hostName}
				inventory.Hosts[assignment.hostName] = host
			}
			if assignment.group != "" {
				inventory.Groups[assignment.group] = struct{}{}
				host.Group = assignment.group
			}
			publishSnapshot(inventory, subscribers)
		case update := <-st.serviceEdits:
			host, ok := inventory.Hosts[update.hostName]
			if !ok {
				update.response <- fmt.Errorf("host %s not found", update.hostName)
				continue
			}
			if err := applyServiceUpdate(host, update); err != nil {
				update.response <- err
				continue
			}
			update.response <- nil
			publishSnapshot(inventory, subscribers)
		case add := <-st.serviceAdds:
			host, ok := inventory.Hosts[add.hostName]
			if !ok {
				add.response <- fmt.Errorf("host %s not found", add.hostName)
				continue
			}
			if err := applyServiceAdd(host, add); err != nil {
				add.response <- err
				continue
			}
			add.response <- nil
			publishSnapshot(inventory, subscribers)
		case request := <-st.requests:
			request.response <- inventory.Clone()
		case request := <-st.subscribes:
			stream := make(chan model.Inventory, 1)
			subscribers[stream] = struct{}{}
			stream <- inventory.Clone()
			request.response <- stream
		case request := <-st.unsubscribes:
			if _, ok := subscribers[request.stream]; ok {
				delete(subscribers, request.stream)
				close(request.stream)
			}
		case meta := <-st.hostMeta:
			host, ok := inventory.Hosts[meta.hostName]
			if !ok {
				host = &model.Host{Name: meta.hostName}
				inventory.Hosts[meta.hostName] = host
			}
			host.DefaultGateway = meta.defaultGateway
			host.DetectedParent = meta.detectedParent
			host.OSName = meta.osName
			host.OSVersion = meta.osVersion
			host.OSLogo = meta.osLogo
			publishSnapshot(inventory, subscribers)
		case stats := <-st.activity:
			inventory.Activity = stats.stats
			publishSnapshot(inventory, subscribers)
		}
	}
}

func publishSnapshot(inventory model.Inventory, subscribers map[chan model.Inventory]struct{}) {
	// Fan-out snapshots without blocking the store goroutine.
	if len(subscribers) == 0 {
		return
	}
	snapshot := inventory.Clone()
	for stream := range subscribers {
		select {
		case stream <- snapshot:
		default:
		}
	}
}

func closedInventoryStream() <-chan model.Inventory {
	// Return a closed channel so callers can select without extra nil checks.
	stream := make(chan model.Inventory)
	close(stream)
	return stream
}

// ---- Inventory helpers ----

func applyObject(inventory *model.Inventory, object nagiosimport.Object) {
	switch object.Kind {
	case nagiosimport.KindHost:
		applyHost(inventory, object.Host)
	case nagiosimport.KindService:
		applyService(inventory, object.Service, object.HostNames)
	case nagiosimport.KindCommand:
		applyCommand(inventory, object.Command)
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
			Group:   host.Group,
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
		service.CheckCommand = expandCommand(inventory.Commands, service.CheckCommand)
		if serviceExists(host.Services, service.Name) {
			continue
		}
		host.Services = append(host.Services, service)
	}
}

func applyCommand(inventory *model.Inventory, command nagiosimport.CommandDefinition) {
	if command.Name == "" || command.Command == "" {
		return
	}
	inventory.Commands[command.Name] = command.Command
}

func applyServiceUpdate(host *model.Host, update serviceUpdateRequest) error {
	// Edit must be strict so typos do not create unintended checks.
	for index := range host.Services {
		service := &host.Services[index]
		if service.Name != update.serviceName {
			continue
		}
		service.CheckCommand = strings.TrimSpace(update.command)
		service.Notes = strings.TrimSpace(update.notes)
		service.CheckIntervalMinutes = update.interval
		service.SSHUser = strings.TrimSpace(update.sshUser)
		service.SSHKeyPath = strings.TrimSpace(update.sshKeyPath)
		service.SSHCommand = strings.TrimSpace(update.sshCommand)
		return nil
	}
	return fmt.Errorf("service %s not found on host %s", update.serviceName, host.Name)
}

func applyServiceAdd(host *model.Host, add serviceAddRequest) error {
	// Add path is separate from edit path to keep intent explicit and safe.
	if strings.TrimSpace(add.serviceName) == "" {
		return fmt.Errorf("service name is required")
	}
	if serviceExists(host.Services, add.serviceName) {
		return fmt.Errorf("service %s already exists on host %s", add.serviceName, host.Name)
	}
	host.Services = append(host.Services, model.Service{
		Name:                 strings.TrimSpace(add.serviceName),
		HostName:             host.Name,
		CheckCommand:         strings.TrimSpace(add.command),
		Notes:                strings.TrimSpace(add.notes),
		CheckIntervalMinutes: add.interval,
		SSHUser:              strings.TrimSpace(add.sshUser),
		SSHKeyPath:           strings.TrimSpace(add.sshKeyPath),
		SSHCommand:           strings.TrimSpace(add.sshCommand),
	})
	return nil
}

func expandCommand(commands map[string]string, raw string) string {
	if raw == "" {
		return raw
	}
	parts := strings.Split(raw, "!")
	if len(parts) == 0 {
		return raw
	}
	commandLine, ok := commands[parts[0]]
	if !ok {
		return raw
	}
	expanded := commandLine
	for index, arg := range parts[1:] {
		placeholder := fmt.Sprintf("$ARG%d$", index+1)
		expanded = strings.ReplaceAll(expanded, placeholder, arg)
	}
	return expanded
}

func serviceExists(services []model.Service, name string) bool {
	for _, service := range services {
		if service.Name == name {
			return true
		}
	}
	return false
}
