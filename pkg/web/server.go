package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"chicha-pulse/pkg/model"
	"chicha-pulse/pkg/store"
)

// This package keeps the UI minimal so the single binary stays lightweight.

// ---- Configuration ----

type AuthConfig struct {
	Username string
	Password string
}

// ---- Server ----

type Server struct {
	store          *store.Store
	auth           AuthConfig
	template       *template.Template
	alertsTemplate *template.Template
	hostsTemplate  *template.Template
	pageTitle      string
	allowIPs       []string
}

// NewServer prepares the HTTP handler so the caller can run it with a standard net/http server.
func NewServer(st *store.Store, auth AuthConfig, pageTitle string, allowIPs []string) (*Server, error) {
	page := template.Must(template.New("index").Funcs(template.FuncMap{
		"statusBadge": statusBadge,
	}).Parse(indexTemplate))
	alerts := template.Must(template.New("alerts").Funcs(template.FuncMap{
		"statusBadge": statusBadge,
	}).Parse(alertsTemplate))
	hosts := template.Must(template.New("hosts").Funcs(template.FuncMap{
		"statusBadge": statusBadge,
	}).Parse(hostsTemplate))
	return &Server{
		store:          st,
		auth:           auth,
		template:       page,
		alertsTemplate: alerts,
		hostsTemplate:  hosts,
		pageTitle:      pageTitle,
		allowIPs:       append([]string(nil), allowIPs...),
	}, nil
}

// Handler exposes the root HTTP handler with basic auth to keep access simple for now.
func (srv *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/events/stats", srv.handleStatsEvents)
	mux.HandleFunc("/events/alerts", srv.handleAlertsEvents)
	mux.HandleFunc("/events/hosts", srv.handleHostsEvents)
	mux.HandleFunc("/groups", srv.handleAddGroup)
	mux.HandleFunc("/assign", srv.handleAssignGroup)
	return srv.basicAuth(mux)
}

// ---- Handlers ----

func (srv *Server) handleIndex(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	snapshot, err := srv.store.Snapshot(ctx)
	if err != nil {
		http.Error(writer, "failed to load inventory", http.StatusInternalServerError)
		return
	}

	view := buildView(snapshot, srv.pageTitle)
	if err := srv.template.Execute(writer, view); err != nil {
		http.Error(writer, "failed to render", http.StatusInternalServerError)
	}
}

func (srv *Server) handleStatsEvents(writer http.ResponseWriter, request *http.Request) {
	flusher, ok := writer.(http.Flusher)
	if !ok {
		http.Error(writer, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	// Use SSE so the UI can update without reloading the full page.
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")

	ctx := request.Context()
	stream, stop := srv.store.Subscribe(ctx)
	defer stop()

	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepAlive.C:
			fmt.Fprint(writer, ": keep-alive\n\n")
			flusher.Flush()
		case snapshot, ok := <-stream:
			if !ok {
				return
			}
			payload := buildStatsPayload(snapshot)
			data, err := json.Marshal(payload)
			if err != nil {
				return
			}
			fmt.Fprintf(writer, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (srv *Server) handleAlertsEvents(writer http.ResponseWriter, request *http.Request) {
	flusher, ok := writer.(http.Flusher)
	if !ok {
		http.Error(writer, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	// Use SSE so the UI can update the alerts list without reloading the page.
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")

	ctx := request.Context()
	stream, stop := srv.store.Subscribe(ctx)
	defer stop()

	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepAlive.C:
			fmt.Fprint(writer, ": keep-alive\n\n")
			flusher.Flush()
		case snapshot, ok := <-stream:
			if !ok {
				return
			}
			html, err := srv.renderAlertsHTML(buildAlerts(snapshot))
			if err != nil {
				return
			}
			data, err := json.Marshal(map[string]string{"html": html})
			if err != nil {
				return
			}
			fmt.Fprintf(writer, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (srv *Server) handleHostsEvents(writer http.ResponseWriter, request *http.Request) {
	flusher, ok := writer.(http.Flusher)
	if !ok {
		http.Error(writer, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	// Use SSE so the UI can update host/service state without full reloads.
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")

	ctx := request.Context()
	stream, stop := srv.store.Subscribe(ctx)
	defer stop()

	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepAlive.C:
			fmt.Fprint(writer, ": keep-alive\n\n")
			flusher.Flush()
		case snapshot, ok := <-stream:
			if !ok {
				return
			}
			parents, heads := buildParentHierarchy(snapshot)
			var headViews []hostView
			for _, host := range heads {
				headViews = append(headViews, buildHostView(host, parents, snapshot))
			}
			sort.Slice(headViews, func(i, j int) bool {
				return headViews[i].Name < headViews[j].Name
			})
			html, err := srv.renderHostsHTML(headViews, snapshot)
			if err != nil {
				return
			}
			data, err := json.Marshal(map[string]string{"html": html})
			if err != nil {
				return
			}
			fmt.Fprintf(writer, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (srv *Server) handleAddGroup(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "invalid form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(request.FormValue("group"))
	if name != "" {
		_ = srv.store.AddGroup(request.Context(), name)
	}
	http.Redirect(writer, request, "/", http.StatusSeeOther)
}

func (srv *Server) handleAssignGroup(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "invalid form", http.StatusBadRequest)
		return
	}
	host := strings.TrimSpace(request.FormValue("host"))
	group := strings.TrimSpace(request.FormValue("group"))
	if host != "" && group != "" {
		_ = srv.store.AssignHostGroup(request.Context(), host, group)
	}
	http.Redirect(writer, request, "/", http.StatusSeeOther)
}

func (srv *Server) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !srv.isAllowedIP(request) {
			http.Error(writer, "forbidden", http.StatusForbidden)
			return
		}
		user, pass, ok := request.BasicAuth()
		if !ok || user != srv.auth.Username || pass != srv.auth.Password {
			writer.Header().Set("WWW-Authenticate", "Basic realm=\"chicha-pulse\"")
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (srv *Server) isAllowedIP(request *http.Request) bool {
	// Enforce allow-lists so only trusted IPs reach the UI.
	if len(srv.allowIPs) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	for _, entry := range srv.allowIPs {
		clean := strings.TrimSpace(entry)
		if clean == "" {
			continue
		}
		if strings.Contains(clean, "/") {
			_, block, err := net.ParseCIDR(clean)
			if err == nil && block.Contains(ip) {
				return true
			}
			continue
		}
		if ip.Equal(net.ParseIP(clean)) {
			return true
		}
	}
	return false
}

// ---- View models ----

type pageView struct {
	Title         string
	TotalServices int
	Stats         statsView
	Groups        []groupView
	GroupNames    []string
	Heads         []hostView
	Alerts        []alertView
}

type groupView struct {
	Name  string
	Hosts []hostSummary
}

type hostSummary struct {
	Name        string
	StatusLabel string
	StatusClass string
}

type hostView struct {
	Name        string
	Address     string
	Group       string
	OSName      string
	OSVersion   string
	OSLogo      string
	StatusLabel string
	StatusClass string
	Services    []serviceView
	Guests      []hostView
}

type serviceView struct {
	Name        string
	Command     string
	Notes       string
	Interval    int
	SSHUser     string
	SSHKeyPath  string
	StatusLabel string
	StatusClass string
	CheckedAt   string
	Output      string
}

type alertView struct {
	HostName    string
	ServiceName string
	StatusLabel string
	StatusClass string
	Output      string
	CheckedAt   string
}

type statsView struct {
	Total        int
	Errors       int
	Warning      int
	Critical     int
	Unknown      int
	Planned      int
	Running      int
	OverallLabel string
	OverallClass string
}

type statsPayload struct {
	TotalServices int    `json:"total_services"`
	ErrorCount    int    `json:"error_count"`
	WarningCount  int    `json:"warning_count"`
	CriticalCount int    `json:"critical_count"`
	UnknownCount  int    `json:"unknown_count"`
	PlannedCount  int    `json:"planned_count"`
	RunningCount  int    `json:"running_count"`
	OverallLabel  string `json:"overall_label"`
	OverallClass  string `json:"overall_class"`
}

type alertsPayload struct {
	Alerts []alertView
}

type hostsPayload struct {
	Heads      []hostView
	GroupNames []string
}

// ---- Template rendering ----

func (srv *Server) renderAlertsHTML(alerts []alertView) (string, error) {
	// Render just the alerts card so SSE updates stay lightweight.
	var buffer strings.Builder
	payload := buildAlertsPayload(alerts)
	if err := srv.alertsTemplate.Execute(&buffer, payload); err != nil {
		return "", err
	}
	return buffer.String(), nil
}

func (srv *Server) renderHostsHTML(heads []hostView, inventory model.Inventory) (string, error) {
	// Render host hierarchy as a partial so the UI can swap it in-place.
	var buffer strings.Builder
	payload := buildHostsPayload(heads, inventory)
	if err := srv.hostsTemplate.Execute(&buffer, payload); err != nil {
		return "", err
	}
	return buffer.String(), nil
}

// ---- View helpers ----

func buildView(inventory model.Inventory, title string) pageView {
	parents, heads := buildParentHierarchy(inventory)

	var headViews []hostView
	for _, host := range heads {
		headViews = append(headViews, buildHostView(host, parents, inventory))
	}
	sort.Slice(headViews, func(i, j int) bool {
		return headViews[i].Name < headViews[j].Name
	})

	groups, groupNames := buildGroups(inventory)
	alerts := buildAlerts(inventory)
	return pageView{
		Title:         title,
		TotalServices: countServices(inventory),
		Stats:         buildStats(inventory),
		Groups:        groups,
		GroupNames:    groupNames,
		Heads:         headViews,
		Alerts:        alerts,
	}
}

func buildAlertsPayload(alerts []alertView) alertsPayload {
	// Keep a stable structure for the alerts stream payload.
	return alertsPayload{Alerts: alerts}
}

func buildHostsPayload(heads []hostView, inventory model.Inventory) hostsPayload {
	// Include group names so the host assignment dropdown stays current.
	_, groupNames := buildGroups(inventory)
	return hostsPayload{
		Heads:      heads,
		GroupNames: groupNames,
	}
}

func buildParentHierarchy(inventory model.Inventory) (map[string][]*model.Host, []*model.Host) {
	// Prefer detected parents so live topology overrides static Nagios parents.
	parents := map[string][]*model.Host{}
	var heads []*model.Host
	for _, host := range inventory.Hosts {
		parentNames := resolveHostParents(host)
		if len(parentNames) == 0 {
			heads = append(heads, host)
			continue
		}
		for _, parent := range parentNames {
			parents[parent] = append(parents[parent], host)
		}
	}
	return parents, heads
}

func resolveHostParents(host *model.Host) []string {
	if strings.TrimSpace(host.DetectedParent) != "" {
		return []string{host.DetectedParent}
	}
	if len(host.Parents) == 0 {
		return nil
	}
	return append([]string(nil), host.Parents...)
}

func buildGroups(inventory model.Inventory) ([]groupView, []string) {
	var names []string
	for name := range inventory.Groups {
		names = append(names, name)
	}
	sort.Strings(names)

	var groups []groupView
	for _, name := range names {
		var hosts []hostSummary
		for _, host := range inventory.Hosts {
			if host.Group != name {
				continue
			}
			label, class := hostStatus(host, inventory)
			hosts = append(hosts, hostSummary{Name: host.Name, StatusLabel: label, StatusClass: class})
		}
		sort.Slice(hosts, func(i, j int) bool {
			return hosts[i].Name < hosts[j].Name
		})
		groups = append(groups, groupView{Name: name, Hosts: hosts})
	}
	return groups, names
}

func buildAlerts(inventory model.Inventory) []alertView {
	var alerts []alertView
	for key, status := range inventory.Statuses {
		if status.Status == 0 {
			continue
		}
		parts := strings.SplitN(key, "/", 2)
		hostName := parts[0]
		serviceName := ""
		if len(parts) > 1 {
			serviceName = parts[1]
		}
		label, class := statusLabel(status.Status)
		alerts = append(alerts, alertView{
			HostName:    hostName,
			ServiceName: serviceName,
			StatusLabel: label,
			StatusClass: class,
			Output:      status.Output,
			CheckedAt:   formatTime(status.CheckedAt),
		})
	}
	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].CheckedAt == alerts[j].CheckedAt {
			return alerts[i].HostName < alerts[j].HostName
		}
		return alerts[i].CheckedAt > alerts[j].CheckedAt
	})
	return alerts
}

func buildHostView(host *model.Host, parents map[string][]*model.Host, inventory model.Inventory) hostView {
	services := make([]serviceView, 0, len(host.Services))
	for _, service := range host.Services {
		key := host.Name + "/" + service.Name
		status, ok := inventory.Statuses[key]
		label, class := statusLabelFromStatus(status, ok)
		services = append(services, serviceView{
			Name:        service.Name,
			Command:     displayServiceCommand(host, service),
			Notes:       service.Notes,
			Interval:    service.CheckIntervalMinutes,
			SSHUser:     service.SSHUser,
			SSHKeyPath:  service.SSHKeyPath,
			StatusLabel: label,
			StatusClass: class,
			CheckedAt:   formatTime(status.CheckedAt),
			Output:      status.Output,
		})
	}
	sort.Slice(services, func(i, j int) bool {
		return services[i].Name < services[j].Name
	})

	var guests []hostView
	for _, child := range parents[host.Name] {
		guests = append(guests, buildHostView(child, parents, inventory))
	}
	if len(guests) > 0 {
		sort.Slice(guests, func(i, j int) bool {
			return guests[i].Name < guests[j].Name
		})
	}

	label, class := hostStatus(host, inventory)

	return hostView{
		Name:        host.Name,
		Address:     host.Address,
		Group:       host.Group,
		OSName:      host.OSName,
		OSVersion:   host.OSVersion,
		OSLogo:      host.OSLogo,
		StatusLabel: label,
		StatusClass: class,
		Services:    services,
		Guests:      guests,
	}
}

func buildStats(inventory model.Inventory) statsView {
	// Count statuses by severity so the UI can show error breakdowns.
	stats := statsView{}
	for _, host := range inventory.Hosts {
		for _, service := range host.Services {
			stats.Total++
			key := host.Name + "/" + service.Name
			status, ok := inventory.Statuses[key]
			if !ok {
				stats.Unknown++
				continue
			}
			switch status.Status {
			case 0:
				// OK results are not errors, but they still contribute to totals.
			case 1:
				stats.Warning++
			case 2:
				stats.Critical++
			default:
				stats.Unknown++
			}
		}
	}
	stats.Errors = stats.Warning + stats.Critical + stats.Unknown
	stats.Planned = inventory.Activity.Planned
	stats.Running = inventory.Activity.Running
	stats.OverallLabel, stats.OverallClass = overallStatus(inventory)
	return stats
}

func buildStatsPayload(inventory model.Inventory) statsPayload {
	// Convert the internal stats struct into a stable JSON payload.
	stats := buildStats(inventory)
	return statsPayload{
		TotalServices: stats.Total,
		ErrorCount:    stats.Errors,
		WarningCount:  stats.Warning,
		CriticalCount: stats.Critical,
		UnknownCount:  stats.Unknown,
		PlannedCount:  stats.Planned,
		RunningCount:  stats.Running,
		OverallLabel:  stats.OverallLabel,
		OverallClass:  stats.OverallClass,
	}
}

func overallStatus(inventory model.Inventory) (string, string) {
	// Summarize the worst status so the UI can color the live indicator.
	worst := -1
	for _, status := range inventory.Statuses {
		label, _ := statusLabel(status.Status)
		severity := statusSeverity(label)
		if severity > worst {
			worst = severity
		}
	}
	if worst == -1 {
		return "UNKNOWN", "status-unknown"
	}
	return statusLabelFromSeverity(worst)
}

func hostStatus(host *model.Host, inventory model.Inventory) (string, string) {
	worst := -1
	for _, service := range host.Services {
		key := host.Name + "/" + service.Name
		status, ok := inventory.Statuses[key]
		label, class := statusLabelFromStatus(status, ok)
		severity := statusSeverity(label)
		if severity > worst {
			worst = severity
			if severity == severityCritical {
				return label, class
			}
		}
	}
	if worst == -1 {
		return "UNKNOWN", "status-unknown"
	}
	return statusLabelFromSeverity(worst)
}

func statusLabelFromStatus(status model.ServiceStatus, ok bool) (string, string) {
	if !ok {
		return "UNKNOWN", "status-unknown"
	}
	return statusLabel(status.Status)
}

func statusLabel(code int) (string, string) {
	switch code {
	case 0:
		return "OK", "status-ok"
	case 1:
		return "WARNING", "status-warning"
	case 2:
		return "CRITICAL", "status-critical"
	default:
		return "UNKNOWN", "status-unknown"
	}
}

const (
	severityUnknown  = 0
	severityOk       = 1
	severityWarning  = 2
	severityCritical = 3
)

func statusSeverity(label string) int {
	switch label {
	case "OK":
		return severityOk
	case "WARNING":
		return severityWarning
	case "CRITICAL":
		return severityCritical
	default:
		return severityUnknown
	}
}

func statusLabelFromSeverity(severity int) (string, string) {
	switch severity {
	case severityOk:
		return "OK", "status-ok"
	case severityWarning:
		return "WARNING", "status-warning"
	case severityCritical:
		return "CRITICAL", "status-critical"
	default:
		return "UNKNOWN", "status-unknown"
	}
}

func countServices(inventory model.Inventory) int {
	count := 0
	for _, host := range inventory.Hosts {
		count += len(host.Services)
	}
	return count
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339)
}

func displayServiceCommand(host *model.Host, service model.Service) string {
	// Prefer showing the native ssh command so operators see the real connection shape.
	if command, ok := legacySSHDisplayCommand(service.CheckCommand); ok {
		return command
	}
	if command := buildSSHCommandDisplay(host, service); command != "" {
		return command
	}
	return service.CheckCommand
}

func legacySSHDisplayCommand(command string) (string, bool) {
	// Translate legacy check_ssh invocations into a plain ssh command for readability.
	fields := strings.Fields(command)
	for index, field := range fields {
		if strings.HasSuffix(field, "check_ssh") || strings.Contains(field, "/check_ssh") {
			if index+1 >= len(fields) {
				return "", false
			}
			target := fields[index+1]
			remoteCommand := ""
			if index+2 < len(fields) {
				remoteCommand = normalizeRemoteCommand(strings.Join(fields[index+2:], " "))
			}
			parts := []string{"ssh", target}
			if remoteCommand != "" {
				parts = append(parts, remoteCommand)
			}
			return strings.Join(parts, " "), true
		}
	}
	return "", false
}

func buildSSHCommandDisplay(host *model.Host, service model.Service) string {
	// Use the parsed SSH settings so check_by_ssh commands read as standard ssh.
	if service.SSHCommand == "" && service.SSHUser == "" && service.SSHKeyPath == "" && service.SSHPort == 0 {
		return ""
	}
	address := host.Address
	if address == "" {
		address = host.Name
	}
	if address == "" {
		return ""
	}
	target := address
	if strings.TrimSpace(service.SSHUser) != "" {
		target = service.SSHUser + "@" + address
	}
	parts := []string{"ssh"}
	if service.SSHPort != 0 {
		parts = append(parts, "-p", strconv.Itoa(service.SSHPort))
	}
	if strings.TrimSpace(service.SSHKeyPath) != "" {
		parts = append(parts, "-i", service.SSHKeyPath)
	}
	parts = append(parts, target)
	if strings.TrimSpace(service.SSHCommand) != "" {
		parts = append(parts, service.SSHCommand)
	}
	return strings.Join(parts, " ")
}

func normalizeRemoteCommand(command string) string {
	// Unquote commands so the display stays readable and matches ssh expectations.
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

// ---- Templates ----

const indexTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{.Title}}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2rem; background: #f6f6f6; }
    h1 { color: #222; }
    .card { background: white; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; }
    .host { background: white; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; border-left: 6px solid #ddd; }
    .services { margin: 0.5rem 0 0; padding-left: 1rem; }
    .guest { margin-left: 1.5rem; border-left: 2px solid #ddd; padding-left: 1rem; }
    .meta { color: #666; font-size: 0.9rem; }
    .status-ok { border-left-color: #2ecc71; }
    .status-warning { border-left-color: #f1c40f; }
    .status-critical { border-left-color: #e74c3c; }
    .status-unknown { border-left-color: #95a5a6; }
    .badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.8rem; color: white; }
    .badge-ok { background: #2ecc71; }
    .badge-warning { background: #f1c40f; }
    .badge-critical { background: #e74c3c; }
    .badge-unknown { background: #95a5a6; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 0.5rem; border-bottom: 1px solid #eee; text-align: left; }
    form.inline { display: inline; }
    .stats-row { display: flex; flex-wrap: wrap; gap: 1rem; }
    .stats-item { min-width: 10rem; }
    .live-indicator { font-weight: bold; color: #2c3e50; }
    .trend { font-weight: bold; margin-left: 0.5rem; }
  </style>
</head>
<body>
  <h1>{{.Title}}</h1>

  <div class="card">
    <h2>Live task stats</h2>
    <div class="stats-row">
      <div class="stats-item"><strong>Total services:</strong> <span id="stat-total">{{.Stats.Total}}</span></div>
      <div class="stats-item"><strong>Errors:</strong> <span id="stat-errors">{{.Stats.Errors}}</span><span id="stat-error-trend" class="trend"></span></div>
      <div class="stats-item">Warning: <span id="stat-warning">{{.Stats.Warning}}</span></div>
      <div class="stats-item">Critical: <span id="stat-critical">{{.Stats.Critical}}</span></div>
      <div class="stats-item">Unknown: <span id="stat-unknown">{{.Stats.Unknown}}</span></div>
      <div class="stats-item">Planned soon: <span id="stat-planned">{{.Stats.Planned}}</span></div>
      <div class="stats-item">Running now: <span id="stat-running">{{.Stats.Running}}</span></div>
      <div class="stats-item">Overall: <span id="stat-overall" class="badge {{statusBadge .Stats.OverallClass}}">{{.Stats.OverallLabel}}</span></div>
    </div>
    <div class="meta live-indicator" id="stat-connection">Live updates connected.</div>
  </div>

  <div class="card">
    <h2>Groups</h2>
    <form method="post" action="/groups">
      <input type="text" name="group" placeholder="New group" />
      <button type="submit">Add group</button>
    </form>
    {{if .Groups}}
      {{range .Groups}}
        <h3>{{.Name}}</h3>
        {{if .Hosts}}
          <ul>
            {{range .Hosts}}
              <li><span class="badge {{statusBadge .StatusClass}}">{{.StatusLabel}}</span> {{.Name}}</li>
            {{end}}
          </ul>
        {{else}}
          <div class="meta">No hosts assigned yet.</div>
        {{end}}
      {{end}}
    {{else}}
      <div class="meta">No groups yet.</div>
    {{end}}
  </div>

  <div id="alerts-card">
    {{template "alertsCard" .}}
  </div>

  <div id="hosts-tree">
    {{template "hostsTree" .}}
  </div>
  <script>
    (function () {
      // Use SSE to update the stats card without reloading the page.
      var totalEl = document.getElementById("stat-total");
      var errorEl = document.getElementById("stat-errors");
      var warningEl = document.getElementById("stat-warning");
      var criticalEl = document.getElementById("stat-critical");
      var unknownEl = document.getElementById("stat-unknown");
      var plannedEl = document.getElementById("stat-planned");
      var runningEl = document.getElementById("stat-running");
      var overallEl = document.getElementById("stat-overall");
      var connectionEl = document.getElementById("stat-connection");
      var trendEl = document.getElementById("stat-error-trend");
      var lastErrors = Number(errorEl.textContent) || 0;

      if (!window.EventSource) {
        connectionEl.textContent = "Live updates unavailable (EventSource not supported).";
        return;
      }

      function statusBadge(statusClass) {
        if (statusClass === "status-ok") {
          return "badge-ok";
        }
        if (statusClass === "status-warning") {
          return "badge-warning";
        }
        if (statusClass === "status-critical") {
          return "badge-critical";
        }
        return "badge-unknown";
      }

      var source = new EventSource("/events/stats");
      source.onmessage = function (event) {
        try {
          var payload = JSON.parse(event.data);
          totalEl.textContent = payload.total_services;
          errorEl.textContent = payload.error_count;
          warningEl.textContent = payload.warning_count;
          criticalEl.textContent = payload.critical_count;
          unknownEl.textContent = payload.unknown_count;
          plannedEl.textContent = payload.planned_count;
          runningEl.textContent = payload.running_count;
          overallEl.textContent = payload.overall_label;
          overallEl.className = "badge " + statusBadge(payload.overall_class);
          var delta = payload.error_count - lastErrors;
          if (delta > 0) {
            trendEl.textContent = "↑ " + delta;
          } else if (delta < 0) {
            trendEl.textContent = "↓ " + Math.abs(delta);
          } else {
            trendEl.textContent = "";
          }
          lastErrors = payload.error_count;
          connectionEl.textContent = "Live updates connected.";
        } catch (err) {
          connectionEl.textContent = "Live updates received malformed data.";
        }
      };
      source.onerror = function () {
        connectionEl.textContent = "Live updates disconnected; retrying.";
      };

      var alertsSource = new EventSource("/events/alerts");
      alertsSource.onmessage = function (event) {
        try {
          var payload = JSON.parse(event.data);
          document.getElementById("alerts-card").innerHTML = payload.html;
        } catch (err) {
          connectionEl.textContent = "Live updates received malformed data.";
        }
      };

      var hostsSource = new EventSource("/events/hosts");
      hostsSource.onmessage = function (event) {
        try {
          var payload = JSON.parse(event.data);
          document.getElementById("hosts-tree").innerHTML = payload.html;
        } catch (err) {
          connectionEl.textContent = "Live updates received malformed data.";
        }
      };
    })();
  </script>
</body>
</html>
{{define "alertsCard"}}
  {{if .Alerts}}
    <div class="card">
      <h2>Recent alerts</h2>
      <table>
        <thead>
          <tr><th>Status</th><th>Host</th><th>Service</th><th>Output</th><th>Checked</th></tr>
        </thead>
        <tbody>
          {{range .Alerts}}
            <tr>
              <td><span class="badge {{statusBadge .StatusClass}}">{{.StatusLabel}}</span></td>
              <td>{{.HostName}}</td>
              <td>{{.ServiceName}}</td>
              <td>{{.Output}}</td>
              <td>{{.CheckedAt}}</td>
            </tr>
          {{end}}
        </tbody>
      </table>
    </div>
  {{else}}
    <div class="card">
      <h2>Recent alerts</h2>
      <div class="meta">No active alerts.</div>
    </div>
  {{end}}
{{end}}
{{define "hostsTree"}}
  {{range .Heads}}
    <div class="host {{.StatusClass}}">
      <h2>{{.Name}} <span class="badge {{statusBadge .StatusClass}}">{{.StatusLabel}}</span></h2>
      {{if .Address}}<div class="meta">Address: {{.Address}}</div>{{end}}
      {{if .OSName}}<div class="meta">OS: {{.OSLogo}} {{.OSName}} {{.OSVersion}}</div>{{end}}
      {{if $.GroupNames}}
        {{ $current := .Group }}
        <form class="inline" method="post" action="/assign">
          <input type="hidden" name="host" value="{{.Name}}" />
          <select name="group">
            {{range $.GroupNames}}
              <option value="{{.}}" {{if eq . $current}}selected{{end}}>{{.}}</option>
            {{end}}
          </select>
          <button type="submit">Assign group</button>
        </form>
      {{end}}
      {{template "services" .}}
      {{template "guests" .}}
    </div>
  {{else}}
    <p>No hosts imported yet.</p>
  {{end}}
{{end}}
{{define "services"}}
  {{if .Services}}
    <h3>Services</h3>
    <ul class="services">
      {{range .Services}}
        <li>
          <strong>{{.Name}}</strong>
          <span class="badge {{statusBadge .StatusClass}}">{{.StatusLabel}}</span>
          — {{.Command}}
          {{if .Notes}} ({{.Notes}}){{end}}
          {{if .Interval}}<span class="meta"> every {{.Interval}}m</span>{{end}}
          {{if .SSHUser}}<span class="meta"> ssh {{.SSHUser}}</span>{{end}}
          {{if .SSHKeyPath}}<span class="meta"> key {{.SSHKeyPath}}</span>{{end}}
          {{if .CheckedAt}}<div class="meta">Checked: {{.CheckedAt}} — {{.Output}}</div>{{end}}
        </li>
      {{end}}
    </ul>
  {{end}}
{{end}}
{{define "guests"}}
  {{if .Guests}}
    <h3>Virtual machines</h3>
    {{range .Guests}}
      <div class="guest {{.StatusClass}}">
        <h4>{{.Name}} <span class="badge {{statusBadge .StatusClass}}">{{.StatusLabel}}</span></h4>
        {{if .Address}}<div class="meta">Address: {{.Address}}</div>{{end}}
        {{if .OSName}}<div class="meta">OS: {{.OSLogo}} {{.OSName}} {{.OSVersion}}</div>{{end}}
        {{template "services" .}}
        {{template "guests" .}}
      </div>
    {{end}}
  {{end}}
{{end}}
`

const alertsTemplate = `{{if .Alerts}}
  <div class="card">
    <h2>Recent alerts</h2>
    <table>
      <thead>
        <tr><th>Status</th><th>Host</th><th>Service</th><th>Output</th><th>Checked</th></tr>
      </thead>
      <tbody>
        {{range .Alerts}}
          <tr>
            <td><span class="badge {{statusBadge .StatusClass}}">{{.StatusLabel}}</span></td>
            <td>{{.HostName}}</td>
            <td>{{.ServiceName}}</td>
            <td>{{.Output}}</td>
            <td>{{.CheckedAt}}</td>
          </tr>
        {{end}}
      </tbody>
    </table>
  </div>
{{else}}
  <div class="card">
    <h2>Recent alerts</h2>
    <div class="meta">No active alerts.</div>
  </div>
{{end}}`

const hostsTemplate = `{{range .Heads}}
  <div class="host {{.StatusClass}}">
    <h2>{{.Name}} <span class="badge {{statusBadge .StatusClass}}">{{.StatusLabel}}</span></h2>
    {{if .Address}}<div class="meta">Address: {{.Address}}</div>{{end}}
    {{if .OSName}}<div class="meta">OS: {{.OSLogo}} {{.OSName}} {{.OSVersion}}</div>{{end}}
    {{if $.GroupNames}}
      {{ $current := .Group }}
      <form class="inline" method="post" action="/assign">
        <input type="hidden" name="host" value="{{.Name}}" />
        <select name="group">
          {{range $.GroupNames}}
            <option value="{{.}}" {{if eq . $current}}selected{{end}}>{{.}}</option>
          {{end}}
        </select>
        <button type="submit">Assign group</button>
      </form>
    {{end}}
    {{template "services" .}}
    {{template "guests" .}}
  </div>
{{else}}
  <p>No hosts imported yet.</p>
{{end}}
{{define "services"}}
  {{if .Services}}
    <h3>Services</h3>
    <ul class="services">
      {{range .Services}}
        <li>
          <strong>{{.Name}}</strong>
          <span class="badge {{statusBadge .StatusClass}}">{{.StatusLabel}}</span>
          — {{.Command}}
          {{if .Notes}} ({{.Notes}}){{end}}
          {{if .Interval}}<span class="meta"> every {{.Interval}}m</span>{{end}}
          {{if .SSHUser}}<span class="meta"> ssh {{.SSHUser}}</span>{{end}}
          {{if .SSHKeyPath}}<span class="meta"> key {{.SSHKeyPath}}</span>{{end}}
          {{if .CheckedAt}}<div class="meta">Checked: {{.CheckedAt}} — {{.Output}}</div>{{end}}
        </li>
      {{end}}
    </ul>
  {{end}}
{{end}}
{{define "guests"}}
  {{if .Guests}}
    <h3>Virtual machines</h3>
    {{range .Guests}}
      <div class="guest {{.StatusClass}}">
        <h4>{{.Name}} <span class="badge {{statusBadge .StatusClass}}">{{.StatusLabel}}</span></h4>
        {{if .Address}}<div class="meta">Address: {{.Address}}</div>{{end}}
        {{if .OSName}}<div class="meta">OS: {{.OSLogo}} {{.OSName}} {{.OSVersion}}</div>{{end}}
        {{template "services" .}}
        {{template "guests" .}}
      </div>
    {{end}}
  {{end}}
{{end}}`

// ---- Template helpers ----

func statusBadge(class string) string {
	switch class {
	case "status-ok":
		return "badge-ok"
	case "status-warning":
		return "badge-warning"
	case "status-critical":
		return "badge-critical"
	default:
		return "badge-unknown"
	}
}

// ---- Lifecycle ----

// Run starts the HTTP server with a cancellable context so the main package can shut it down.
func Run(ctx context.Context, server *http.Server) error {
	shutdownErr := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			_ = server.Close()
		}
		shutdownErr <- err
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	if err := <-shutdownErr; err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}
