package web

import (
	"context"
	"html/template"
	"net/http"
	"sort"

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
	store     *store.Store
	auth      AuthConfig
	template  *template.Template
	pageTitle string
}

// NewServer prepares the HTTP handler so the caller can run it with a standard net/http server.
func NewServer(st *store.Store, auth AuthConfig, pageTitle string) (*Server, error) {
	page := template.Must(template.New("index").Parse(indexTemplate))
	return &Server{
		store:     st,
		auth:      auth,
		template:  page,
		pageTitle: pageTitle,
	}, nil
}

// Handler exposes the root HTTP handler with basic auth to keep access simple for now.
func (srv *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
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

func (srv *Server) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		user, pass, ok := request.BasicAuth()
		if !ok || user != srv.auth.Username || pass != srv.auth.Password {
			writer.Header().Set("WWW-Authenticate", "Basic realm=\"chicha-pulse\"")
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// ---- View models ----

type pageView struct {
	Title string
	Heads []hostView
}

type hostView struct {
	Name     string
	Address  string
	Services []serviceView
	Guests   []hostView
}

type serviceView struct {
	Name         string
	CheckCommand string
	Notes        string
}

// ---- View helpers ----

func buildView(inventory model.Inventory, title string) pageView {
	parents := map[string][]*model.Host{}
	var heads []*model.Host
	for _, host := range inventory.Hosts {
		if len(host.Parents) == 0 {
			heads = append(heads, host)
			continue
		}
		for _, parent := range host.Parents {
			parents[parent] = append(parents[parent], host)
		}
	}

	var headViews []hostView
	for _, host := range heads {
		headViews = append(headViews, buildHostView(host, parents))
	}

	sort.Slice(headViews, func(i, j int) bool {
		return headViews[i].Name < headViews[j].Name
	})

	return pageView{Title: title, Heads: headViews}
}

func buildHostView(host *model.Host, parents map[string][]*model.Host) hostView {
	services := make([]serviceView, 0, len(host.Services))
	for _, service := range host.Services {
		services = append(services, serviceView{
			Name:         service.Name,
			CheckCommand: service.CheckCommand,
			Notes:        service.Notes,
		})
	}
	sort.Slice(services, func(i, j int) bool {
		return services[i].Name < services[j].Name
	})

	var guests []hostView
	for _, child := range parents[host.Name] {
		guests = append(guests, buildHostView(child, parents))
	}
	if len(guests) > 0 {
		sort.Slice(guests, func(i, j int) bool {
			return guests[i].Name < guests[j].Name
		})
	}

	return hostView{
		Name:     host.Name,
		Address:  host.Address,
		Services: services,
		Guests:   guests,
	}
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
    .host { background: white; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; }
    .services { margin: 0.5rem 0 0; padding-left: 1rem; }
    .guest { margin-left: 1.5rem; border-left: 2px solid #ddd; padding-left: 1rem; }
    .meta { color: #666; font-size: 0.9rem; }
  </style>
</head>
<body>
  <h1>{{.Title}}</h1>
  {{range .Heads}}
    <div class="host">
      <h2>{{.Name}}</h2>
      {{if .Address}}<div class="meta">Address: {{.Address}}</div>{{end}}
      {{template "services" .}}
      {{template "guests" .}}
    </div>
  {{else}}
    <p>No hosts imported yet.</p>
  {{end}}
</body>
</html>
{{define "services"}}
  {{if .Services}}
    <h3>Services</h3>
    <ul class="services">
      {{range .Services}}
        <li><strong>{{.Name}}</strong> — {{.CheckCommand}}{{if .Notes}} ({{.Notes}}){{end}}</li>
      {{end}}
    </ul>
  {{end}}
{{end}}
{{define "guests"}}
  {{if .Guests}}
    <h3>Virtual machines</h3>
    {{range .Guests}}
      <div class="guest">
        <h4>{{.Name}}</h4>
        {{if .Address}}<div class="meta">Address: {{.Address}}</div>{{end}}
        {{template "services" .}}
        {{template "guests" .}}
      </div>
    {{end}}
  {{end}}
{{end}}
`

// ---- Lifecycle ----

// Run starts the HTTP server with a cancellable context so the main package can shut it down.
func Run(ctx context.Context, server *http.Server) error {
	shutdownErr := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdownErr <- server.Shutdown(context.Background())
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return <-shutdownErr
}
