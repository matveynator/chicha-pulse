package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"chicha-pulse/pkg/fleet"
)

type fleetHostView struct {
	Key   string
	State fleet.HostState
}
type fleetPageView struct {
	UpdatedAt string
	Online, Offline, Unknown int
	Hosts []fleetHostView
	Selected *fleetHostView
	Errors []string
	Enabled bool
}
type fleetLiveStatus struct {
	Key string `json:"key"`
	Status string `json:"status"`
	LastProbe time.Time `json:"last_probe,omitempty"`
}
type fleetLiveResponse struct {
	UpdatedAt time.Time `json:"updated_at"`
	Hosts []fleetLiveStatus `json:"hosts"`
	Selected *fleet.HostState `json:"selected,omitempty"`
	Errors []string `json:"errors,omitempty"`
}

func (srv *Server) SetFleetMonitor(m *fleet.Monitor) {
	srv.fleet = m
}

func (srv *Server) loadFleetPage(request *http.Request) (fleetPageView, error) {
	view := fleetPageView{Enabled: srv.fleet != nil}
	if srv.fleet == nil { return view, nil }
	snap, err := srv.fleet.Snapshot(request.Context())
	if err != nil { return view, err }
	view.Errors = snap.Errors
	if !snap.UpdatedAt.IsZero() { view.UpdatedAt = snap.UpdatedAt.Local().Format("2006-01-02 15:04:05 MST") }
	chosen := request.URL.Query().Get("host")
	for _, host := range snap.Hosts {
		item := fleetHostView{Key: host.Host.Provider+"/"+host.Host.ID, State: host}
		switch host.Status {
		case "online": view.Online++
		case "offline": view.Offline++
		default: view.Unknown++
		}
		view.Hosts = append(view.Hosts, item)
		if chosen == item.Key { copy := item; view.Selected = &copy }
	}
	return view, nil
}

func (srv *Server) handleFleetPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	if !srv.permissionsFromRequest(r).CanViewMonitoring || !srv.permissionsFromRequest(r).CanViewServers {
		http.Error(w, "forbidden", http.StatusForbidden); return
	}
	view, err := srv.loadFleetPage(r)
	if err != nil { http.Error(w, "fleet snapshot unavailable", http.StatusServiceUnavailable); return }
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := fleetTemplate.Execute(w, view); err != nil { return }
}

func (srv *Server) handleFleetData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	p := srv.permissionsFromRequest(r)
	if !p.CanViewMonitoring || !p.CanViewServers { http.Error(w, "forbidden", http.StatusForbidden); return }
	if srv.fleet == nil { http.Error(w, "fleet collection disabled", http.StatusServiceUnavailable); return }
	snap, err := srv.fleet.Snapshot(r.Context())
	if err != nil { http.Error(w, "snapshot unavailable", http.StatusServiceUnavailable); return }
	feed := fleetLiveResponse{UpdatedAt: snap.UpdatedAt, Errors: snap.Errors, Hosts: make([]fleetLiveStatus, 0, len(snap.Hosts))}
	chosen := r.URL.Query().Get("host")
	for _, host := range snap.Hosts {
		key := host.Host.Provider+"/"+host.Host.ID
		feed.Hosts = append(feed.Hosts, fleetLiveStatus{Key:key, Status:host.Status, LastProbe:host.LastProbe})
		if key == chosen { copy := host; feed.Selected = &copy }
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(feed)
}

// Prometheus-compatible read-only text metrics, protected by the same Basic Auth.
func (srv *Server) handleFleetMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	if !srv.permissionsFromRequest(r).CanViewMonitoring { http.Error(w, "forbidden", http.StatusForbidden); return }
	if srv.fleet == nil { http.Error(w, "fleet collection disabled", http.StatusServiceUnavailable); return }
	snap, err := srv.fleet.Snapshot(r.Context())
	if err != nil { http.Error(w, "snapshot unavailable", http.StatusServiceUnavailable); return }
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintln(w, "# HELP chicha_fleet_ssh_up 1 if the last SSH probe completed successfully.")
	fmt.Fprintln(w, "# TYPE chicha_fleet_ssh_up gauge")
	for _, item := range snap.Hosts {
		labels := fmt.Sprintf("{provider=%q,server_id=%q,server_name=%q}", item.Host.Provider, item.Host.ID, escapePromLabel(item.Host.Name))
		up := 0
		if item.Status == "online" { up = 1 }
		fmt.Fprintf(w, "chicha_fleet_ssh_up%s %d\n", labels, up)
		if len(item.History) == 0 { continue }
		s := item.History[len(item.History)-1]
		fmt.Fprintf(w, "chicha_fleet_load1%s %.3f\n", labels, s.Load1)
		fmt.Fprintf(w, "chicha_fleet_memory_used_percent%s %.3f\n", labels, s.MemoryUsedPct)
		fmt.Fprintf(w, "chicha_fleet_root_disk_used_percent%s %.3f\n", labels, s.RootDiskUsedPct)
	}
}
func escapePromLabel(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ") }
var fleetTemplate = template.Must(template.New("fleet").Parse`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fleet · chicha-pulse</title>
<style>
:root { color-scheme: dark; font-family: Inter, -apple-system, BlinkMacSystemFont, system-ui, sans-serif; }
* {box-sizing:border-box}
body {margin:0;background:#0d1117;color:#e6edf3;font-size:14px}
a {color:inherit;text-decoration:none}
header {padding:22px clamp(16px,4vw,56px);border-bottom:1px solid #263241;display:flex;align-items:center;justify-content:space-between;gap:16px}
header a.home {font-size:22px;font-weight:720;letter-spacing:-.6px}
header nav {display:flex;gap:22px;color:#98a9be}
main {max-width:1660px;margin:auto;padding:28px clamp(16px,3vw,48px)}
h1 {font-size:28px;letter-spacing:-.8px;margin:4px 0 8px} h2 {font-size:18px;margin:0 0 14px}
.muted {color:#91a4b8} .toolbar {display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:end;margin-bottom:26px}
.summary {display:flex;gap:10px;flex-wrap:wrap}.summary>span {padding:9px 13px;background:#151d28;border:1px solid #253447;border-radius:12px}
.lamp {display:inline-block;width:10px;height:10px;border-radius:50%;background:#8391a5;box-shadow:0 0 0 3px #8391a51c;flex:none}
.lamp.online{background:#35d083;box-shadow:0 0 0 3px #35d08320,0 0 15px #35d08344}
.lamp.offline{background:#f17171;box-shadow:0 0 0 3px #f171711e}.lamp.unknown{background:#e7b955;box-shadow:0 0 0 3px #e7b95520}
.layout {display:grid;grid-template-columns:minmax(255px,325px) minmax(0,1fr);gap:20px;align-items:start}
.panel {background:#151c26;border:1px solid #263447;border-radius:16px;overflow:hidden}
.panelhead {padding:18px;border-bottom:1px solid #263447}
.server-list {max-height:calc(100vh - 250px);overflow:auto}
.server {display:block;padding:15px 18px;border-bottom:1px solid #233143;transition:background .12s}
.server:last-child{border-bottom:0}.server:hover,.server.selected{background:#202b3a}.server.selected{box-shadow:inset 3px 0 #6eacef}
.serverline{display:flex;align-items:center;gap:10px}.serverline strong{font-weight:650;overflow-wrap:anywhere}
.servermeta{padding-left:20px;margin-top:5px;color:#98aabf;font-size:12px}
.content{padding:20px 22px}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin:16px 0 22px}
.metric{background:#101823;border:1px solid #263447;border-radius:12px;padding:14px}
.metric label{display:block;color:#8fa4b9;font-size:12px;margin-bottom:6px}
.metric strong{font-size:21px;font-weight:650;white-space:nowrap}
.chartgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px;margin:15px 0 22px}
.chart {border:1px solid #263447;border-radius:12px;background:#101823;padding:14px}
.chart label {display:block;color:#aebed0;margin-bottom:8px}
canvas{display:block;width:100%;height:116px}
.section {margin-top:10px;border:1px solid #263447;border-radius:12px;background:#101823}
.section summary{cursor:pointer;padding:15px 16px;font-size:14px;font-weight:650}
.section pre{max-height:340px;overflow:auto;margin:0;padding:15px;border-top:1px solid #263447;background:#0b121c;color:#c9d8e7;font:12px/1.55 ui-monospace,Menlo,Consolas,monospace;white-space:pre}
.ips{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}.ip{font:12px ui-monospace,Menlo,monospace;border-radius:6px;padding:6px 8px;background:#253448}
.error{padding:12px 15px;background:#442929;border-radius:10px;color:#ffd3d3;margin:12px 0;overflow-wrap:anywhere}
.warn{padding:12px 15px;background:#3f361f;border-radius:10px;color:#ffe2a3;margin:12px 0;overflow-wrap:anywhere}
.empty{text-align:center;padding:72px 18px;color:#91a4b8}
button{background:#233449;color:#e6edf3;border:1px solid #3d5269;padding:8px 12px;border-radius:8px;cursor:pointer}
.small{font-size:12px}.inline{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
@media(max-width:850px){.layout{grid-template-columns:1fr}.server-list{max-height:340px} header{padding:16px}}
</style>
</head>
<body>
<header><a class="home" href="/fleet">chicha<span style="color:#5ac595">•</span>pulse / fleet</a><nav><a href="/">Monitoring</a><a href="/fleet/metrics">Prometheus</a></nav></header>
<main>
<div class="toolbar">
  <div><h1>Infrastructure fleet</h1><div class="muted">Hetzner · Selectel · SSH-based inventory and telemetry</div></div>
  <div><div class="summary"><span><i class="lamp online"></i> <b id="cnt-online">{{.Online}}</b> connected</span><span><i class="lamp offline"></i> <b id="cnt-offline">{{.Offline}}</b> unreachable</span><span><i class="lamp unknown"></i> <b id="cnt-unknown">{{.Unknown}}</b> unknown</span></div>
  <div class="muted small" style="margin-top:8px" id="updated-at">Updated {{.UpdatedAt}}</div></div>
</div>
{{if not .Enabled}}<div class="warn">Fleet discovery is disabled. Restart chicha-pulse with -fleet and configure provider API credentials.</div>{{end}}
{{range .Errors}}<div class="error">{{.}}</div>{{end}}
<div class="layout">
<section class="panel">
<div class="panelhead"><h2 style="margin:0">Servers ({{len .Hosts}})</h2></div>
<div class="server-list">
{{range .Hosts}}
 <a href="/fleet?host={{urlquery .Key}}" class="server {{if $.Selected}}{{if eq .Key $.Selected.Key}}selected{{end}}{{end}}" title="{{.State.Host.Provider}}">
  <div class="serverline"><i class="lamp {{.State.Status}}" data-led="{{.Key}}"></i><strong>{{.State.Host.Name}}</strong></div>
  <div class="servermeta">{{.State.Host.Provider}} · {{.State.Host.MainIP}}</div>
  <div class="servermeta">{{.State.Host.Datacenter}} · <span data-status="{{.Key}}">{{.State.Status}}</span></div>
 </a>
{{else}}<p class="muted" style="padding:20px">No servers discovered yet.</p>{{end}}
</div>
</section>
<section class="panel">
{{with .Selected}}
<div class="content" id="host-detail" data-host="{{.Key}}">
<div class="inline" style="justify-content:space-between"><h2 style="font-size:25px;letter-spacing:-.4px;margin:0">{{.State.Host.Name}}</h2><div class="inline"><i class="lamp {{.State.Status}}" id="detail-lamp"></i><span id="detail-status">{{.State.Status}}</span> <button type="button" onclick="location.reload()">Refresh details</button></div></div>
<div class="muted" style="margin-top:8px">{{.State.Host.Provider}} · {{.State.Host.State}} · {{.State.Host.Datacenter}} · {{.State.Host.ID}}</div>
{{if .State.SSH.Error}}<div class="warn" id="ssh-error">SSH: {{.State.SSH.Error}}</div>{{else}}<div class="warn" id="ssh-error" hidden></div>{{end}}
<div class="ips">{{if .State.Host.MainIP}}<span class="ip">Primary {{.State.Host.MainIP}}</span>{{end}}{{range .State.Host.Addresses}}<span class="ip">{{.IP}} ({{.Scope}})</span>{{end}}{{range .State.Host.Subnets}}<span class="ip">{{.}}</span>{{end}}</div>
<div class="meta-grid">
 <div class="metric"><label>OS / kernel</label><strong style="font-size:15px" data-section-metric="uname">{{index .State.SSH.Sections "uname"}}</strong></div>
 <div class="metric"><label>Hostname</label><strong style="font-size:15px" data-section-metric="hostname">{{index .State.SSH.Sections "hostname"}}</strong></div>
 <div class="metric"><label>Load (1 min)</label><strong id="latest-load">—</strong></div>
 <div class="metric"><label>RAM used</label><strong id="latest-mem">—</strong></div>
 <div class="metric"><label>Root disk used</label><strong id="latest-disk">—</strong></div>
 <div class="metric"><label>Uptime</label><strong style="font-size:13px" data-section-metric="uptime">{{index .State.SSH.Sections "uptime"}}</strong></div>
</div>
<div class="chartgrid">
 <div class="chart"><label>Load average (1 min)</label><canvas width="320" height="116" data-metric="load1"></canvas></div>
 <div class="chart"><label>Memory utilization</label><canvas width="320" height="116" data-metric="memory_used_pct"></canvas></div>
 <div class="chart"><label>Root filesystem utilization</label><canvas width="320" height="116" data-metric="root_disk_used_pct"></canvas></div>
</div>
{{range $name, $label := .State.SSH.Sections}}
{{end}}
<details class="section" open><summary>Hardware · CPU · memory</summary><pre data-section="hardware">{{index .State.SSH.Sections "hardware"}}</pre><pre data-section="memory">{{index .State.SSH.Sections "memory"}}</pre></details>
<details class="section" open><summary>Disks · filesystem · RAID · SMART</summary><pre data-section="disks">{{index .State.SSH.Sections "disks"}}</pre><pre data-section="filesystem">{{index .State.SSH.Sections "filesystem"}}</pre><pre data-section="raid">{{index .State.SSH.Sections "raid"}}</pre><pre data-section="smart">{{index .State.SSH.Sections "smart"}}</pre></details>
<details class="section" open><summary>Active processes (PID, name, CPU, RAM)</summary><pre data-section="processes">{{index .State.SSH.Sections "processes"}}</pre></details>
<details class="section" open><summary>Running services and listening ports</summary><pre data-section="services">{{index .State.SSH.Sections "services"}}</pre><pre data-section="listeners">{{index .State.SSH.Sections "listeners"}}</pre></details>
<details class="section" open><summary>Application versions</summary><pre data-section="versions">{{index .State.SSH.Sections "versions"}}</pre></details>
<details class="section"><summary>Installed packages (up to 2,000)</summary><pre data-section="packages">{{index .State.SSH.Sections "packages"}}</pre></details>
<details class="section"><summary>Network · interfaces · routes</summary><pre data-section="addresses">{{index .State.SSH.Sections "addresses"}}</pre><pre data-section="routes">{{index .State.SSH.Sections "routes"}}</pre></details>
<details class="section"><summary>OS information · raw metrics</summary><pre data-section="os">{{index .State.SSH.Sections "os"}}</pre><pre data-section="metrics">{{index .State.SSH.Sections "metrics"}}</pre></details>
</div>
{{else}}
<div class="empty"><h2>Select a server</h2><p>Choose a host to inspect CPU, RAM, disks, RAID, processes, applications and network details.</p></div>
{{end}}
</section>
</div>
</main>
<script>
(function () {
  "use strict";
  var root = document.getElementById("host-detail");
  var selected = root ? root.getAttribute("data-host") : "";
  function text(selector, value) { var node = document.querySelector(selector); if (node) node.textContent = value; }
  function plot(canvas, history, field, color, ceiling) {
    var ctx = canvas.getContext("2d"); if (!ctx) return;
    var width = canvas.width, height = canvas.height, pad = 8;
    ctx.clearRect(0,0,width,height);
    ctx.strokeStyle="#324356";ctx.lineWidth=1;
    for(var g=0;g<=3;g++){var gy=pad+(height-2*pad)*g/3;ctx.beginPath();ctx.moveTo(pad,gy);ctx.lineTo(width-pad,gy);ctx.stroke();}
    var vals = history.map(function(s){return Number(s[field])||0;});
    if(!vals.length)return;
    var max = ceiling || Math.max(1,Math.max.apply(null,vals)*1.15);
    ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();
    vals.forEach(function(value,i){ var x=pad+(width-2*pad)*(vals.length===1?1:i/(vals.length-1)); var y=height-pad-Math.min(1,value/max)*(height-2*pad);if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y); });ctx.stroke();
  }
  function renderState(host) {
    if(!host)return;
    text("#detail-status",host.status);
    var led=document.getElementById("detail-lamp");if(led)led.className="lamp "+host.status;
    var err=document.getElementById("ssh-error"); if(err){err.hidden=!host.ssh.error;err.textContent=host.ssh.error?"SSH: "+host.ssh.error:"";}
    Object.keys(host.ssh.sections||{}).forEach(function(key){
      var code=document.querySelector('pre[data-section="'+key+'"]');
      if(code)code.textContent=host.ssh.sections[key];
      var label=document.querySelector('[data-section-metric="'+key+'"]');
      if(label)label.textContent=host.ssh.sections[key];
    });
    var history=host.history||[];
    if(history.length){
      var latest=history[history.length-1];
      text("#latest-load",Number(latest.load1||0).toFixed(2));
      text("#latest-mem",Number(latest.memory_used_pct||0).toFixed(1)+"%");
      text("#latest-disk",Number(latest.root_disk_used_pct||0).toFixed(1)+"%");
    }
    document.querySelectorAll("canvas[data-metric]").forEach(function(canvas) {
      var metric=canvas.getAttribute("data-metric");
      plot(canvas,history,metric,metric==="load1"?"#5da9fa":metric==="memory_used_pct"?"#43d9a3":"#f2bd69",metric==="load1"?0:100);
    });
  }
  function refresh() {
    fetch("/fleet/data"+(selected?"?host="+encodeURIComponent(selected):""),{cache:"no-store"})
      .then(function(res){if(!res.ok)throw Error("HTTP "+res.status);return res.json();})
      .then(function(feed){
        var counts={online:0,offline:0,unknown:0};
        feed.hosts.forEach(function(h){
          var status=counts[h.status]!==undefined?h.status:"unknown";counts[status]++;
          document.querySelectorAll("[data-led]").forEach(function(node){if(node.getAttribute("data-led")===h.key)node.className="lamp "+status;});
          document.querySelectorAll("[data-status]").forEach(function(node){if(node.getAttribute("data-status")===h.key)node.textContent=status;});
        });
        text("#cnt-online",counts.online);text("#cnt-offline",counts.offline);text("#cnt-unknown",counts.unknown);
        text("#updated-at",feed.updated_at?"Updated "+new Date(feed.updated_at).toLocaleString():"Awaiting first scan");
        renderState(feed.selected);
      }).catch(function(){text("#updated-at","Live status update unavailable");});
  }
  refresh();window.setInterval(refresh,15000);
})();
</script>
</body>
</html>
`))
