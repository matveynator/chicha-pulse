package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"chicha-pulse/pkg/fleet"
)

type fleetSettingsView struct {
	CSRF string
	Message string
	Error string
	RobotUser string
	SelectelAccount string
	SelectelUser string
	SSHUser string
	SSHKeyPath string
	SSHPort int
	PollSeconds int
	RobotReady bool
	CloudReady bool
	SelectelReady bool
	Enabled bool
}

func newFleetCSRF() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

// /fleet/settings is only accessible to admin users. Password/token fields
// are write-only, even for administrators; GET responses never contain secrets.
func (srv *Server) handleFleetSettings(w http.ResponseWriter, r *http.Request) {
	if !srv.permissionsFromRequest(r).CanAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	path := fleet.SettingsPath()
	saved, err := fleet.LoadSettings(path)
	if err != nil {
		http.Error(w, "fleet settings unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	message, errorText := "", ""
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(srv.fleetCSRF)) != 1 {
			http.Error(w, "invalid form token", http.StatusForbidden)
			return
		}
		updated, err := readFleetForm(saved, r)
		if err != nil {
			errorText = err.Error()
		} else {
			saved = updated
			action := r.PostFormValue("action")
			if action != "save" && action != "test" {
				http.Error(w, "unknown form action", http.StatusBadRequest)
				return
			}
			if action == "test" {
				cfg, _, _, _ := fleet.MergeSettings(fleet.FromEnvironment(), fleet.SSHOptions{}, 90*time.Second, saved)
				ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
				defer cancel()
				hosts, problems := fleet.Discover(ctx, cfg)
				if len(problems) != 0 {
					errorText = "Проверка API: " + strings.Join(problems, "; ")
				} else {
					message = fmt.Sprintf("API подключён: обнаружено серверов %d.", len(hosts))
				}
			}
			if errorText == "" {
				if err := fleet.SaveSettings(path, saved); err != nil {
					errorText = "Не удалось сохранить настройки: "+err.Error()
				} else {
					if srv.fleet != nil {
						srv.fleet.Refresh()
					}
					http.Redirect(w, r, "/fleet/settings?saved=1", http.StatusSeeOther)
					return
				}
			}
		}
	} else if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Get("saved") == "1" {
		message = "Настройки сохранены. Новый опрос серверов запущен."
	}
	cfg, ssh, interval, _ := fleet.MergeSettings(fleet.FromEnvironment(), fleet.SSHOptions{User:"root", Port:22}, 90*time.Second, saved)
	view := fleetSettingsView{
		CSRF: srv.fleetCSRF, Message: message, Error: errorText,
		RobotUser: cfg.HetznerUser, SelectelAccount: cfg.SelectelAccountID, SelectelUser: cfg.SelectelUser,
		SSHUser: ssh.User, SSHKeyPath: ssh.KeyPath, SSHPort: ssh.Port,
		PollSeconds: int(interval.Seconds()), Enabled: srv.fleet != nil,
		RobotReady: cfg.HetznerUser != "" && cfg.HetznerPassword != "",
		CloudReady: cfg.HetznerCloudToken != "",
		SelectelReady: cfg.SelectelToken != "" || (cfg.SelectelAccountID != "" && cfg.SelectelUser != "" && cfg.SelectelPassword != ""),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = fleetSettingsTemplate.Execute(w, view)
}

func readFleetForm(s fleet.Settings, r *http.Request) (fleet.Settings, error) {
	value := func(key string) (string, error) {
		v := strings.TrimSpace(r.PostFormValue(key))
		if len(v) > 4096 || strings.ContainsAny(v, "\r\n\x00") {
			return "", fmt.Errorf("недопустимое значение поля %s", key)
		}
		return v, nil
	}
	// Empty secret fields mean "keep previous value". Clear checkboxes explicitly
	// disable a provider's persisted credentials without revealing those values.
	for _, pair := range [][2]string{
		{"robot_user","robotUser"}, {"robot_password","robotPass"},
		{"cloud_token","cloudToken"},
		{"selectel_account","selectelAccount"}, {"selectel_user","selectelUser"},
		{"selectel_password","selectelPass"}, {"selectel_token","selectelToken"},
		{"ssh_user","sshUser"}, {"ssh_key_path","sshKeyPath"},
	} {
		if _, err := value(pair[0]); err != nil {
			return s, err
		}
	}
	if r.PostFormValue("clear_robot") == "on" {
		s.RobotUser, s.RobotPassword = "", ""
	} else {
		if v, _ := value("robot_user"); v != "" { s.RobotUser = v }
		if v, _ := value("robot_password"); v != "" { s.RobotPassword = v }
	}
	if r.PostFormValue("clear_cloud") == "on" {
		s.CloudToken = ""
	} else if v, _ := value("cloud_token"); v != "" {
		s.CloudToken = v
	}
	if r.PostFormValue("clear_selectel") == "on" {
		s.SelectelAccount, s.SelectelUser, s.SelectelPassword, s.SelectelToken = "", "", "", ""
	} else {
		if v, _ := value("selectel_account"); v != "" { s.SelectelAccount = v }
		if v, _ := value("selectel_user"); v != "" { s.SelectelUser = v }
		password, _ := value("selectel_password")
		token, _ := value("selectel_token")
		if password != "" && token != "" {
			return s, fmt.Errorf("для Selectel укажите либо пароль сервисного пользователя, либо готовый IAM-токен")
		}
		if password != "" { s.SelectelPassword, s.SelectelToken = password, "" }
		if token != "" { s.SelectelToken, s.SelectelPassword = token, "" }
	}
	s.SSHUser, _ = value("ssh_user")
	if s.SSHUser == "" { s.SSHUser = "root" }
	s.SSHKeyPath, _ = value("ssh_key_path")
	port, err := strconv.Atoi(r.PostFormValue("ssh_port"))
	if err != nil || port < 1 || port > 65535 {
		return s, fmt.Errorf("SSH-порт должен быть от 1 до 65535")
	}
	s.SSHPort = port
	poll, err := strconv.Atoi(r.PostFormValue("poll_seconds"))
	if err != nil || poll < 30 || poll > 3600 {
		return s, fmt.Errorf("интервал опроса должен быть от 30 до 3600 секунд")
	}
	s.PollSeconds = poll
	return s, nil
}

var fleetSettingsTemplate = template.Must(template.New("fleet-settings").Parse(`<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Настройки · chicha-pulse</title>
<style>
:root {color-scheme:dark;font-family:Inter,-apple-system,BlinkMacSystemFont,system-ui,sans-serif}
*{box-sizing:border-box} body{background:#0d1117;color:#e6edf3;margin:0;font-size:14px}
header{padding:20px clamp(16px,4vw,48px);border-bottom:1px solid #293446;display:flex;justify-content:space-between;gap:16px}
a{color:#9ecafa;text-decoration:none}main{max-width:940px;margin:0 auto;padding:26px 18px 72px}
h1{font-size:27px;letter-spacing:-.6px;margin:4px 0 10px}h2{font-size:17px;margin:0 0 7px}
p{color:#91a4b8;line-height:1.55}label{display:block;font-weight:550;margin:12px 0 6px}
input[type=text],input[type=password],input[type=number]{display:block;background:#0d1520;border:1px solid #38475b;color:#fff;border-radius:8px;padding:11px 12px;font:inherit;width:100%;min-width:0}
input:focus{outline:2px solid #4c86c9;outline-offset:1px}
.card{background:#161f2a;border:1px solid #2b394c;border-radius:14px;padding:19px 22px;margin-top:14px}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px 20px}
small{color:#96a8ba} .pill{display:inline-block;font-size:12px;font-weight:500;padding:4px 8px;border:1px solid #465268;border-radius:20px;margin-left:8px;color:#a8b5c4}
.pill.yes{color:#6cdea9;border-color:#21513a}
.bar{margin-top:20px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
button{background:#369a71;border:1px solid #369a71;color:#08150f;font-weight:700;border-radius:9px;padding:12px 15px;cursor:pointer;font:inherit}
button.secondary{color:#dce7f5;background:#26374a;border-color:#3c5167}
button:hover{filter:brightness(1.13)}
.notice{margin:14px 0;padding:14px;border-radius:9px;background:#15372c;color:#9ef2c9}
.error{margin:14px 0;padding:14px;border-radius:9px;background:#46272d;color:#ffcbd1;overflow-wrap:anywhere}
.check{display:flex;align-items:center;gap:8px;color:#b7c6d6;font-weight:400}
.check input{width:auto} .note{font-size:12px}
@media(max-width:650px){.grid{grid-template-columns:1fr}.card{padding:16px}}
</style>
</head>
<body>
<header><strong>chicha•pulse / настройки</strong><nav><a href="/fleet">← Серверы</a></nav></header>
<main>
<h1>Подключение серверов</h1>
<p>Укажите доступы один раз. Программа сама найдёт активные серверы Hetzner и Selectel и будет регулярно собирать состояние по SSH. Секреты в браузере повторно не показываются.</p>
{{if .Message}}<div class="notice">{{.Message}}</div>{{end}}
{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
{{if not .Enabled}}<div class="error">Для фонового опроса запустите chicha-pulse с флагом -fleet.</div>{{end}}
<form method="post" action="/fleet/settings" autocomplete="off">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<section class="card">
<h2>1. Hetzner Robot <span class="pill {{if .RobotReady}}yes{{end}}">{{if .RobotReady}}Подключено{{else}}Не настроено{{end}}</span></h2>
<p>Для выделенных физических серверов: учётная запись Robot Webservice API.</p>
<div class="grid">
<div><label for="robot-user">Robot API user</label><input id="robot-user" type="text" name="robot_user" value="{{.RobotUser}}" autocomplete="off"></div>
<div><label for="robot-password">API password</label><input id="robot-password" type="password" name="robot_password" placeholder="Оставьте пустым, чтобы не менять" autocomplete="new-password"></div>
</div>
<label class="check"><input type="checkbox" name="clear_robot"> Удалить сохранённые данные Hetzner Robot</label>
</section>
<section class="card">
<h2>2. Hetzner Cloud <span class="pill {{if .CloudReady}}yes{{end}}">{{if .CloudReady}}Подключено{{else}}Не настроено{{end}}</span></h2>
<p>Необязательно: для виртуальных серверов в Cloud. Токен проекта с правом чтения.</p>
<label for="cloud-token">API token</label><input id="cloud-token" type="password" name="cloud_token" placeholder="Оставьте пустым, чтобы не менять" autocomplete="new-password">
<label class="check"><input type="checkbox" name="clear_cloud"> Удалить сохранённый токен Cloud</label>
</section>
<section class="card">
<h2>3. Selectel <span class="pill {{if .SelectelReady}}yes{{end}}">{{if .SelectelReady}}Подключено{{else}}Не настроено{{end}}</span></h2>
<p>Рекомендуется сервисный IAM-пользователь Selectel. Его пароль позволяет автоматически обновлять токены.</p>
<div class="grid">
<div><label for="selectel-account">Номер аккаунта</label><input id="selectel-account" name="selectel_account" type="text" value="{{.SelectelAccount}}" autocomplete="off"></div>
<div><label for="selectel-user">Сервисный пользователь</label><input id="selectel-user" name="selectel_user" type="text" value="{{.SelectelUser}}" autocomplete="off"></div>
<div><label for="selectel-password">Пароль сервисного пользователя</label><input id="selectel-password" name="selectel_password" type="password" placeholder="Не менять" autocomplete="new-password"></div>
<div><label for="selectel-token">Готовый IAM-токен (вместо пароля)</label><input id="selectel-token" name="selectel_token" type="password" placeholder="Необязательно, срок действия ограничен" autocomplete="new-password"></div>
</div>
<label class="check"><input type="checkbox" name="clear_selectel"> Удалить сохранённые данные Selectel</label>
</section>
<section class="card">
<h2>4. SSH и частота проверок</h2>
<p>Подключение по ключу без пароля. Файл приватного ключа должен находиться на машине, где запущен chicha-pulse. Проверка отпечатков SSH-серверов обязательна.</p>
<div class="grid">
<div><label for="ssh-user">SSH-пользователь</label><input id="ssh-user" name="ssh_user" type="text" value="{{.SSHUser}}" required></div>
<div><label for="ssh-key-path">Путь к SSH-ключу на сервере мониторинга</label><input id="ssh-key-path" name="ssh_key_path" type="text" value="{{.SSHKeyPath}}" placeholder="/home/monitor/.ssh/id_ed25519"></div>
<div><label for="ssh-port">SSH-порт</label><input id="ssh-port" name="ssh_port" type="number" min="1" max="65535" value="{{.SSHPort}}" required></div>
<div><label for="poll-seconds">Интервал опроса, секунд</label><input id="poll-seconds" name="poll_seconds" type="number" min="30" max="3600" value="{{.PollSeconds}}" required></div>
</div>
<small>Если ключ не указан, будет использован SSH-agent или стандартная конфигурация OpenSSH на сервере мониторинга.</small>
</section>
<div class="bar">
<small>Токены и пароли сохраняются в зашифрованном файле с доступом только для процесса мониторинга. Не открывайте эту страницу по незащищённому HTTP.</small>
<div><button class="secondary" type="submit" name="action" value="test">Проверить API и сохранить</button> <button type="submit" name="action" value="save">Сохранить</button></div>
</div>
</form>
</main>
</body>
</html>`))
