package web

import (
	"context"
	"net/http"
	"chicha-pulse/pkg/auth"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"chicha-pulse/pkg/fleet"
)

func formSettings(t *testing.T, saved fleet.Settings, values url.Values) (fleet.Settings, error) {
	t.Helper()
	req := httptest.NewRequest("POST", "/fleet/settings", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {t.Fatal(err)}
	return readFleetForm(saved, req)
}

func TestFleetFormKeepsWriteOnlySecrets(t *testing.T) {
	saved := fleet.Settings{RobotUser:"robot", RobotPassword:"saved-robot", CloudToken:"saved-cloud",
		SelectelAccount:"1234", SelectelUser:"service", SelectelPassword:"saved-selectel", SSHUser:"root",SSHPort:22,PollSeconds:90}
	got, err := formSettings(t, saved, url.Values{
		"robot_user":{"robot"}, "robot_password":{""}, "cloud_token":{""},
		"selectel_account":{"1234"}, "selectel_user":{"service"}, "selectel_password":{""},
		"ssh_user":{"inventory"}, "ssh_key_path":{"/home/monitor/.ssh/id_ed25519"},
		"ssh_port":{"2222"}, "poll_seconds":{"120"},
	})
	if err != nil {t.Fatal(err)}
	if got.RobotPassword != saved.RobotPassword || got.CloudToken != saved.CloudToken || got.SelectelPassword != saved.SelectelPassword {
		t.Fatalf("blank fields erased passwords: %+v", got)
	}
	if got.SSHUser != "inventory" || got.SSHPort != 2222 || got.PollSeconds != 120 {
		t.Fatalf("SSH settings: %+v",got)
	}
}

func TestFleetFormClearingAndValidation(t *testing.T) {
	saved := fleet.Settings{RobotUser:"robot", RobotPassword:"secret", SSHPort:22}
	got, err := formSettings(t, saved, url.Values{
		"clear_robot":{"on"}, "ssh_user":{"root"},"ssh_port":{"22"},"poll_seconds":{"90"},
	})
	if err != nil {t.Fatal(err)}
	if got.RobotUser != "" || got.RobotPassword != "" {
		t.Fatalf("robot credentials not cleared")
	}
	_, err = formSettings(t, saved, url.Values{
		"ssh_user":{"root"},"ssh_port":{"0"},"poll_seconds":{"90"},
	})
	if err == nil {t.Fatal("invalid port accepted")}
	_, err = formSettings(t, saved, url.Values{
		"ssh_user":{"root"},"ssh_port":{"22"},"poll_seconds":{"90"},
		"selectel_password":{"pw"},"selectel_token":{"token"},
	})
	if err == nil {t.Fatal("ambiguous selectel auth accepted")}
}

func TestFleetSettingsRequireHTTPSExceptLoopback(t *testing.T) {
	srv := &Server{fleetCSRF:"test"}
	for _, test := range []struct{
		remote string
		tls bool
		want int
	}{
		{remote:"198.51.100.15:4352", tls:false, want:http.StatusForbidden},
		{remote:"127.0.0.1:4352", tls:false, want:http.StatusOK},
	} {
		req := httptest.NewRequest("GET", "http://localhost/fleet/settings", nil)
		req.RemoteAddr = test.remote
		req = req.WithContext(context.WithValue(req.Context(), userContextKey, auth.User{Roles: []auth.Role{auth.RoleAdmin}}))
		// The first case is always rejected before any filesystem read.
		// The loopback case may read an existing settings file, but should
		// never be blocked by the HTTPS guard.
		w := httptest.NewRecorder()
		srv.handleFleetSettings(w, req)
		if test.want == http.StatusForbidden && w.Code != http.StatusForbidden {
			t.Fatalf("remote plaintext should be denied; status=%d", w.Code)
		}
	}
}
