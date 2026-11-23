package fleet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHetznerDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "robot" || pass != "secret" {
			t.Errorf("bad basic auth")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/server" {
			t.Errorf("unexpected URL %q", r.URL.Path)
		}
		w.Write([]byte(`[{"server":{"server_ip":"192.0.2.3","server_number":3,"server_name":"one","status":"ready","ip":["192.0.2.3","192.0.2.4"],"subnet":[{"ip":"2001:db8::","mask":"64"}]}},{"server":{"server_number":4,"status":"in process"}}]`))
	}))
	defer server.Close()
	hosts, problems := Discover(context.Background(), Config{HetznerUser: "robot", HetznerPassword: "secret", HetznerBaseURL: server.URL, Client: server.Client()})
	if len(problems) != 0 || len(hosts) != 1 {
		t.Fatalf("hosts=%+v errors=%v", hosts, problems)
	}
	h := hosts[0]
	if h.ID != "3" || h.MainIP != "192.0.2.3" || len(h.Addresses) != 2 || len(h.Subnets) != 1 {
		t.Fatalf("unexpected server: %+v", h)
	}
}

func TestSelectelPaginationAndIAM(t *testing.T) {
	pages := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/identity/v3/auth/tokens" {
			w.Header().Set("X-Subject-Token", "iam-secret")
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Header.Get("X-Auth-Token") != "iam-secret" {
			t.Errorf("bad IAM token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		page := r.URL.Query().Get("page")
		pages[r.URL.Path+"#"+page]++
		switch r.URL.Path {
		case "/resource":
			if page == "1" {
				w.Write([]byte(`{"limit":1,"result":[{"uuid":"abc","service_type":"server","state":"active","user_desc":"main"}]}`))
			} else {
				w.Write([]byte(`{"limit":1,"result":[]}`))
			}
		case "/network/ipam/ip":
			w.Write([]byte(`{"limit":100,"result":[{"ip":"192.0.2.30","resource_uuid":"abc"},{"ip":"192.0.2.31","resource_uuid":"abc"}]}`))
		case "/network/ipam/local_ip":
			w.Write([]byte(`{"limit":100,"result":[{"ip":"10.0.0.20","resource_uuid":"abc"}]}`))
		case "/boot/os/abc":
			w.Write([]byte(`{"result":{"ipv4_address":"192.0.2.31"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := Config{SelectelAccountID: "123", SelectelUser: "test", SelectelPassword: "secret", SelectelBaseURL: server.URL, SelectelIAMURL: server.URL + "/identity/v3/auth/tokens", Client: server.Client()}
	hosts, problems := Discover(context.Background(), cfg)
	if len(problems) != 0 || len(hosts) != 1 || hosts[0].MainIP != "192.0.2.31" || len(hosts[0].Addresses) != 3 {
		t.Fatalf("hosts=%+v errors=%v", hosts, problems)
	}
	if pages["/resource#2"] != 1 {
		t.Fatalf("pagination not followed: %v", pages)
	}
}

func TestHetznerCloudAndFloatingIPs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cloud-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/servers":
			w.Write([]byte(`{"servers":[{"id":12,"name":"web","status":"running","datacenter":{"name":"hel1-dc2"},"public_net":{"ipv4":{"ip":"192.0.2.10"},"ipv6":{"ip":"2001:db8:1::/64"}},"private_net":[{"ip":"10.0.0.3"}]}],"meta":{"pagination":{"next_page":null}}}`))
		case "/floating_ips":
			w.Write([]byte(`{"floating_ips":[{"ip":"192.0.2.11","server":12}],"meta":{"pagination":{"next_page":null}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	hosts, problems := Discover(context.Background(), Config{HetznerCloudToken: "cloud-secret", HetznerCloudURL: server.URL, Client: server.Client()})
	if len(problems) != 0 || len(hosts) != 1 || hosts[0].MainIP != "192.0.2.10" || len(hosts[0].Addresses) != 3 || len(hosts[0].Subnets) != 1 {
		t.Fatalf("hosts=%+v errors=%v", hosts, problems)
	}
}

func TestProviderErrorsNotLost(t *testing.T) {
	hosts, problems := Discover(context.Background(), Config{HetznerUser: "robot"})
	if len(hosts) != 0 || len(problems) != 1 || !strings.Contains(problems[0], "PASSWORD") {
		t.Fatalf("hosts=%+v errors=%v", hosts, problems)
	}
}

func TestParseSections(t *testing.T) {
	got := parseSections("noise\n__CHICHA_SECTION_uname__\nOpenBSD 8.0\n__CHICHA_SECTION_raid__\nclean\n")
	if got["uname"] != "OpenBSD 8.0" || got["raid"] != "clean" {
		t.Fatalf("parsed: %v", got)
	}
}
