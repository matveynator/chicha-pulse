// Package fleet discovers dedicated servers at Hetzner Robot and Selectel.
// Provider requests are read-only; credentials come exclusively from the environment.
package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	robotURL    = "https://robot-ws.your-server.de"
	selectelURL = "https://api.selectel.ru/servers/v2"
	iamURL      = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"
	pageSize    = 100
	maxPages    = 1000
)

type Address struct {
	IP    string `json:"ip"`
	Scope string `json:"scope"` // public or local; provider view, not OS assignment
}

type Host struct {
	Provider   string    `json:"provider"`
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	State      string    `json:"state"`
	Datacenter string    `json:"datacenter,omitempty"`
	MainIP     string    `json:"main_ip,omitempty"`
	Addresses  []Address `json:"addresses,omitempty"`
	Subnets    []string  `json:"subnets,omitempty"`
	Warnings   []string  `json:"warnings,omitempty"`
}

type Config struct {
	HetznerUser       string
	HetznerPassword   string
	HetznerBaseURL    string
	HetznerCloudToken string
	HetznerCloudURL   string
	SelectelToken     string
	SelectelAccountID string
	SelectelUser      string
	SelectelPassword  string
	SelectelBaseURL   string
	SelectelIAMURL    string
	Client            *http.Client
}

func FromEnvironment() Config {
	return Config{
		HetznerUser: os.Getenv("HETZNER_ROBOT_USER"), HetznerPassword: os.Getenv("HETZNER_ROBOT_PASSWORD"),
		HetznerCloudToken: os.Getenv("HETZNER_CLOUD_TOKEN"),
		SelectelToken:     os.Getenv("SELECTEL_TOKEN"), SelectelAccountID: os.Getenv("SELECTEL_ACCOUNT_ID"),
		SelectelUser: os.Getenv("SELECTEL_USER"), SelectelPassword: os.Getenv("SELECTEL_PASSWORD"),
	}
}

// Discover returns successfully discovered hosts and provider errors separately;
// a provider failure never silently deletes the other provider's inventory.
func Discover(ctx context.Context, cfg Config) ([]Host, []string) {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 20 * time.Second}
	}
	if cfg.HetznerBaseURL == "" {
		cfg.HetznerBaseURL = robotURL
	}
	if cfg.HetznerCloudURL == "" {
		cfg.HetznerCloudURL = "https://api.hetzner.cloud/v1"
	}
	if cfg.SelectelBaseURL == "" {
		cfg.SelectelBaseURL = selectelURL
	}
	if cfg.SelectelIAMURL == "" {
		cfg.SelectelIAMURL = iamURL
	}
	var hosts []Host
	var problems []string
	enabled := false
	if cfg.HetznerUser != "" || cfg.HetznerPassword != "" {
		enabled = true
		if cfg.HetznerUser == "" || cfg.HetznerPassword == "" {
			problems = append(problems, "hetzner: both HETZNER_ROBOT_USER and HETZNER_ROBOT_PASSWORD are required")
		} else if found, err := discoverHetzner(ctx, cfg); err != nil {
			problems = append(problems, "hetzner: "+err.Error())
		} else {
			hosts = append(hosts, found...)
		}
	}
	if cfg.HetznerCloudToken != "" {
		enabled = true
		if found, err := discoverHetznerCloud(ctx, cfg); err != nil {
			problems = append(problems, "hetzner cloud: "+err.Error())
		} else {
			hosts = append(hosts, found...)
		}
	}
	if cfg.SelectelToken != "" || cfg.SelectelAccountID != "" || cfg.SelectelUser != "" || cfg.SelectelPassword != "" {
		enabled = true
		if found, err := discoverSelectel(ctx, cfg); err != nil {
			problems = append(problems, "selectel: "+err.Error())
		} else {
			hosts = append(hosts, found...)
		}
	}
	if !enabled {
		problems = append(problems, "no providers configured: set Hetzner Robot and/or Selectel credentials")
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Provider != hosts[j].Provider {
			return hosts[i].Provider < hosts[j].Provider
		}
		return hosts[i].ID < hosts[j].ID
	})
	return hosts, problems
}

func getJSON(ctx context.Context, client *http.Client, endpoint string, headers http.Header, basicUser, basicPassword string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	for k, values := range headers {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	if basicUser != "" {
		req.SetBasicAuth(basicUser, basicPassword)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

func discoverHetzner(ctx context.Context, cfg Config) ([]Host, error) {
	var payload []struct {
		Server struct {
			IP        string   `json:"server_ip"`
			IPv6Net   string   `json:"server_ipv6_net"`
			Number    int64    `json:"server_number"`
			Name      string   `json:"server_name"`
			DC        string   `json:"dc"`
			Status    string   `json:"status"`
			Cancelled bool     `json:"cancelled"`
			IPs       []string `json:"ip"`
			Subnets   []struct {
				IP   string `json:"ip"`
				Mask string `json:"mask"`
			} `json:"subnet"`
		} `json:"server"`
	}
	if err := getJSON(ctx, cfg.Client, strings.TrimRight(cfg.HetznerBaseURL, "/")+"/server", nil, cfg.HetznerUser, cfg.HetznerPassword, &payload); err != nil {
		return nil, err
	}
	hosts := make([]Host, 0, len(payload))
	for _, entry := range payload {
		s := entry.Server
		// Hetzner reports "ready" for provisioned machines; "in process" has no guaranteed SSH service.
		if s.Number == 0 || s.Status != "ready" {
			continue
		}
		h := Host{Provider: "hetzner", ID: strconv.FormatInt(s.Number, 10), Name: s.Name, State: s.Status, Datacenter: s.DC, MainIP: s.IP}
		if h.Name == "" {
			h.Name = "hetzner-" + h.ID
		}
		if s.Cancelled {
			h.Warnings = append(h.Warnings, "cancellation scheduled")
		}
		h.addIP(s.IP, "public")
		for _, ip := range s.IPs {
			h.addIP(ip, "public")
		}
		for _, subnet := range s.Subnets {
			if subnet.IP != "" && subnet.Mask != "" {
				h.Subnets = append(h.Subnets, subnet.IP+"/"+subnet.Mask)
			}
		}
		if s.IPv6Net != "" && len(h.Subnets) == 0 {
			h.Warnings = append(h.Warnings, "IPv6 network "+s.IPv6Net+" has no prefix length in API data")
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

type selectelResource struct {
	UUID         string `json:"uuid"`
	State        string `json:"state"`
	ServiceType  string `json:"service_type"`
	UserDesc     string `json:"user_desc"`
	ConfigName   string `json:"config_name"`
	LocationUUID string `json:"location_uuid"`
}
type selectelIP struct {
	IP           string `json:"ip"`
	ResourceUUID string `json:"resource_uuid"`
	Subnet       string `json:"subnet"`
}

type page[T any] struct {
	Result []T `json:"result"`
	Limit  int `json:"limit"`
	Page   int `json:"page"`
}

// collectPages terminates on an empty/short page, and caps traversal so an
// unexpected API response cannot trigger an unbounded request loop.
func collectPages[T any](ctx context.Context, cfg Config, path, token string) ([]T, error) {
	var all []T
	h := http.Header{"X-Auth-Token": []string{token}}
	for number := 1; number <= maxPages; number++ {
		endpoint := fmt.Sprintf("%s/%s?limit=%d&page=%d", strings.TrimRight(cfg.SelectelBaseURL, "/"), strings.TrimLeft(path, "/"), pageSize, number)
		var response page[T]
		if err := getJSON(ctx, cfg.Client, endpoint, h, "", "", &response); err != nil {
			return nil, err
		}
		all = append(all, response.Result...)
		limit := response.Limit
		if limit <= 0 || limit > pageSize {
			limit = pageSize
		}
		if len(response.Result) < limit {
			return all, nil
		}
	}
	return nil, fmt.Errorf("%s: exceeded %d API pages", path, maxPages)
}

func discoverSelectel(ctx context.Context, cfg Config) ([]Host, error) {
	token := cfg.SelectelToken
	if token == "" {
		if cfg.SelectelAccountID == "" || cfg.SelectelUser == "" || cfg.SelectelPassword == "" {
			return nil, errors.New("provide SELECTEL_TOKEN or SELECTEL_ACCOUNT_ID, SELECTEL_USER and SELECTEL_PASSWORD")
		}
		var err error
		token, err = fetchSelectelToken(ctx, cfg)
		if err != nil {
			return nil, err
		}
	}
	resources, err := collectPages[selectelResource](ctx, cfg, "resource", token)
	if err != nil {
		return nil, err
	}
	publicIPs, err := collectPages[selectelIP](ctx, cfg, "network/ipam/ip", token)
	if err != nil {
		return nil, err
	}
	localIPs, err := collectPages[selectelIP](ctx, cfg, "network/ipam/local_ip", token)
	if err != nil {
		return nil, err
	}
	byResource := make(map[string]*Host)
	for _, s := range resources {
		if s.UUID == "" || (s.ServiceType != "server" && s.ServiceType != "serverchip") || !activeSelectelState(s.State) {
			continue
		}
		name := strings.TrimSpace(s.UserDesc)
		if name == "" {
			name = s.ConfigName
		}
		if name == "" {
			name = "selectel-" + s.UUID
		}
		byResource[s.UUID] = &Host{Provider: "selectel", ID: s.UUID, Name: name, State: s.State, Datacenter: s.LocationUUID}
	}
	for _, ip := range publicIPs {
		if h := byResource[ip.ResourceUUID]; h != nil {
			h.addIP(ip.IP, "public")
			h.addSubnet(ip.Subnet)
		}
	}
	for _, ip := range localIPs {
		if h := byResource[ip.ResourceUUID]; h != nil {
			h.addIP(ip.IP, "local")
			h.addSubnet(ip.Subnet)
		}
	}
	hosts := make([]Host, 0, len(byResource))
	for id, h := range byResource {
		// The OS install address is a hint, not proof of the OS' current network configuration.
		endpoint := strings.TrimRight(cfg.SelectelBaseURL, "/") + "/boot/os/" + url.PathEscape(id)
		var boot struct {
			Result struct {
				IPv4 string `json:"ipv4_address"`
			} `json:"result"`
		}
		if err := getJSON(ctx, cfg.Client, endpoint, http.Header{"X-Auth-Token": []string{token}}, "", "", &boot); err == nil {
			if ip := net.ParseIP(boot.Result.IPv4); ip != nil {
				h.MainIP = ip.String()
				h.addIP(h.MainIP, "public")
			}
		} else {
			h.Warnings = append(h.Warnings, "OS install IP unavailable: "+err.Error())
		}
		if h.MainIP == "" {
			for _, ip := range h.Addresses {
				if ip.Scope == "public" && net.ParseIP(ip.IP).To4() != nil {
					h.MainIP = ip.IP
					break
				}
			}
		}
		if h.MainIP == "" {
			h.Warnings = append(h.Warnings, "no public IPv4 for SSH")
		}
		sort.Slice(h.Addresses, func(i, j int) bool { return h.Addresses[i].IP < h.Addresses[j].IP })
		sort.Strings(h.Subnets)
		hosts = append(hosts, *h)
	}
	return hosts, nil
}

func activeSelectelState(state string) bool {
	switch strings.ToLower(state) {
	case "dead", "deleted", "pending", "canceled", "cancelled", "expired", "inactive", "terminated", "released":
		return false
	default:
		return true // Keep unknown paid states visible rather than silently omitting assets.
	}
}

func fetchSelectelToken(ctx context.Context, cfg Config) (string, error) {
	reqBody := map[string]any{"auth": map[string]any{
		"identity": map[string]any{"methods": []string{"password"}, "password": map[string]any{"user": map[string]any{
			"name": cfg.SelectelUser, "domain": map[string]string{"name": cfg.SelectelAccountID}, "password": cfg.SelectelPassword}}},
		"scope": map[string]any{"domain": map[string]string{"name": cfg.SelectelAccountID}},
	}}
	encoded, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.SelectelIAMURL, bytes.NewReader(encoded))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cfg.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("IAM: HTTP %d", resp.StatusCode)
	}
	token := resp.Header.Get("X-Subject-Token")
	if token == "" {
		return "", errors.New("IAM did not return X-Subject-Token")
	}
	return token, nil
}

func (h *Host) addIP(value, scope string) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return
	}
	normalized := ip.String()
	for _, existing := range h.Addresses {
		if existing.IP == normalized && existing.Scope == scope {
			return
		}
	}
	h.Addresses = append(h.Addresses, Address{IP: normalized, Scope: scope})
}
func (h *Host) addSubnet(value string) {
	if value == "" {
		return
	}
	if _, _, err := net.ParseCIDR(value); err != nil {
		return
	}
	for _, s := range h.Subnets {
		if s == value {
			return
		}
	}
	h.Subnets = append(h.Subnets, value)
}
