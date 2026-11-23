package fleet

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
)

type cloudResponse[T any] struct {
	Servers     []T `json:"servers"`
	FloatingIPs []T `json:"floating_ips"`
	Meta        struct {
		Pagination struct {
			NextPage *int `json:"next_page"`
		} `json:"pagination"`
	} `json:"meta"`
}

type cloudServer struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Datacenter struct {
		Name string `json:"name"`
	} `json:"datacenter"`
	PublicNet struct {
		IPv4 *struct {
			IP string `json:"ip"`
		} `json:"ipv4"`
		IPv6 *struct {
			IP string `json:"ip"`
		} `json:"ipv6"`
	} `json:"public_net"`
	PrivateNet []struct {
		IP string `json:"ip"`
	} `json:"private_net"`
}

type floatingIP struct {
	IP     string `json:"ip"`
	Server *int64 `json:"server"`
}

func discoverHetznerCloud(ctx context.Context, cfg Config) ([]Host, error) {
	headers := http.Header{"Authorization": []string{"Bearer " + cfg.HetznerCloudToken}}
	base := strings.TrimRight(cfg.HetznerCloudURL, "/")
	byID := map[int64]*Host{}
	// Pagination meta is authoritative; Link headers are deprecated.
	for page := 1; page <= maxPages; page++ {
		var data cloudResponse[cloudServer]
		if err := getJSON(ctx, cfg.Client, fmt.Sprintf("%s/servers?page=%d&per_page=50", base, page), headers, "", "", &data); err != nil {
			return nil, err
		}
		for _, s := range data.Servers {
			if s.ID == 0 || s.Status == "deleting" {
				continue
			}
			h := &Host{Provider: "hetzner-cloud", ID: fmt.Sprint(s.ID), Name: s.Name, State: s.Status, Datacenter: s.Datacenter.Name}
			if s.PublicNet.IPv4 != nil {
				h.MainIP = s.PublicNet.IPv4.IP
				h.addIP(h.MainIP, "public")
			}
			if s.PublicNet.IPv6 != nil {
				h.addCloudIP(s.PublicNet.IPv6.IP, "public")
			}
			for _, ip := range s.PrivateNet {
				h.addIP(ip.IP, "local")
			}
			byID[s.ID] = h
		}
		if data.Meta.Pagination.NextPage == nil {
			break
		}
		if *data.Meta.Pagination.NextPage <= page {
			return nil, fmt.Errorf("cloud server pagination did not advance")
		}
		if page == maxPages {
			return nil, fmt.Errorf("cloud server pagination exceeded %d pages", maxPages)
		}
	}
	for page := 1; page <= maxPages; page++ {
		var data cloudResponse[floatingIP]
		if err := getJSON(ctx, cfg.Client, fmt.Sprintf("%s/floating_ips?page=%d&per_page=50", base, page), headers, "", "", &data); err != nil {
			return nil, err
		}
		for _, ip := range data.FloatingIPs {
			if ip.Server != nil {
				if h := byID[*ip.Server]; h != nil {
					h.addCloudIP(ip.IP, "public")
				}
			}
		}
		if data.Meta.Pagination.NextPage == nil {
			break
		}
		if *data.Meta.Pagination.NextPage <= page {
			return nil, fmt.Errorf("cloud floating IP pagination did not advance")
		}
		if page == maxPages {
			return nil, fmt.Errorf("cloud floating IP pagination exceeded %d pages", maxPages)
		}
	}
	hosts := make([]Host, 0, len(byID))
	for _, h := range byID {
		sort.Slice(h.Addresses, func(i, j int) bool { return h.Addresses[i].IP < h.Addresses[j].IP })
		sort.Strings(h.Subnets)
		hosts = append(hosts, *h)
	}
	return hosts, nil
}

func (h *Host) addCloudIP(ip, scope string) {
	if strings.Contains(ip, "/") {
		if _, n, err := net.ParseCIDR(ip); err == nil {
			h.addSubnet(n.String())
		}
		return
	}
	h.addIP(ip, scope)
}
