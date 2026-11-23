// fleet-inventory is a read-only one-shot inventory export for chicha-pulse.
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"chicha-pulse/pkg/fleet"
)

type report struct {
	CollectedAt time.Time      `json:"collected_at"`
	Hosts       []fleet.Result `json:"hosts"`
	Errors      []string       `json:"errors,omitempty"`
}

func main() {
	format := flag.String("format", "json", "Export format: json or csv")
	apiOnly := flag.Bool("api-only", false, "Do not SSH into hosts")
	user := flag.String("ssh-user", "root", "SSH username")
	key := flag.String("ssh-key", "", "SSH identity file (default: ssh-agent/config)")
	port := flag.Int("ssh-port", 22, "SSH port")
	workers := flag.Int("workers", 8, "Concurrent SSH probes (1-32)")
	timeout := flag.Duration("ssh-timeout", 25*time.Second, "Per-host SSH timeout")
	flag.Parse()
	if (*format != "json" && *format != "csv") || *port < 1 || *port > 65535 || *workers < 1 || *workers > 32 {
		fmt.Fprintln(os.Stderr, "invalid format, SSH port or workers")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hosts, problems := fleet.Discover(ctx, fleet.FromEnvironment())
	r := report{CollectedAt: time.Now().UTC(), Hosts: make([]fleet.Result, 0), Errors: problems}
	if *apiOnly {
		for _, h := range hosts {
			r.Hosts = append(r.Hosts, fleet.Result{Host: h})
		}
	} else {
		r.Hosts = fleet.Scan(ctx, hosts, fleet.SSHOptions{User: *user, KeyPath: *key, Port: *port, Workers: *workers, Timeout: *timeout})
	}
	var err error
	if *format == "csv" {
		err = writeCSV(r)
	} else {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(r)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, e := range r.Errors {
		fmt.Fprintln(os.Stderr, e)
	}
	if len(r.Errors) > 0 {
		os.Exit(1)
	}
}

func writeCSV(r report) error {
	w := csv.NewWriter(os.Stdout)
	if err := w.Write([]string{"provider", "id", "name", "state", "datacenter", "main_ip", "assigned_ips", "subnets", "ssh_error", "uname", "hostname", "uptime"}); err != nil {
		return err
	}
	for _, item := range r.Hosts {
		h := item.Host
		ips := make([]string, 0, len(h.Addresses))
		for _, address := range h.Addresses {
			ips = append(ips, address.IP+" ("+address.Scope+")")
		}
		record := []string{h.Provider, h.ID, h.Name, h.State, h.Datacenter, h.MainIP, strings.Join(ips, "; "), strings.Join(h.Subnets, "; "), item.SSH.Error, item.SSH.Sections["uname"], item.SSH.Sections["hostname"], item.SSH.Sections["uptime"]}
		if err := w.Write(record); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
