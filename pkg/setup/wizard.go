package setup

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"chicha-pulse/pkg/model"
	"chicha-pulse/pkg/nagiosimport"
)

// Package setup provides an interactive wizard so the first run is self-guided.

// ---- Data ----

type Settings struct {
	ImportNagiosPath string
	WebAddress       string
	TelegramToken    string
	TelegramChatID   string
	DatabaseDriver   string
	DatabaseDSN      string
}

type Summary struct {
	Hosts          int
	Services       int
	Notifications  int
	ConfigFileHint string
}

// ---- Wizard ----

// Run prompts for configuration details and returns settings for the main runtime.
func Run(ctx context.Context) (Settings, error) {
	reader := bufio.NewReader(os.Stdin)
	printBanner()

	settings := Settings{}
	defaultNagios := "/etc/nagios4/nagios.cfg"

	path := prompt(reader, fmt.Sprintf("Nagios config path [%s]: ", defaultNagios), defaultNagios)
	summary, err := summarizeNagios(ctx, path)
	if err != nil {
		return Settings{}, err
	}

	fmt.Printf("\nFound Nagios: %d hosts, %d services, %d notifications (from %s).\n", summary.Hosts, summary.Services, summary.Notifications, summary.ConfigFileHint)
	confirm := prompt(reader, "Import this configuration? [Y/n]: ", "Y")
	if strings.ToLower(confirm) == "n" {
		return Settings{}, fmt.Errorf("import cancelled by user")
	}

	settings.ImportNagiosPath = path
	settings.TelegramToken = prompt(reader, "Telegram bot token (leave empty to skip): ", "")
	if settings.TelegramToken != "" {
		settings.TelegramChatID = prompt(reader, "Telegram chat ID: ", "")
	}

	settings.WebAddress = prompt(reader, "Web port [4321]: ", "4321")
	settings.WebAddress = normalizeAddress(settings.WebAddress)

	allowIP := prompt(reader, "Lock web port to a single IP with iptables? (leave empty to skip): ", "")
	if allowIP != "" {
		if err := applyIptables(ctx, settings.WebAddress, allowIP); err != nil {
			return Settings{}, err
		}
	}

	settings.DatabaseDriver = prompt(reader, "Database driver [sqlite]: ", "sqlite")
	settings.DatabaseDriver = strings.ToLower(strings.TrimSpace(settings.DatabaseDriver))
	if settings.DatabaseDriver == "" {
		settings.DatabaseDriver = "sqlite"
	}
	if settings.DatabaseDriver == "postgres" {
		settings.DatabaseDSN = prompt(reader, "Postgres DSN: ", "")
	} else {
		settings.DatabaseDSN = defaultSQLitePath(settings.WebAddress)
		fmt.Printf("SQLite database path: %s\n", settings.DatabaseDSN)
	}

	return settings, nil
}

// ---- Prompt helpers ----

func prompt(reader *bufio.Reader, label, fallback string) string {
	fmt.Print(label)
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return fallback
	}
	return text
}

func normalizeAddress(port string) string {
	trimmed := strings.TrimSpace(port)
	if strings.HasPrefix(trimmed, ":") {
		return trimmed
	}
	return ":" + trimmed
}

func defaultSQLitePath(address string) string {
	port := strings.TrimPrefix(address, ":")
	path := filepath.Join("/var/lib/chicha-pulse", fmt.Sprintf("database-%s.sqlite", port))
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	return "file:" + path
}

func applyIptables(ctx context.Context, address, ip string) error {
	port, err := portFromAddress(address)
	if err != nil {
		return err
	}
	allow := exec.CommandContext(ctx, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", port, "-s", ip, "-j", "ACCEPT")
	if output, err := allow.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables allow failed: %s", strings.TrimSpace(string(output)))
	}
	deny := exec.CommandContext(ctx, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", port, "-j", "DROP")
	if output, err := deny.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables deny failed: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func portFromAddress(address string) (string, error) {
	trimmed := strings.TrimPrefix(address, ":")
	if trimmed == "" {
		return "", fmt.Errorf("invalid address: %s", address)
	}
	if _, err := strconv.Atoi(trimmed); err != nil {
		return "", fmt.Errorf("invalid port: %s", trimmed)
	}
	return trimmed, nil
}

func printBanner() {
	purple := "\033[35m"
	cyan := "\033[36m"
	reset := "\033[0m"
	fmt.Println(purple + "══════════════════════════════════════" + reset)
	fmt.Println(cyan + "   chicha-pulse interactive setup" + reset)
	fmt.Println(purple + "══════════════════════════════════════" + reset)
}

// ---- Nagios summary ----

func summarizeNagios(ctx context.Context, root string) (Summary, error) {
	files, err := nagiosimport.ResolveConfigFiles(ctx, root)
	if err != nil {
		return Summary{}, err
	}
	objects, errs := nagiosimport.StreamFiles(ctx, files)
	inventory := model.NewInventory()
	for objects != nil || errs != nil {
		select {
		case <-ctx.Done():
			return Summary{}, ctx.Err()
		case obj, ok := <-objects:
			if !ok {
				objects = nil
				continue
			}
			applyObject(&inventory, obj)
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			if err != nil {
				return Summary{}, err
			}
		}
	}

	return Summary{
		Hosts:          len(inventory.Hosts),
		Services:       countServices(inventory),
		Notifications:  countNotifications(inventory),
		ConfigFileHint: files[0],
	}, nil
}

func applyObject(inventory *model.Inventory, object nagiosimport.Object) {
	switch object.Kind {
	case nagiosimport.KindHost:
		inventory.Hosts[object.Host.Name] = &object.Host
	case nagiosimport.KindService:
		for _, hostName := range object.HostNames {
			host, ok := inventory.Hosts[hostName]
			if !ok {
				host = &model.Host{Name: hostName}
				inventory.Hosts[hostName] = host
			}
			service := object.Service
			service.HostName = hostName
			host.Services = append(host.Services, service)
		}
	}
}

func countServices(inventory model.Inventory) int {
	count := 0
	for _, host := range inventory.Hosts {
		count += len(host.Services)
	}
	return count
}

func countNotifications(inventory model.Inventory) int {
	count := 0
	for _, host := range inventory.Hosts {
		for _, service := range host.Services {
			if service.NotificationsEnabled || len(service.Contacts) > 0 {
				count++
			}
		}
	}
	return count
}
