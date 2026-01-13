package setup

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"chicha-pulse/pkg/model"
	"chicha-pulse/pkg/nagiosimport"
	"chicha-pulse/pkg/sshkeys"
)

// Package setup provides an interactive wizard so the first run is self-guided.

// ---- Data ----

type Settings struct {
	ImportNagiosPath string
	WebAddress       string
	WebAllowIPs      []string
	TelegramToken    string
	TelegramChatID   string
	DatabaseDriver   string
	DatabaseDSN      string
	DomainName       string
	SSLEmail         string
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

	stored, _ := LoadSettings()
	settings := stored

	printSectionTitle("Database", "Configure storage so setup can reuse existing values.")
	if strings.TrimSpace(settings.DatabaseDriver) == "" {
		response, err := prompt(ctx, reader, "Database driver [sqlite]: ", fallbackValue(stored.DatabaseDriver, "sqlite"))
		if err != nil {
			return Settings{}, err
		}
		settings.DatabaseDriver = strings.ToLower(strings.TrimSpace(response))
		if settings.DatabaseDriver == "" {
			settings.DatabaseDriver = "sqlite"
		}
	}
	defaultPort := fallbackValue(strings.TrimPrefix(stored.WebAddress, ":"), "4321")
	if strings.TrimSpace(settings.DatabaseDSN) == "" {
		if settings.DatabaseDriver == "postgres" {
			response, err := prompt(ctx, reader, fmt.Sprintf("Postgres DSN [%s]: ", stored.DatabaseDSN), stored.DatabaseDSN)
			if err != nil {
				return Settings{}, err
			}
			settings.DatabaseDSN = response
		} else {
			fallbackDSN := stored.DatabaseDSN
			if fallbackDSN == "" {
				fallbackDSN = defaultSQLitePath(":" + defaultPort)
			}
			response, err := prompt(ctx, reader, fmt.Sprintf("SQLite database path [%s]: ", fallbackDSN), fallbackDSN)
			if err != nil {
				return Settings{}, err
			}
			settings.DatabaseDSN = response
		}
	}
	if strings.TrimSpace(settings.DatabaseDSN) != "" {
		if storedFromDB, err := loadSettingsFromDB(settings.DatabaseDriver, settings.DatabaseDSN); err == nil {
			settings = mergeSettings(settings, storedFromDB)
		}
	}
	if settings.DatabaseDriver != "" && settings.DatabaseDSN != "" {
		if dbSummary, ok, err := loadImportSummaryFromDB(settings.DatabaseDriver, settings.DatabaseDSN); err == nil && ok {
			fmt.Printf("\nDatabase import summary: %d hosts, %d services, %d notifications (from %s).\n", dbSummary.Hosts, dbSummary.Services, dbSummary.Notifications, dbSummary.ConfigFileHint)
		}
	}
	printExistingSettings(settings)

	printSectionTitle("Nagios import", "Only new inventory is imported; existing items are kept.")
	defaultNagios := fallbackValue(settings.ImportNagiosPath, "/etc/nagios4/nagios.cfg")
	path := defaultNagios
	if strings.TrimSpace(settings.ImportNagiosPath) == "" {
		response, err := prompt(ctx, reader, fmt.Sprintf("Nagios config path [%s]: ", defaultNagios), defaultNagios)
		if err != nil {
			return Settings{}, err
		}
		path = response
	}
	summary, err := summarizeNagios(ctx, path)
	if err != nil {
		return Settings{}, err
	}

	fmt.Printf("\nFound Nagios: %d hosts, %d services, %d notifications (from %s).\n", summary.Hosts, summary.Services, summary.Notifications, summary.ConfigFileHint)
	previousSummary, hasPrevious, err := loadImportSummary()
	if err != nil {
		return Settings{}, err
	}
	if !hasPrevious {
		if dbSummary, ok, dbErr := loadImportSummaryFromDB(settings.DatabaseDriver, settings.DatabaseDSN); dbErr == nil && ok {
			previousSummary = dbSummary
			hasPrevious = true
		}
	}
	if hasPrevious {
		fmt.Printf("Previously imported: %d hosts, %d services, %d notifications (from %s).\n", previousSummary.Hosts, previousSummary.Services, previousSummary.Notifications, previousSummary.ConfigFileHint)
	}
	delta := buildImportDelta(summary, previousSummary, hasPrevious)
	confirm := "Y"
	if hasPrevious && delta.HasNoNew {
		fmt.Println("All services already imported.")
		confirm, err = prompt(ctx, reader, "No new inventory since last import. Skip import? [Y/n]: ", "Y")
		if err != nil {
			return Settings{}, err
		}
		if strings.ToLower(confirm) == "n" {
			confirm = "Y"
		} else {
			confirm = "SKIP"
		}
	} else if hasPrevious {
		confirm, err = prompt(ctx, reader, fmt.Sprintf("Import new inventory? (+%d hosts, +%d services, +%d notifications) [Y/n]: ", delta.AddedHosts, delta.AddedServices, delta.AddedNotifications), "Y")
		if err != nil {
			return Settings{}, err
		}
	} else {
		confirm, err = prompt(ctx, reader, "Import this configuration? [Y/n]: ", "Y")
		if err != nil {
			return Settings{}, err
		}
	}
	if strings.ToLower(confirm) == "n" {
		confirm = "SKIP"
	}
	if confirm != "SKIP" {
		if err := saveImportSummary(summary); err != nil {
			return Settings{}, err
		}
		if err := saveImportSummaryToDB(settings.DatabaseDriver, settings.DatabaseDSN, summary); err != nil {
			fmt.Fprintf(os.Stderr, "setup db import summary save failed: %v\n", err)
		}
	}

	settings.ImportNagiosPath = path

	printSectionTitle("Notifications", "Optional alerts via Telegram.")
	if strings.TrimSpace(settings.TelegramToken) == "" {
		response, err := prompt(ctx, reader, "Telegram bot token (leave empty to skip): ", settings.TelegramToken)
		if err != nil {
			return Settings{}, err
		}
		settings.TelegramToken = response
	}
	if settings.TelegramToken != "" && strings.TrimSpace(settings.TelegramChatID) == "" {
		response, err := prompt(ctx, reader, "Telegram chat ID: ", settings.TelegramChatID)
		if err != nil {
			return Settings{}, err
		}
		settings.TelegramChatID = response
	}

	printSectionTitle("Web", "Configure the HTTP interface and access rules.")
	if strings.TrimSpace(settings.WebAddress) == "" {
		response, err := prompt(ctx, reader, fmt.Sprintf("Web port [%s]: ", defaultPort), defaultPort)
		if err != nil {
			return Settings{}, err
		}
		settings.WebAddress = normalizeAddress(response)
	}

	if len(settings.WebAllowIPs) == 0 {
		allowIP, err := prompt(ctx, reader, "Allowed IPs for web access (comma or space separated, leave empty to skip): ", "")
		if err != nil {
			return Settings{}, err
		}
		settings.WebAllowIPs = parseCSVList(allowIP)
	}
	if len(settings.WebAllowIPs) > 0 {
		if err := applyIptables(ctx, settings.WebAddress, settings.WebAllowIPs); err != nil {
			return Settings{}, err
		}
	}

	if settings.DatabaseDriver == "sqlite" && strings.TrimSpace(settings.DatabaseDSN) == "" {
		settings.DatabaseDSN = defaultSQLitePath(settings.WebAddress)
		fmt.Printf("SQLite database path: %s\n", settings.DatabaseDSN)
	}

	printSectionTitle("TLS", "Optional HTTPS with automatic Let's Encrypt certificates.")
	if strings.TrimSpace(settings.DomainName) == "" {
		response, err := prompt(ctx, reader, "Domain for HTTPS certificates (leave empty to skip): ", "")
		if err != nil {
			return Settings{}, err
		}
		settings.DomainName = strings.TrimSpace(response)
	}
	if settings.DomainName != "" && strings.TrimSpace(settings.SSLEmail) == "" {
		response, err := prompt(ctx, reader, "Email for Let's Encrypt alerts: ", settings.SSLEmail)
		if err != nil {
			return Settings{}, err
		}
		settings.SSLEmail = strings.TrimSpace(response)
	}
	if settings.DomainName != "" {
		if err := ensureLetsEncrypt(ctx, settings.DomainName, settings.SSLEmail); err != nil {
			return Settings{}, err
		}
		if strings.TrimSpace(settings.WebAddress) == "" || settings.WebAddress == ":80" {
			settings.WebAddress = ":443"
		}
	}

	if err := configureSSHKeys(ctx, reader, settings); err != nil {
		return Settings{}, err
	}

	if settings.TelegramToken != "" && settings.TelegramChatID != "" {
		if err := sendTelegramTest(ctx, settings); err != nil {
			return Settings{}, err
		}
	}

	printAccessSummary(settings)

	if err := saveSettings(settings); err != nil {
		return Settings{}, err
	}

	return settings, nil
}

// ---- Prompt helpers ----

func prompt(ctx context.Context, reader *bufio.Reader, label, fallback string) (string, error) {
	// Keep prompts cancellable so Ctrl+C stops setup cleanly.
	fmt.Print(label)
	text, err := reader.ReadString('\n')
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", err
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return fallback, nil
	}
	return text, nil
}

func fallbackValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func normalizeAddress(port string) string {
	trimmed := strings.TrimSpace(port)
	if strings.HasPrefix(trimmed, ":") {
		return trimmed
	}
	return ":" + trimmed
}

func defaultSQLitePath(address string) string {
	path := filepath.Join("/var/lib/chicha-pulse", "database.sqlite")
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	return "file:" + path
}

func applyIptables(ctx context.Context, address string, allowIPs []string) error {
	// Apply allow-list rules first, then drop everything else on the web port.
	port, err := portFromAddress(address)
	if err != nil {
		return err
	}
	for _, ip := range allowIPs {
		if strings.TrimSpace(ip) == "" {
			continue
		}
		if err := addIptablesRule(ctx, port, ip, "ACCEPT"); err != nil {
			return err
		}
	}
	return addIptablesRule(ctx, port, "", "DROP")
}

func EnsureIptables(ctx context.Context, address string, allowIPs []string) error {
	// Re-apply allow-list rules on restart so the port stays protected.
	port, err := portFromAddress(address)
	if err != nil {
		return err
	}
	for _, ip := range allowIPs {
		clean := strings.TrimSpace(ip)
		if clean == "" {
			continue
		}
		if !iptablesRuleExists(ctx, port, clean, "ACCEPT") {
			if err := addIptablesRule(ctx, port, clean, "ACCEPT"); err != nil {
				return err
			}
		}
	}
	if len(allowIPs) > 0 && !iptablesRuleExists(ctx, port, "", "DROP") {
		if err := addIptablesRule(ctx, port, "", "DROP"); err != nil {
			return err
		}
	}
	return nil
}

func iptablesRuleExists(ctx context.Context, port string, ip string, action string) bool {
	// Query iptables before adding to avoid duplicate rules.
	args := []string{"-C", "INPUT", "-p", "tcp", "--dport", port}
	if ip != "" {
		args = append(args, "-s", ip)
	}
	args = append(args, "-j", action)
	cmd := exec.CommandContext(ctx, "iptables", args...)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func addIptablesRule(ctx context.Context, port string, ip string, action string) error {
	// Add a specific iptables rule with clear error reporting.
	args := []string{"-A", "INPUT", "-p", "tcp", "--dport", port}
	if ip != "" {
		args = append(args, "-s", ip)
	}
	args = append(args, "-j", action)
	cmd := exec.CommandContext(ctx, "iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables %s failed: %s", strings.ToLower(action), strings.TrimSpace(string(output)))
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

func printSectionTitle(title string, hint string) {
	// Use color to separate wizard sections for clarity.
	cyan := "\033[36m"
	green := "\033[32m"
	reset := "\033[0m"
	fmt.Printf("\n%s[%s]%s %s\n", cyan, title, reset, hint)
	fmt.Printf("%s──────────────────────────────────────%s\n", green, reset)
}

func printExistingSettings(settings Settings) {
	// Show current settings so operators can keep what already works.
	fmt.Println("\nCurrent settings (press Enter to keep defaults):")
	if settings.ImportNagiosPath != "" {
		fmt.Printf("- Nagios config: %s\n", settings.ImportNagiosPath)
	}
	if settings.WebAddress != "" {
		fmt.Printf("- Web address: %s\n", settings.WebAddress)
	}
	if len(settings.WebAllowIPs) > 0 {
		fmt.Printf("- Web allow IPs: %s\n", strings.Join(settings.WebAllowIPs, ", "))
	}
	if settings.TelegramToken != "" {
		fmt.Printf("- Telegram token: %s\n", redactToken(settings.TelegramToken))
	}
	if settings.TelegramChatID != "" {
		fmt.Printf("- Telegram chat ID: %s\n", settings.TelegramChatID)
	}
	if settings.DatabaseDriver != "" {
		fmt.Printf("- Database driver: %s\n", settings.DatabaseDriver)
	}
	if settings.DatabaseDSN != "" {
		fmt.Printf("- Database DSN: %s\n", redactDSN(settings.DatabaseDSN))
	}
	if settings.DomainName != "" {
		fmt.Printf("- TLS domain: %s\n", settings.DomainName)
	}
}

func redactToken(token string) string {
	// Hide most of the token to avoid leaking secrets in the setup output.
	trimmed := strings.TrimSpace(token)
	if len(trimmed) <= 6 {
		return "***"
	}
	return trimmed[:3] + "***" + trimmed[len(trimmed)-3:]
}

type importDelta struct {
	AddedHosts         int
	AddedServices      int
	AddedNotifications int
	HasNoNew           bool
}

func parseCSVList(input string) []string {
	// Split on commas and whitespace so admins can paste lists quickly.
	fields := strings.FieldsFunc(input, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	})
	var values []string
	for _, field := range fields {
		clean := strings.TrimSpace(field)
		if clean != "" {
			values = append(values, clean)
		}
	}
	return values
}

// ---- SSH key setup ----

func configureSSHKeys(ctx context.Context, reader *bufio.Reader, settings Settings) error {
	if err := sshkeys.EnsureKeyring(ctx, settings.DatabaseDriver, settings.DatabaseDSN); err != nil {
		return err
	}
	if strings.TrimSpace(settings.DatabaseDriver) == "" || strings.TrimSpace(settings.DatabaseDSN) == "" {
		fmt.Println("SSH key setup skipped: database not configured.")
		return nil
	}
	if records, err := sshkeys.LoadKeyringFromSettings(ctx); err == nil && len(records) > 0 {
		fmt.Println("SSH key setup skipped: existing keys found.")
		return nil
	}
	if err := tightenSQLitePermissions(settings.DatabaseDriver, settings.DatabaseDSN); err != nil {
		fmt.Fprintf(os.Stderr, "setup: sqlite permissions warning: %v\n", err)
	}

	fmt.Println("\nSSH key setup (up to 3 keys):")
	for index := 1; index <= 3; index++ {
		choice, err := prompt(ctx, reader, fmt.Sprintf("Key %d: enter private key path, 'g' to generate, 'p' to paste, or leave empty to skip: ", index), "")
		if err != nil {
			return err
		}
		if strings.TrimSpace(choice) == "" {
			return nil
		}
		keyPath := strings.TrimSpace(choice)
		if strings.EqualFold(keyPath, "g") {
			generated, passphrase, publicKey, err := generateSSHKey()
			if err != nil {
				return err
			}
			fmt.Printf("Generated SSH key: %s\n", generated)
			fmt.Printf("Public key:\n%s\n", publicKey)
			if err := saveSSHKey(ctx, settings, generated, passphrase, publicKey); err != nil {
				return err
			}
		} else if strings.EqualFold(keyPath, "p") {
			passphrase, err := promptPassphrase(ctx, reader, "Passphrase for this key (leave empty to keep none, or type 'g' to generate): ")
			if err != nil {
				return err
			}
			if strings.EqualFold(passphrase, "g") {
				generatedPassphrase, err := randomPassphrase()
				if err != nil {
					return err
				}
				passphrase = generatedPassphrase
				fmt.Printf("Generated passphrase: %s\n", passphrase)
			}
			label, privateKey, err := promptPrivateKeyPaste(ctx, reader)
			if err != nil {
				return err
			}
			publicKey, err := derivePublicKey(ctx, privateKey)
			if err != nil {
				return err
			}
			fmt.Printf("Public key:\n%s\n", publicKey)
			if err := saveSSHKeyData(ctx, settings, label, privateKey, passphrase, publicKey); err != nil {
				return err
			}
		} else {
			passphrase, err := promptPassphrase(ctx, reader, "Passphrase for this key (leave empty to keep none, or type 'g' to generate): ")
			if err != nil {
				return err
			}
			if strings.EqualFold(passphrase, "g") {
				generatedPassphrase, err := randomPassphrase()
				if err != nil {
					return err
				}
				passphrase = generatedPassphrase
				fmt.Printf("Generated passphrase: %s\n", passphrase)
			}
			publicKey, err := readPublicKey(ctx, keyPath)
			if err != nil {
				return err
			}
			fmt.Printf("Public key:\n%s\n", publicKey)
			if err := saveSSHKey(ctx, settings, keyPath, passphrase, publicKey); err != nil {
				return err
			}
		}
		next, err := prompt(ctx, reader, "Add another SSH key? [y/N]: ", "N")
		if err != nil {
			return err
		}
		if strings.ToLower(next) != "y" {
			return nil
		}
	}
	return nil
}

func saveSSHKey(ctx context.Context, settings Settings, path, passphrase, publicKey string) error {
	privateKey, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	label := filepath.Base(path)
	return sshkeys.SaveKey(ctx, settings.DatabaseDriver, settings.DatabaseDSN, label, publicKey, privateKey, []byte(passphrase))
}

func saveSSHKeyData(ctx context.Context, settings Settings, label string, privateKey []byte, passphrase, publicKey string) error {
	// Save pasted keys with a label so the keyring can reference the source later.
	cleanLabel := strings.TrimSpace(label)
	if cleanLabel == "" {
		cleanLabel = fmt.Sprintf("pasted-%d", time.Now().Unix())
	}
	return sshkeys.SaveKey(ctx, settings.DatabaseDriver, settings.DatabaseDSN, cleanLabel, publicKey, privateKey, []byte(passphrase))
}

func generateSSHKey() (string, string, string, error) {
	passphrase, err := randomPassphrase()
	if err != nil {
		return "", "", "", err
	}
	dir := "/var/lib/chicha-pulse/ssh"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("id_ed25519_%d", time.Now().UnixNano()))
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-a", "64", "-f", path, "-N", passphrase)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", "", "", fmt.Errorf("ssh-keygen failed: %s", strings.TrimSpace(string(output)))
	}
	publicKeyBytes, err := os.ReadFile(path + ".pub")
	if err != nil {
		return "", "", "", err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return "", "", "", err
	}
	return path, passphrase, strings.TrimSpace(string(publicKeyBytes)), nil
}

func readPublicKey(ctx context.Context, path string) (string, error) {
	pubPath := path + ".pub"
	if data, err := os.ReadFile(pubPath); err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	cmd := exec.CommandContext(ctx, "ssh-keygen", "-y", "-f", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ssh-keygen -y failed: %s", strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func derivePublicKey(ctx context.Context, privateKey []byte) (string, error) {
	// Write pasted keys to a temp file so ssh-keygen can derive the public key.
	dir := "/var/lib/chicha-pulse/ssh"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("pasted_%d", time.Now().UnixNano()))
	if err := os.WriteFile(path, privateKey, 0o600); err != nil {
		return "", err
	}
	defer os.Remove(path)
	return readPublicKey(ctx, path)
}

func promptPrivateKeyPaste(ctx context.Context, reader *bufio.Reader) (string, []byte, error) {
	// Accept multi-line pasted keys so operators can avoid storing files ahead of time.
	fmt.Println("Paste private key contents, then finish with a single line containing END:")
	label, err := prompt(ctx, reader, "Label for this key (optional): ", "")
	if err != nil {
		return "", nil, err
	}
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if ctx.Err() != nil {
				return "", nil, ctx.Err()
			}
			return "", nil, err
		}
		text := strings.TrimRight(line, "\r\n")
		if strings.TrimSpace(text) == "END" {
			break
		}
		lines = append(lines, text)
	}
	if len(lines) == 0 {
		return "", nil, fmt.Errorf("no key data provided")
	}
	return label, []byte(strings.Join(lines, "\n") + "\n"), nil
}

func promptPassphrase(ctx context.Context, reader *bufio.Reader, label string) (string, error) {
	// Read passphrases with cancellation support.
	fmt.Print(label)
	text, err := reader.ReadString('\n')
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", err
	}
	return strings.TrimSpace(text), nil
}

func randomPassphrase() (string, error) {
	// Use random bytes to make the passphrase hard to guess while still printable.
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 24
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = letters[int(buf[i])%len(letters)]
	}
	return string(buf), nil
}

func tightenSQLitePermissions(driverName, dsn string) error {
	if driverName != "sqlite" {
		return nil
	}
	path := strings.TrimPrefix(dsn, "file:")
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode().Perm() != 0o600 {
		return os.Chmod(path, 0o600)
	}
	return nil
}

// ---- Settings persistence ----

func settingsPath() string {
	return "/var/lib/chicha-pulse/settings.conf"
}

func importSummaryPath() string {
	// Keep import metadata alongside settings for easy inspection.
	return "/var/lib/chicha-pulse/import_summary.json"
}

func loadSettings() (Settings, error) {
	data, err := os.ReadFile(settingsPath())
	if err != nil {
		return Settings{}, err
	}
	parsed := parseKeyValues(string(data))
	return Settings{
		ImportNagiosPath: parsed["import_nagios"],
		WebAddress:       parsed["web_addr"],
		WebAllowIPs:      parseCSVList(parsed["web_allow_ips"]),
		TelegramToken:    parsed["telegram_token"],
		TelegramChatID:   parsed["telegram_chat_id"],
		DatabaseDriver:   parsed["db_driver"],
		DatabaseDSN:      parsed["db_dsn"],
		DomainName:       parsed["domain_name"],
		SSLEmail:         parsed["ssl_email"],
	}, nil
}

// LoadSettings exposes stored settings so non-interactive runs can reuse the last setup.
func LoadSettings() (Settings, error) {
	fileSettings, err := loadSettings()
	if err != nil {
		return Settings{}, err
	}
	if fileSettings.DatabaseDriver != "" && fileSettings.DatabaseDSN != "" {
		if stored, dbErr := loadSettingsFromDB(fileSettings.DatabaseDriver, fileSettings.DatabaseDSN); dbErr == nil {
			return mergeSettings(fileSettings, stored), nil
		}
	}
	return fileSettings, nil
}

func saveSettings(settings Settings) error {
	path := settingsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	content := strings.Join([]string{
		"import_nagios=" + settings.ImportNagiosPath,
		"web_addr=" + settings.WebAddress,
		"web_allow_ips=" + strings.Join(settings.WebAllowIPs, ","),
		"telegram_token=" + settings.TelegramToken,
		"telegram_chat_id=" + settings.TelegramChatID,
		"db_driver=" + settings.DatabaseDriver,
		"db_dsn=" + settings.DatabaseDSN,
		"domain_name=" + settings.DomainName,
		"ssl_email=" + settings.SSLEmail,
	}, "\n")
	if err := saveSettingsToDB(settings); err != nil {
		fmt.Fprintf(os.Stderr, "setup db save failed: %v\n", err)
	}
	return os.WriteFile(path, []byte(content+"\n"), 0o600)
}

func parseKeyValues(content string) map[string]string {
	values := make(map[string]string)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			continue
		}
		values[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return values
}

func mergeSettings(base, override Settings) Settings {
	merged := base
	if strings.TrimSpace(override.ImportNagiosPath) != "" {
		merged.ImportNagiosPath = override.ImportNagiosPath
	}
	if strings.TrimSpace(override.WebAddress) != "" {
		merged.WebAddress = override.WebAddress
	}
	if len(override.WebAllowIPs) > 0 {
		merged.WebAllowIPs = append([]string(nil), override.WebAllowIPs...)
	}
	if strings.TrimSpace(override.TelegramToken) != "" {
		merged.TelegramToken = override.TelegramToken
	}
	if strings.TrimSpace(override.TelegramChatID) != "" {
		merged.TelegramChatID = override.TelegramChatID
	}
	if strings.TrimSpace(override.DatabaseDriver) != "" {
		merged.DatabaseDriver = override.DatabaseDriver
	}
	if strings.TrimSpace(override.DatabaseDSN) != "" {
		merged.DatabaseDSN = override.DatabaseDSN
	}
	if strings.TrimSpace(override.DomainName) != "" {
		merged.DomainName = override.DomainName
	}
	if strings.TrimSpace(override.SSLEmail) != "" {
		merged.SSLEmail = override.SSLEmail
	}
	return merged
}

func loadImportSummary() (Summary, bool, error) {
	// Load the last import summary so setup can detect new inventory.
	data, err := os.ReadFile(importSummaryPath())
	if err != nil {
		if os.IsNotExist(err) {
			return Summary{}, false, nil
		}
		return Summary{}, false, err
	}
	var summary Summary
	if err := json.Unmarshal(data, &summary); err != nil {
		return Summary{}, false, err
	}
	return summary, true, nil
}

func saveImportSummary(summary Summary) error {
	// Persist the summary so later runs can compute deltas.
	if err := os.MkdirAll(filepath.Dir(importSummaryPath()), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(importSummaryPath(), data, 0o600)
}

func loadImportSummaryFromDB(driverName, dsn string) (Summary, bool, error) {
	// Read the last import summary from the database for quick stats.
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return Summary{}, false, err
	}
	defer db.Close()
	statement := `SELECT hosts, services, notifications, config_path
FROM setup_import_summary ORDER BY created_at DESC LIMIT 1`
	row := db.QueryRow(statement)
	var summary Summary
	if err := row.Scan(&summary.Hosts, &summary.Services, &summary.Notifications, &summary.ConfigFileHint); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Summary{}, false, nil
		}
		return Summary{}, false, err
	}
	return summary, true, nil
}

func saveImportSummaryToDB(driverName, dsn string, summary Summary) error {
	// Keep the last import summary in the database for future setup runs.
	if driverName == "" || dsn == "" {
		return nil
	}
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	schema := `CREATE TABLE IF NOT EXISTS setup_import_summary (
id TEXT,
hosts INTEGER,
services INTEGER,
notifications INTEGER,
config_path TEXT,
created_at TEXT
)`
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	statement := fmt.Sprintf(`INSERT INTO setup_import_summary (
id, hosts, services, notifications, config_path, created_at
) VALUES (%s, %s, %s, %s, %s, %s)`,
		placeholder(driverName, 1),
		placeholder(driverName, 2),
		placeholder(driverName, 3),
		placeholder(driverName, 4),
		placeholder(driverName, 5),
		placeholder(driverName, 6),
	)
	_, err = db.Exec(statement,
		fmt.Sprintf("%d", time.Now().UnixNano()),
		summary.Hosts,
		summary.Services,
		summary.Notifications,
		summary.ConfigFileHint,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

func buildImportDelta(current Summary, previous Summary, hasPrevious bool) importDelta {
	// Track added inventory so setup can avoid unnecessary re-import prompts.
	if !hasPrevious || previous.ConfigFileHint != current.ConfigFileHint {
		return importDelta{
			AddedHosts:         current.Hosts,
			AddedServices:      current.Services,
			AddedNotifications: current.Notifications,
			HasNoNew:           false,
		}
	}
	addedHosts := current.Hosts - previous.Hosts
	if addedHosts < 0 {
		addedHosts = 0
	}
	addedServices := current.Services - previous.Services
	if addedServices < 0 {
		addedServices = 0
	}
	addedNotifications := current.Notifications - previous.Notifications
	if addedNotifications < 0 {
		addedNotifications = 0
	}
	return importDelta{
		AddedHosts:         addedHosts,
		AddedServices:      addedServices,
		AddedNotifications: addedNotifications,
		HasNoNew:           addedHosts == 0 && addedServices == 0 && addedNotifications == 0,
	}
}

func loadSettingsFromDB(driverName, dsn string) (Settings, error) {
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return Settings{}, err
	}
	defer db.Close()

	statement := `SELECT import_nagios, web_addr, web_allow_ips, telegram_token, telegram_chat_id, db_driver, db_dsn, domain_name, ssl_email
FROM setup_settings ORDER BY updated_at DESC LIMIT 1`
	row := db.QueryRow(statement)
	settings := Settings{}
	var allowIPs string
	if err := row.Scan(
		&settings.ImportNagiosPath,
		&settings.WebAddress,
		&allowIPs,
		&settings.TelegramToken,
		&settings.TelegramChatID,
		&settings.DatabaseDriver,
		&settings.DatabaseDSN,
		&settings.DomainName,
		&settings.SSLEmail,
	); err != nil {
		return Settings{}, err
	}
	settings.WebAllowIPs = parseCSVList(allowIPs)
	return settings, nil
}

func saveSettingsToDB(settings Settings) error {
	if settings.DatabaseDriver == "" || settings.DatabaseDSN == "" {
		return nil
	}
	db, err := sql.Open(settings.DatabaseDriver, settings.DatabaseDSN)
	if err != nil {
		return err
	}
	defer db.Close()

	schema := `CREATE TABLE IF NOT EXISTS setup_settings (
id TEXT,
import_nagios TEXT,
web_addr TEXT,
web_allow_ips TEXT,
telegram_token TEXT,
telegram_chat_id TEXT,
db_driver TEXT,
db_dsn TEXT,
domain_name TEXT,
ssl_email TEXT,
updated_at TEXT
)`
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	statement := fmt.Sprintf(`INSERT INTO setup_settings (
id, import_nagios, web_addr, web_allow_ips, telegram_token, telegram_chat_id, db_driver, db_dsn, domain_name, ssl_email, updated_at
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		placeholder(settings.DatabaseDriver, 1),
		placeholder(settings.DatabaseDriver, 2),
		placeholder(settings.DatabaseDriver, 3),
		placeholder(settings.DatabaseDriver, 4),
		placeholder(settings.DatabaseDriver, 5),
		placeholder(settings.DatabaseDriver, 6),
		placeholder(settings.DatabaseDriver, 7),
		placeholder(settings.DatabaseDriver, 8),
		placeholder(settings.DatabaseDriver, 9),
		placeholder(settings.DatabaseDriver, 10),
		placeholder(settings.DatabaseDriver, 11),
	)
	_, err = db.Exec(statement,
		fmt.Sprintf("%d", time.Now().UnixNano()),
		settings.ImportNagiosPath,
		settings.WebAddress,
		strings.Join(settings.WebAllowIPs, ","),
		settings.TelegramToken,
		settings.TelegramChatID,
		settings.DatabaseDriver,
		settings.DatabaseDSN,
		settings.DomainName,
		settings.SSLEmail,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

func placeholder(driverName string, index int) string {
	if driverName == "postgres" {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func sendTelegramTest(ctx context.Context, settings Settings) error {
	message := buildSetupMessage(settings)
	payload := map[string]string{
		"chat_id": settings.TelegramChatID,
		"text":    message,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, telegramEndpoint(settings.TelegramToken), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("telegram test failed: %s", response.Status)
	}
	return nil
}

func ensureLetsEncrypt(ctx context.Context, domain string, email string) error {
	// Use certbot so HTTPS certificates are issued and auto-renewed by the system.
	if strings.TrimSpace(domain) == "" {
		return nil
	}
	if strings.TrimSpace(email) == "" {
		return fmt.Errorf("ssl email is required for Let's Encrypt")
	}
	args := []string{
		"certonly",
		"--standalone",
		"--non-interactive",
		"--agree-tos",
		"-m", email,
		"-d", domain,
	}
	cmd := exec.CommandContext(ctx, "certbot", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("certbot failed: %s", strings.TrimSpace(string(output)))
	}
	if err := ensureRenewCron(); err != nil {
		return err
	}
	return nil
}

func ensureRenewCron() error {
	// Write a cron job so certbot renew runs automatically.
	cronPath := "/etc/cron.d/chicha-pulse-renew"
	content := "0 3 * * * root certbot renew --quiet\n"
	return os.WriteFile(cronPath, []byte(content), 0o644)
}

func telegramEndpoint(token string) string {
	return fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
}

func buildSetupMessage(settings Settings) string {
	lines := []string{
		"✅ chicha-pulse setup completed",
		fmt.Sprintf("Nagios: %s", settings.ImportNagiosPath),
		fmt.Sprintf("Web: %s", settings.WebAddress),
		fmt.Sprintf("Database: %s (%s)", settings.DatabaseDriver, redactDSN(settings.DatabaseDSN)),
	}
	if len(settings.WebAllowIPs) > 0 {
		lines = append(lines, fmt.Sprintf("Web access: locked to %s via iptables", strings.Join(settings.WebAllowIPs, ", ")))
	} else {
		lines = append(lines, "Web access: open (no iptables lock)")
	}
	if settings.DomainName != "" {
		lines = append(lines, fmt.Sprintf("TLS domain: %s", settings.DomainName))
	}
	ips := listLocalIPs()
	if len(ips) > 0 {
		lines = append(lines, fmt.Sprintf("Local IPs: %s", strings.Join(ips, ", ")))
	}
	return strings.Join(lines, "\n")
}

func redactDSN(dsn string) string {
	if dsn == "" {
		return ""
	}
	if strings.Contains(dsn, "://") {
		parts := strings.SplitN(dsn, "://", 2)
		return parts[0] + "://***"
	}
	if strings.Contains(dsn, "password=") {
		return "***"
	}
	return dsn
}

func listLocalIPs() []string {
	var ips []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := extractIP(addr)
			if ip != "" {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

func extractIP(addr net.Addr) string {
	switch value := addr.(type) {
	case *net.IPNet:
		if ip := value.IP.To4(); ip != nil {
			return ip.String()
		}
	case *net.IPAddr:
		if ip := value.IP.To4(); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func printAccessSummary(settings Settings) {
	fmt.Println("\nAccess summary:")
	fmt.Printf("- Web address: %s\n", settings.WebAddress)
	if len(settings.WebAllowIPs) > 0 {
		fmt.Printf("- Web access locked to: %s\n", strings.Join(settings.WebAllowIPs, ", "))
	} else {
		fmt.Println("- Web access: open (no iptables lock)")
	}
	ips := listLocalIPs()
	if len(ips) > 0 {
		fmt.Printf("- Local IPs: %s\n", strings.Join(ips, ", "))
	}
	if settings.DomainName != "" {
		fmt.Printf("- TLS domain: %s\n", settings.DomainName)
	}
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
