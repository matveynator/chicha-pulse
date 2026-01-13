package setup

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
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
	WebAllowIP       string
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

	stored, _ := LoadSettings()
	settings := stored
	defaultNagios := fallbackValue(stored.ImportNagiosPath, "/etc/nagios4/nagios.cfg")

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
	settings.TelegramToken = prompt(reader, "Telegram bot token (leave empty to skip): ", stored.TelegramToken)
	if settings.TelegramToken != "" {
		settings.TelegramChatID = prompt(reader, "Telegram chat ID: ", stored.TelegramChatID)
	}

	defaultPort := fallbackValue(strings.TrimPrefix(stored.WebAddress, ":"), "4321")
	settings.WebAddress = prompt(reader, fmt.Sprintf("Web port [%s]: ", defaultPort), defaultPort)
	settings.WebAddress = normalizeAddress(settings.WebAddress)

	allowIP := prompt(reader, "Lock web port to a single IP with iptables? (leave empty to skip): ", stored.WebAllowIP)
	if allowIP != "" {
		if err := applyIptables(ctx, settings.WebAddress, allowIP); err != nil {
			return Settings{}, err
		}
	}
	settings.WebAllowIP = allowIP

	settings.DatabaseDriver = prompt(reader, "Database driver [sqlite]: ", fallbackValue(stored.DatabaseDriver, "sqlite"))
	settings.DatabaseDriver = strings.ToLower(strings.TrimSpace(settings.DatabaseDriver))
	if settings.DatabaseDriver == "" {
		settings.DatabaseDriver = "sqlite"
	}
	if settings.DatabaseDriver == "postgres" {
		settings.DatabaseDSN = prompt(reader, "Postgres DSN: ", stored.DatabaseDSN)
	} else {
		settings.DatabaseDSN = defaultSQLitePath(settings.WebAddress)
		fmt.Printf("SQLite database path: %s\n", settings.DatabaseDSN)
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

func prompt(reader *bufio.Reader, label, fallback string) string {
	fmt.Print(label)
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return fallback
	}
	return text
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

// ---- SSH key setup ----

func configureSSHKeys(ctx context.Context, reader *bufio.Reader, settings Settings) error {
	if err := sshkeys.EnsureKeyring(ctx, settings.DatabaseDriver, settings.DatabaseDSN); err != nil {
		return err
	}
	if strings.TrimSpace(settings.DatabaseDriver) == "" || strings.TrimSpace(settings.DatabaseDSN) == "" {
		fmt.Println("SSH key setup skipped: database not configured.")
		return nil
	}
	if err := tightenSQLitePermissions(settings.DatabaseDriver, settings.DatabaseDSN); err != nil {
		fmt.Fprintf(os.Stderr, "setup: sqlite permissions warning: %v\n", err)
	}

	fmt.Println("\nSSH key setup (up to 3 keys):")
	for index := 1; index <= 3; index++ {
		choice := prompt(reader, fmt.Sprintf("Key %d: enter private key path, 'g' to generate, 'p' to paste, or leave empty to skip: ", index), "")
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
			passphrase := promptPassphrase(reader, "Passphrase for this key (leave empty to keep none, or type 'g' to generate): ")
			if strings.EqualFold(passphrase, "g") {
				generatedPassphrase, err := randomPassphrase()
				if err != nil {
					return err
				}
				passphrase = generatedPassphrase
				fmt.Printf("Generated passphrase: %s\n", passphrase)
			}
			label, privateKey, err := promptPrivateKeyPaste(reader)
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
			passphrase := promptPassphrase(reader, "Passphrase for this key (leave empty to keep none, or type 'g' to generate): ")
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
		next := prompt(reader, "Add another SSH key? [y/N]: ", "N")
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

func promptPrivateKeyPaste(reader *bufio.Reader) (string, []byte, error) {
	// Accept multi-line pasted keys so operators can avoid storing files ahead of time.
	fmt.Println("Paste private key contents, then finish with a single line containing END:")
	label := prompt(reader, "Label for this key (optional): ", "")
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
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

func promptPassphrase(reader *bufio.Reader, label string) string {
	fmt.Print(label)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
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

func loadSettings() (Settings, error) {
	data, err := os.ReadFile(settingsPath())
	if err != nil {
		return Settings{}, err
	}
	parsed := parseKeyValues(string(data))
	return Settings{
		ImportNagiosPath: parsed["import_nagios"],
		WebAddress:       parsed["web_addr"],
		WebAllowIP:       parsed["web_allow_ip"],
		TelegramToken:    parsed["telegram_token"],
		TelegramChatID:   parsed["telegram_chat_id"],
		DatabaseDriver:   parsed["db_driver"],
		DatabaseDSN:      parsed["db_dsn"],
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
		"web_allow_ip=" + settings.WebAllowIP,
		"telegram_token=" + settings.TelegramToken,
		"telegram_chat_id=" + settings.TelegramChatID,
		"db_driver=" + settings.DatabaseDriver,
		"db_dsn=" + settings.DatabaseDSN,
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
	if strings.TrimSpace(override.WebAllowIP) != "" {
		merged.WebAllowIP = override.WebAllowIP
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
	return merged
}

func loadSettingsFromDB(driverName, dsn string) (Settings, error) {
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return Settings{}, err
	}
	defer db.Close()

	statement := `SELECT import_nagios, web_addr, web_allow_ip, telegram_token, telegram_chat_id, db_driver, db_dsn
FROM setup_settings ORDER BY updated_at DESC LIMIT 1`
	row := db.QueryRow(statement)
	settings := Settings{}
	if err := row.Scan(
		&settings.ImportNagiosPath,
		&settings.WebAddress,
		&settings.WebAllowIP,
		&settings.TelegramToken,
		&settings.TelegramChatID,
		&settings.DatabaseDriver,
		&settings.DatabaseDSN,
	); err != nil {
		return Settings{}, err
	}
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
web_allow_ip TEXT,
telegram_token TEXT,
telegram_chat_id TEXT,
db_driver TEXT,
db_dsn TEXT,
updated_at TEXT
)`
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	statement := fmt.Sprintf(`INSERT INTO setup_settings (
id, import_nagios, web_addr, web_allow_ip, telegram_token, telegram_chat_id, db_driver, db_dsn, updated_at
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		placeholder(settings.DatabaseDriver, 1),
		placeholder(settings.DatabaseDriver, 2),
		placeholder(settings.DatabaseDriver, 3),
		placeholder(settings.DatabaseDriver, 4),
		placeholder(settings.DatabaseDriver, 5),
		placeholder(settings.DatabaseDriver, 6),
		placeholder(settings.DatabaseDriver, 7),
		placeholder(settings.DatabaseDriver, 8),
		placeholder(settings.DatabaseDriver, 9),
	)
	_, err = db.Exec(statement,
		fmt.Sprintf("%d", time.Now().UnixNano()),
		settings.ImportNagiosPath,
		settings.WebAddress,
		settings.WebAllowIP,
		settings.TelegramToken,
		settings.TelegramChatID,
		settings.DatabaseDriver,
		settings.DatabaseDSN,
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
	if settings.WebAllowIP != "" {
		lines = append(lines, fmt.Sprintf("Web access: locked to %s via iptables", settings.WebAllowIP))
	} else {
		lines = append(lines, "Web access: open (no iptables lock)")
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
	if settings.WebAllowIP != "" {
		fmt.Printf("- Web access locked to: %s\n", settings.WebAllowIP)
	} else {
		fmt.Println("- Web access: open (no iptables lock)")
	}
	ips := listLocalIPs()
	if len(ips) > 0 {
		fmt.Printf("- Local IPs: %s\n", strings.Join(ips, ", "))
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
