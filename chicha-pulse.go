package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"chicha-pulse/pkg/activity"
	"chicha-pulse/pkg/alert"
	"chicha-pulse/pkg/checker"
	"chicha-pulse/pkg/model"
	"chicha-pulse/pkg/nagiosimport"
	"chicha-pulse/pkg/notify"
	"chicha-pulse/pkg/setup"
	"chicha-pulse/pkg/storage"
	"chicha-pulse/pkg/store"
	"chicha-pulse/pkg/tlsmanager"
	"chicha-pulse/pkg/topology"
	"chicha-pulse/pkg/web"

	_ "chicha-pulse/pkg/localsql"
)

// This file is the single entry point that wires subsystems together with channels.

// ---- Configuration ----

// Configuration keeps runtime settings together so the rest of the code stays tidy.
type Configuration struct {
	ImportNagiosPath string
	WebAddress       string
	PageTitle        string
	TelegramToken    string
	TelegramChatID   string
	DatabaseDriver   string
	DatabaseDSN      string
	DomainName       string
	SSLEmail         string
	WebAllowIPs      []string
	SetupMode        bool
}

// ---- Entry point ----
func main() {
	config := parseFlags()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Printf("shutdown requested, draining services")
	}()

	if config.SetupMode {
		settings, err := setup.Run(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				log.Printf("setup cancelled")
				return
			}
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		config = applySettings(config, settings)
	} else {
		settings, err := setup.LoadSettings()
		if err == nil {
			config = applySettings(config, settings)
		}
	}

	if err := validateConfig(config); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if len(config.WebAllowIPs) > 0 {
		if err := setup.EnsureIptables(ctx, config.WebAddress, config.WebAllowIPs); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	st := store.New(ctx)
	if err := runImport(ctx, st, config.ImportNagiosPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	database, err := storage.Open(ctx, config.DatabaseDriver, config.DatabaseDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer closeDatabase(database)

	results, activityEvents := checker.Start(ctx, st)
	alertInput, storageInput, statusInput := fanOutResults(ctx, results)
	alertEvents := alert.Start(ctx, alertInput)
	startStatusSink(ctx, st, statusInput)
	startActivitySink(ctx, st, activity.Start(ctx, activityEvents))
	topology.Start(ctx, st)

	if config.TelegramToken != "" && config.TelegramChatID != "" {
		notifier := notify.NewTelegram(config.TelegramToken, config.TelegramChatID)
		if err := notify.Start(ctx, notifier, alertEvents); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else {
		log.Printf("telegram notifications disabled")
	}

	if err := storage.Start(ctx, database, storageInput); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	auth := generateAuth()
	log.Printf("web auth username: %s", auth.Username)
	log.Printf("web auth password: %s", auth.Password)
	if err := storage.SaveAuth(ctx, database, auth); err != nil {
		log.Printf("failed to store web credentials: %v", err)
	}

	srv, err := web.NewServer(st, auth, config.PageTitle, config.WebAllowIPs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	httpServer := &http.Server{
		Addr:    config.WebAddress,
		Handler: srv.Handler(),
	}

	if config.DomainName != "" {
		if err := runTLS(ctx, httpServer, config.DomainName, config.SSLEmail); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if err := web.Run(ctx, httpServer); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ---- Flag parsing ----

func parseFlags() Configuration {
	config := Configuration{}
	flag.Usage = printHelp
	flag.StringVar(&config.ImportNagiosPath, "import-nagios", "", "Path to Nagios config directory or nagios.cfg")
	flag.StringVar(&config.WebAddress, "web-addr", ":8080", "HTTP listen address")
	flag.BoolVar(&config.SetupMode, "setup", false, "Run interactive setup")
	flag.Parse()
	return config
}

func printHelp() {
	cyan := "\033[36m"
	yellow := "\033[33m"
	green := "\033[32m"
	reset := "\033[0m"

	fmt.Fprintf(os.Stderr, "%schicha-pulse%s\n", green, reset)
	fmt.Fprintf(os.Stderr, "%sUsage:%s chicha-pulse.go [flags]\n\n", yellow, reset)

	fmt.Fprintf(os.Stderr, "%s1) General settings & setup%s\n", cyan, reset)
	fmt.Fprintln(os.Stderr, "  -setup                 Run interactive setup wizard")
	fmt.Fprintln(os.Stderr, "  -web-addr              HTTP listen address (default :8080)")
	fmt.Fprintln(os.Stderr, "")

	fmt.Fprintf(os.Stderr, "%s2) Import flags%s\n", cyan, reset)
	fmt.Fprintln(os.Stderr, "  -import-nagios          Path to Nagios config directory or nagios.cfg")
	fmt.Fprintln(os.Stderr, "")

	fmt.Fprintf(os.Stderr, "%s3) Export flags%s\n", cyan, reset)
	fmt.Fprintln(os.Stderr, "  (none yet)")
	fmt.Fprintln(os.Stderr, "")
}

func validateConfig(config Configuration) error {
	if config.ImportNagiosPath == "" {
		return fmt.Errorf("import-nagios is required to bootstrap inventory")
	}
	return nil
}

func applySettings(config Configuration, settings setup.Settings) Configuration {
	config.ImportNagiosPath = settings.ImportNagiosPath
	config.WebAddress = settings.WebAddress
	config.TelegramToken = settings.TelegramToken
	config.TelegramChatID = settings.TelegramChatID
	config.DatabaseDriver = settings.DatabaseDriver
	config.DatabaseDSN = settings.DatabaseDSN
	config.DomainName = settings.DomainName
	config.SSLEmail = settings.SSLEmail
	config.WebAllowIPs = append([]string(nil), settings.WebAllowIPs...)
	if config.DomainName != "" {
		config.WebAddress = ":443"
	}
	return config
}

// ---- Import pipeline ----

func runImport(ctx context.Context, st *store.Store, root string) error {
	objects, errs := nagiosimport.Stream(ctx, root)
	for objects != nil || errs != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case obj, ok := <-objects:
			if !ok {
				objects = nil
				continue
			}
			if err := st.Apply(ctx, obj); err != nil {
				return err
			}
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// ---- Result routing ----

func fanOutResults(ctx context.Context, input <-chan checker.Result) (<-chan checker.Result, <-chan checker.Result, <-chan checker.Result) {
	alerts := make(chan checker.Result, 8)
	storageStream := make(chan checker.Result, 8)
	statusStream := make(chan checker.Result, 8)
	go func() {
		defer close(alerts)
		defer close(storageStream)
		defer close(statusStream)
		for {
			select {
			case <-ctx.Done():
				return
			case result, ok := <-input:
				if !ok {
					return
				}
				select {
				case <-ctx.Done():
					return
				case alerts <- result:
				}
				select {
				case <-ctx.Done():
					return
				case storageStream <- result:
				}
				select {
				case <-ctx.Done():
					return
				case statusStream <- result:
				}
			}
		}
	}()
	return alerts, storageStream, statusStream
}

func startStatusSink(ctx context.Context, st *store.Store, input <-chan checker.Result) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case result, ok := <-input:
				if !ok {
					return
				}
				status := modelStatus(result)
				_ = st.UpdateStatus(ctx, statusKey(result), status)
			}
		}
	}()
}

func startActivitySink(ctx context.Context, st *store.Store, input <-chan model.ActivityStats) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case stats, ok := <-input:
				if !ok {
					return
				}
				_ = st.UpdateActivity(ctx, stats)
			}
		}
	}()
}

func modelStatus(result checker.Result) model.ServiceStatus {
	return model.ServiceStatus{
		Status:    result.Status,
		Output:    result.Output,
		CheckedAt: result.CheckedAt,
	}
}

func statusKey(result checker.Result) string {
	return result.HostName + "/" + result.ServiceName
}

// ---- Web auth ----

func generateAuth() web.AuthConfig {
	return web.AuthConfig{
		Username: randomToken(12),
		Password: randomToken(32),
	}
}

func randomToken(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	for i := range bytes {
		bytes[i] = alphabet[int(bytes[i])%len(alphabet)]
	}
	return string(bytes)
}

// ---- Cleanup ----

func closeDatabase(database *storage.Store) {
	if err := database.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func runTLS(ctx context.Context, server *http.Server, domain string, email string) error {
	// Serve HTTPS with a redirect server on port 80 for convenience.
	// We generate or refresh certificates here so runtime TLS always has material to load.
	paths, err := tlsmanager.Ensure(ctx, tlsmanager.Config{Domain: domain, Email: email})
	if err != nil {
		return err
	}
	// Renewal runs on a daily cadence so certificates stay fresh.
	renewErrs := tlsmanager.StartRenewal(ctx, tlsmanager.Config{Domain: domain, Email: email}, 24*time.Hour)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-renewErrs:
				if err != nil {
					log.Printf("tls renewal failed: %v", err)
				}
			}
		}
	}()
	// The broker keeps TLS reloading serialized without mutexes.
	broker := tlsmanager.NewBroker(ctx, paths, time.Minute)
	server.TLSConfig = &tls.Config{
		GetCertificate: broker.GetCertificate,
	}
	redirectServer := &http.Server{
		Addr: ":80",
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			target := "https://" + domain + request.URL.RequestURI()
			http.Redirect(writer, request, target, http.StatusMovedPermanently)
		}),
	}
	go func() {
		if err := web.Run(ctx, redirectServer); err != nil {
			log.Printf("redirect server stopped: %v", err)
		}
	}()
	return runTLSWithContext(ctx, server)
}

func runTLSWithContext(ctx context.Context, server *http.Server) error {
	// Respect context cancellation while serving TLS.
	shutdownErr := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			_ = server.Close()
		}
		shutdownErr <- err
	}()
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		return err
	}
	if err := <-shutdownErr; err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}
