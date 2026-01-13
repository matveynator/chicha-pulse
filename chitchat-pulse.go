package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"chicha-pulse/pkg/alert"
	"chicha-pulse/pkg/checker"
	"chicha-pulse/pkg/nagiosimport"
	"chicha-pulse/pkg/notify"
	"chicha-pulse/pkg/storage"
	"chicha-pulse/pkg/store"
	"chicha-pulse/pkg/web"

	_ "chicha-pulse/pkg/localsql"
)

// This file is the single entry point that wires subsystems together with channels.

// ---- Configuration ----

// Configuration keeps runtime settings together so the rest of the code stays tidy.
type Configuration struct {
	ImportNagiosPath string
	WebAddress       string
	SuperAdminUser   string
	SuperAdminPass   string
	PageTitle        string
	CheckInterval    time.Duration
	TelegramToken    string
	TelegramChatID   string
	DatabaseDriver   string
	DatabaseDSN      string
}

// ---- Entry point ----
func main() {
	config := parseFlags()
	if err := validateConfig(config); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	results := checker.Start(ctx, st, config.CheckInterval)
	alertInput, storageInput := fanOutResults(ctx, results)
	alertEvents := alert.Start(ctx, alertInput)

	notifier := notify.NewTelegram(config.TelegramToken, config.TelegramChatID)
	if err := notifier.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := notify.Start(ctx, notifier, alertEvents); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := storage.Start(ctx, database, storageInput); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	srv, err := web.NewServer(st, web.AuthConfig{
		Username: config.SuperAdminUser,
		Password: config.SuperAdminPass,
	}, config.PageTitle)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	httpServer := &http.Server{
		Addr:    config.WebAddress,
		Handler: srv.Handler(),
	}

	if err := web.Run(ctx, httpServer); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ---- Flag parsing ----

func parseFlags() Configuration {
	config := Configuration{}
	flag.StringVar(&config.ImportNagiosPath, "import-nagios", "", "Path to Nagios config directory")
	flag.StringVar(&config.WebAddress, "web-addr", ":8080", "HTTP listen address")
	flag.StringVar(&config.SuperAdminUser, "superadmin-user", "admin", "Superadmin username")
	flag.StringVar(&config.SuperAdminPass, "superadmin-pass", "", "Superadmin password")
	flag.StringVar(&config.PageTitle, "page-title", "chicha-pulse", "Dashboard title")
	flag.DurationVar(&config.CheckInterval, "check-interval", 30*time.Second, "Interval between check runs")
	flag.StringVar(&config.TelegramToken, "telegram-token", "", "Telegram bot token")
	flag.StringVar(&config.TelegramChatID, "telegram-chat-id", "", "Telegram chat ID for notifications")
	flag.StringVar(&config.DatabaseDriver, "db-driver", "sqlite", "Database driver (sqlite or postgres)")
	flag.StringVar(&config.DatabaseDSN, "db-dsn", "file:chicha-pulse.db", "Database DSN")
	flag.Parse()
	return config
}

func validateConfig(config Configuration) error {
	if config.SuperAdminPass == "" {
		return fmt.Errorf("superadmin-pass is required for initial access")
	}
	if config.ImportNagiosPath == "" {
		return fmt.Errorf("import-nagios is required to bootstrap inventory")
	}
	return nil
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

func fanOutResults(ctx context.Context, input <-chan checker.Result) (<-chan checker.Result, <-chan checker.Result) {
	alerts := make(chan checker.Result, 8)
	storageStream := make(chan checker.Result, 8)
	go func() {
		defer close(alerts)
		defer close(storageStream)
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
			}
		}
	}()
	return alerts, storageStream
}

// ---- Cleanup ----

func closeDatabase(database *storage.Store) {
	if err := database.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
