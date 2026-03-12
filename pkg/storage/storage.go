package storage

// Package storage keeps database writes sequential to reduce contention.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"chicha-pulse/pkg/checker"
)

// This package isolates database/sql usage so drivers can be swapped later.

// ---- Store ----

type Store struct {
	database   *sql.DB
	driverName string
}

// Open prepares a database connection so the rest of the app can stay focused on monitoring.
func Open(ctx context.Context, driverName, dsn string) (*Store, error) {
	database, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	if err := database.PingContext(ctx); err != nil {
		return nil, err
	}
	store := &Store{database: database, driverName: driverName}
	if err := ensureSchema(ctx, store); err != nil {
		return nil, err
	}
	return store, nil
}

// Close releases the database connection when the application exits.
func (store *Store) Close() error {
	return store.database.Close()
}

// Start stores check results in a single goroutine to keep database traffic ordered.
func Start(ctx context.Context, store *Store, results <-chan checker.Result) error {
	if store == nil {
		return errors.New("database is required")
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case result, ok := <-results:
				if !ok {
					return
				}
				if err := insertResult(ctx, store, result); err != nil {
					log.Printf("db insert failed host=%s service=%s err=%v", result.HostName, result.ServiceName, err)
				}
			}
		}
	}()
	return nil
}

// Database exposes the underlying database handle so other packages can share the connection.
func (store *Store) Database() *sql.DB {
	return store.database
}

// DriverName reports the active database driver for SQL placeholder formatting.
func (store *Store) DriverName() string {
	return store.driverName
}

// ---- Schema ----

func ensureSchema(ctx context.Context, store *Store) error {
	statement := `CREATE TABLE IF NOT EXISTS check_results (
		id TEXT,
		host_name TEXT,
		service_name TEXT,
		check_command TEXT,
		status INTEGER,
		output TEXT,
		checked_at TEXT
	)`
	if _, err := store.database.ExecContext(ctx, statement); err != nil {
		return err
	}
	return nil
}

// ---- Persistence ----

func insertResult(ctx context.Context, store *Store, result checker.Result) error {
	statement := fmt.Sprintf(`INSERT INTO check_results (
		id,
		host_name,
		service_name,
		check_command,
		status,
		output,
		checked_at
	) VALUES (%s, %s, %s, %s, %s, %s, %s)`,
		placeholder(store.driverName, 1),
		placeholder(store.driverName, 2),
		placeholder(store.driverName, 3),
		placeholder(store.driverName, 4),
		placeholder(store.driverName, 5),
		placeholder(store.driverName, 6),
		placeholder(store.driverName, 7),
	)
	_, err := store.database.ExecContext(ctx, statement,
		resultID(result),
		result.HostName,
		result.ServiceName,
		result.CheckCommand,
		result.Status,
		result.Output,
		result.CheckedAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func placeholder(driverName string, index int) string {
	if driverName == "postgres" {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func resultID(result checker.Result) string {
	return result.CheckedAt.UTC().Format(time.RFC3339Nano) + ":" + result.HostName + ":" + result.ServiceName
}
