package localsql

// Package localsql provides in-process drivers so the app can compile without third-party SQL drivers.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
)

// init registers placeholder drivers so database/sql can be used without external dependencies.
func init() {
	sql.Register("sqlite", &memoryDriver{})
	sql.Register("postgres", &memoryDriver{})
}

// memoryDriver is a minimal driver that accepts Exec calls and keeps them in-process.
type memoryDriver struct{}

func (driver *memoryDriver) Open(name string) (driver.Conn, error) {
	return newConnection(), nil
}

// connection serializes Exec requests through a channel to avoid explicit locking.
type connection struct {
	execCh chan execRequest
	close  chan struct{}
}

type execRequest struct {
	query  string
	args   []driver.Value
	result chan execResult
}

type execResult struct {
	result driver.Result
	err    error
}

func newConnection() *connection {
	conn := &connection{
		execCh: make(chan execRequest),
		close:  make(chan struct{}),
	}
	go conn.loop()
	return conn
}

func (conn *connection) Prepare(query string) (driver.Stmt, error) {
	return &statement{query: query, conn: conn}, nil
}

func (conn *connection) Close() error {
	close(conn.close)
	return nil
}

func (conn *connection) Begin() (driver.Tx, error) {
	return &transaction{}, nil
}

func (conn *connection) Ping(ctx context.Context) error {
	return nil
}

func (conn *connection) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	values := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		values = append(values, arg.Value)
	}
	return conn.exec(ctx, query, values)
}

func (conn *connection) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return nil, errors.New("query not supported in placeholder driver")
}

func (conn *connection) loop() {
	for {
		select {
		case <-conn.close:
			return
		case req := <-conn.execCh:
			req.result <- execResult{result: simpleResult(1), err: nil}
		}
	}
}

func (conn *connection) exec(ctx context.Context, query string, args []driver.Value) (driver.Result, error) {
	request := execRequest{query: query, args: args, result: make(chan execResult, 1)}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-conn.close:
		return nil, errors.New("connection closed")
	case conn.execCh <- request:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case response := <-request.result:
		return response.result, response.err
	}
}

// statement allows database/sql to reuse prepared queries without external dependencies.
type statement struct {
	query string
	conn  *connection
}

func (stmt *statement) Close() error {
	return nil
}

func (stmt *statement) NumInput() int {
	return -1
}

func (stmt *statement) Exec(args []driver.Value) (driver.Result, error) {
	return stmt.conn.exec(context.Background(), stmt.query, args)
}

func (stmt *statement) Query(args []driver.Value) (driver.Rows, error) {
	return nil, errors.New("query not supported in placeholder driver")
}

// transaction exists so database/sql can call Begin without extra dependencies.
type transaction struct{}

func (tx *transaction) Commit() error {
	return nil
}

func (tx *transaction) Rollback() error {
	return nil
}

// simpleResult satisfies driver.Result for Exec calls.
type simpleResult int64

func (result simpleResult) LastInsertId() (int64, error) {
	return 0, errors.New("last insert id not supported")
}

func (result simpleResult) RowsAffected() (int64, error) {
	return int64(result), nil
}
