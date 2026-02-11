package auth

// Package auth keeps authentication and role checks in one place so web handlers stay focused.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// ---- Roles ----

// Role represents an access role assigned to a user account.
type Role string

const (
	RoleAdmin          Role = "admin"
	RoleServersView    Role = "servers:view"
	RoleMonitoringView Role = "monitoring:view"
	RoleMonitoringEdit Role = "monitoring:edit"
	defaultSuperuser        = "superuser"
)

const defaultSaltByteCount = 16

// ---- User models ----

// User holds the authentication record used by the web layer.
type User struct {
	Username     string
	PasswordHash string
	PasswordSalt string
	Roles        []Role
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserView is a safe representation for UI listings.
type UserView struct {
	Username string
	Roles    []Role
}

// ---- Manager ----

// Manager keeps user state in one goroutine so role checks stay lock-free.
type Manager struct {
	requests      chan request
	persistWrites chan persistRequest
	users         map[string]User
	storage       *sql.DB
	driverName    string
	ready         chan struct{}
}

type request interface {
	apply(*Manager)
}

type authenticateRequest struct {
	username string
	password string
	response chan authResponse
}

type authResponse struct {
	user User
	ok   bool
}

func (req authenticateRequest) apply(mgr *Manager) {
	user, ok := mgr.users[strings.ToLower(req.username)]
	if !ok {
		req.response <- authResponse{ok: false}
		return
	}
	if !verifyPassword(req.password, user.PasswordSalt, user.PasswordHash) {
		req.response <- authResponse{ok: false}
		return
	}
	req.response <- authResponse{user: user, ok: true}
}

type createUserRequest struct {
	username string
	password string
	roles    []Role
	response chan error
}

func (req createUserRequest) apply(mgr *Manager) {
	key := strings.ToLower(req.username)
	if key == "" {
		req.response <- errors.New("username is required")
		return
	}
	if _, exists := mgr.users[key]; exists {
		req.response <- fmt.Errorf("user %s already exists", req.username)
		return
	}
	if strings.TrimSpace(req.password) == "" {
		req.response <- errors.New("password is required")
		return
	}
	salt := randomSalt()
	hash := hashPassword(req.password, salt)
	roles := normalizeRoles(req.roles)
	now := time.Now().UTC()
	user := User{
		Username:     req.username,
		PasswordHash: hash,
		PasswordSalt: salt,
		Roles:        roles,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	mgr.users[key] = user
	mgr.enqueuePersist(persistRequest{kind: persistUserUpsert, user: user})
	req.response <- nil
}

type listUsersRequest struct {
	response chan []UserView
}

func (req listUsersRequest) apply(mgr *Manager) {
	views := make([]UserView, 0, len(mgr.users))
	for _, user := range mgr.users {
		views = append(views, UserView{Username: user.Username, Roles: append([]Role(nil), user.Roles...)})
	}
	req.response <- views
}

type ensureDefaultRequest struct {
	response chan defaultResponse
}

type defaultResponse struct {
	username string
	password string
	err      error
}

func (req ensureDefaultRequest) apply(mgr *Manager) {
	if len(mgr.users) > 0 {
		req.response <- defaultResponse{}
		return
	}
	username := defaultSuperuser
	password := randomToken(24)
	// Keep explicit monitoring roles so superuser behavior is obvious in both code and UI checks.
	roles := []Role{RoleAdmin, RoleServersView, RoleMonitoringView, RoleMonitoringEdit}
	salt := randomSalt()
	hash := hashPassword(password, salt)
	now := time.Now().UTC()
	user := User{
		Username:     username,
		PasswordHash: hash,
		PasswordSalt: salt,
		Roles:        roles,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	mgr.users[strings.ToLower(username)] = user
	mgr.enqueuePersist(persistRequest{kind: persistUserUpsert, user: user})
	req.response <- defaultResponse{username: username, password: password}
}

// NewManager starts the auth manager and primes it from storage if possible.
func NewManager(ctx context.Context, storage *sql.DB, driverName string) (*Manager, error) {
	mgr := &Manager{
		requests:      make(chan request),
		persistWrites: make(chan persistRequest, 16),
		users:         make(map[string]User),
		storage:       storage,
		driverName:    driverName,
		ready:         make(chan struct{}),
	}
	go mgr.run(ctx)
	go mgr.runPersist(ctx)
	if storage != nil {
		if err := ensureSchema(ctx, storage); err != nil {
			return nil, err
		}
		go mgr.loadFromStorage(ctx)
	} else {
		close(mgr.ready)
	}
	return mgr, nil
}

// Authenticate validates credentials using the in-memory cache.
func (mgr *Manager) Authenticate(ctx context.Context, username, password string) (User, bool) {
	response := make(chan authResponse, 1)
	select {
	case <-ctx.Done():
		return User{}, false
	case mgr.requests <- authenticateRequest{username: username, password: password, response: response}:
	}
	select {
	case <-ctx.Done():
		return User{}, false
	case result := <-response:
		return result.user, result.ok
	}
}

// CreateUser adds a new account that can log into the UI.
func (mgr *Manager) CreateUser(ctx context.Context, username, password string, roles []Role) error {
	response := make(chan error, 1)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case mgr.requests <- createUserRequest{username: username, password: password, roles: roles, response: response}:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-response:
		return err
	}
}

// ListUsers returns a safe list for admin UI rendering.
func (mgr *Manager) ListUsers(ctx context.Context) ([]UserView, error) {
	response := make(chan []UserView, 1)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case mgr.requests <- listUsersRequest{response: response}:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case users := <-response:
		return users, nil
	}
}

// EnsureDefaultAdmin provisions the first admin user when no accounts exist.
func (mgr *Manager) EnsureDefaultAdmin(ctx context.Context) (string, string, error) {
	select {
	case <-ctx.Done():
		return "", "", ctx.Err()
	case <-mgr.ready:
	}
	response := make(chan defaultResponse, 1)
	select {
	case <-ctx.Done():
		return "", "", ctx.Err()
	case mgr.requests <- ensureDefaultRequest{response: response}:
	}
	select {
	case <-ctx.Done():
		return "", "", ctx.Err()
	case result := <-response:
		return result.username, result.password, result.err
	}
}

func (mgr *Manager) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-mgr.requests:
			req.apply(mgr)
		}
	}
}

// ---- Persistence ----

type persistKind int

const (
	persistUserUpsert persistKind = iota
)

type persistRequest struct {
	kind persistKind
	user User
}

func (mgr *Manager) enqueuePersist(request persistRequest) {
	select {
	case mgr.persistWrites <- request:
	default:
		log.Printf("auth persistence queue is full; write skipped")
	}
}

func (mgr *Manager) runPersist(ctx context.Context) {
	if mgr.storage == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-mgr.persistWrites:
			if req.kind == persistUserUpsert {
				if err := upsertUser(ctx, mgr.storage, mgr.driverName, req.user); err != nil {
					log.Printf("failed to persist user %s: %v", req.user.Username, err)
				}
			}
		}
	}
}

func (mgr *Manager) loadFromStorage(ctx context.Context) {
	defer close(mgr.ready)
	users, err := loadUsers(ctx, mgr.storage)
	if err != nil {
		if isUnsupportedQuery(err) {
			log.Printf("auth storage query unsupported; using in-memory users")
			return
		}
		log.Printf("failed to load users: %v", err)
		return
	}
	if len(users) == 0 {
		return
	}
	loadRequest := loadUsersRequest{users: users}
	select {
	case <-ctx.Done():
		return
	case mgr.requests <- loadRequest:
	}
}

type loadUsersRequest struct {
	users []User
}

func (req loadUsersRequest) apply(mgr *Manager) {
	for _, user := range req.users {
		mgr.users[strings.ToLower(user.Username)] = user
	}
}

func ensureSchema(ctx context.Context, storage *sql.DB) error {
	statement := `CREATE TABLE IF NOT EXISTS auth_users (
		username TEXT,
		password_hash TEXT,
		password_salt TEXT,
		roles TEXT,
		created_at TEXT,
		updated_at TEXT
	)`
	_, err := storage.ExecContext(ctx, statement)
	return err
}

func upsertUser(ctx context.Context, storage *sql.DB, driverName string, user User) error {
	statement := fmt.Sprintf(`INSERT INTO auth_users (
		username,
		password_hash,
		password_salt,
		roles,
		created_at,
		updated_at
	) VALUES (%s, %s, %s, %s, %s, %s)`,
		placeholder(driverName, 1),
		placeholder(driverName, 2),
		placeholder(driverName, 3),
		placeholder(driverName, 4),
		placeholder(driverName, 5),
		placeholder(driverName, 6),
	)
	_, err := storage.ExecContext(ctx, statement,
		user.Username,
		user.PasswordHash,
		user.PasswordSalt,
		formatRoles(user.Roles),
		user.CreatedAt.Format(time.RFC3339Nano),
		user.UpdatedAt.Format(time.RFC3339Nano),
	)
	return err
}

func loadUsers(ctx context.Context, storage *sql.DB) ([]User, error) {
	statement := `SELECT username, password_hash, password_salt, roles, created_at, updated_at FROM auth_users`
	rows, err := storage.QueryContext(ctx, statement)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var user User
		var roles string
		var createdAt string
		var updatedAt string
		if err := rows.Scan(&user.Username, &user.PasswordHash, &user.PasswordSalt, &roles, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		user.Roles = parseRoles(roles)
		user.CreatedAt = parseTime(createdAt)
		user.UpdatedAt = parseTime(updatedAt)
		users = append(users, user)
	}
	return users, rows.Err()
}

func parseTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func placeholder(driverName string, index int) string {
	if driverName == "postgres" {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func randomSalt() string {
	bytes := make([]byte, defaultSaltByteCount)
	if _, err := rand.Read(bytes); err != nil {
		return randomToken(12)
	}
	return base64.RawStdEncoding.EncodeToString(bytes)
}

func hashPassword(password, salt string) string {
	hash := sha256.Sum256([]byte(salt + ":" + password))
	return base64.RawStdEncoding.EncodeToString(hash[:])
}

func verifyPassword(password, salt, hashed string) bool {
	return hashPassword(password, salt) == hashed
}

func randomToken(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	for i := range bytes {
		bytes[i] = alphabet[int(bytes[i])%len(alphabet)]
	}
	return string(bytes)
}

func normalizeRoles(roles []Role) []Role {
	if len(roles) == 0 {
		return []Role{RoleServersView, RoleMonitoringView}
	}
	seen := make(map[Role]struct{})
	var cleaned []Role
	for _, role := range roles {
		trimmed := Role(strings.TrimSpace(string(role)))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		cleaned = append(cleaned, trimmed)
	}
	if len(cleaned) == 0 {
		return []Role{RoleServersView, RoleMonitoringView}
	}
	return cleaned
}

func formatRoles(roles []Role) string {
	parts := make([]string, 0, len(roles))
	for _, role := range roles {
		parts = append(parts, string(role))
	}
	return strings.Join(parts, ",")
}

func parseRoles(value string) []Role {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	fields := strings.Split(value, ",")
	roles := make([]Role, 0, len(fields))
	for _, field := range fields {
		clean := strings.TrimSpace(field)
		if clean == "" {
			continue
		}
		roles = append(roles, Role(clean))
	}
	return normalizeRoles(roles)
}

func isUnsupportedQuery(err error) bool {
	// Match placeholder driver errors so memory-only mode can continue.
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "query not supported") || strings.Contains(message, "unsupported")
}

// HasRole checks for the requested role, honoring admin as universal access.
func HasRole(user User, role Role) bool {
	for _, owned := range user.Roles {
		if owned == RoleAdmin || owned == role {
			return true
		}
	}
	return false
}
