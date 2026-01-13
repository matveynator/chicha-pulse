package tlsmanager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// This package keeps TLS certificate generation and reloading in one place so other packages stay focused.

// ---- Configuration ----

// Config groups certificate settings so callers can pass a single value.
type Config struct {
	Domain         string
	Email          string
	BaseDir        string
	RenewBefore    time.Duration
	CertificateTTL time.Duration
}

// Paths captures the filesystem locations for a TLS certificate and key.
type Paths struct {
	CertFile string
	KeyFile  string
}

const defaultBaseDir = "/etc/chicha-pulse/tls"
const defaultRenewBefore = 30 * 24 * time.Hour
const defaultCertificateTTL = 90 * 24 * time.Hour
const defaultRenewInterval = 24 * time.Hour

// ---- Public API ----

// Ensure verifies a TLS certificate exists and refreshes it when it is close to expiring.
func Ensure(ctx context.Context, config Config) (Paths, error) {
	// We keep certificate state on disk so the running service can reload it without external tools.
	if config.Domain == "" {
		return Paths{}, nil
	}
	applyDefaults(&config)
	paths := certificatePaths(config.Domain, config.BaseDir)
	if err := os.MkdirAll(config.BaseDir, 0o700); err != nil {
		return Paths{}, fmt.Errorf("create tls directory: %w", err)
	}

	statusCh := make(chan certStatus, 1)
	go func() {
		statusCh <- inspectCertificate(paths, config.RenewBefore)
	}()

	select {
	case <-ctx.Done():
		return Paths{}, ctx.Err()
	case status := <-statusCh:
		if status.err != nil && !errors.Is(status.err, os.ErrNotExist) {
			return Paths{}, status.err
		}
		if !status.needsRenewal {
			return paths, nil
		}
	}

	if err := issueSelfSigned(paths, config.Domain, config.Email, config.CertificateTTL); err != nil {
		return Paths{}, err
	}
	return paths, nil
}

// NewBroker starts a goroutine that reloads TLS certificates on a schedule.
func NewBroker(ctx context.Context, paths Paths, reloadEvery time.Duration) *Broker {
	// Using a broker isolates certificate reloads to one goroutine and avoids shared memory locks.
	if reloadEvery <= 0 {
		reloadEvery = time.Minute
	}
	requests := make(chan certRequest)
	broker := &Broker{requests: requests}
	go broker.run(ctx, paths, reloadEvery)
	return broker
}

// StartRenewal launches a goroutine that periodically calls Ensure to refresh certificates.
func StartRenewal(ctx context.Context, config Config, renewEvery time.Duration) <-chan error {
	// A dedicated goroutine keeps renewals off the main path and avoids locks.
	if renewEvery <= 0 {
		renewEvery = defaultRenewInterval
	}
	errs := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(renewEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := Ensure(ctx, config); err != nil {
					select {
					case errs <- err:
					default:
					}
				}
			}
		}
	}()
	return errs
}

// ---- Broker ----

// Broker owns the current TLS certificate and serves it to the HTTP server.
type Broker struct {
	requests chan certRequest
}

type certRequest struct {
	response chan certResponse
}

type certResponse struct {
	cert *tls.Certificate
	err  error
}

// GetCertificate fetches the latest certificate via the broker goroutine.
func (broker *Broker) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	reply := make(chan certResponse, 1)
	broker.requests <- certRequest{response: reply}
	response := <-reply
	return response.cert, response.err
}

func (broker *Broker) run(ctx context.Context, paths Paths, reloadEvery time.Duration) {
	// The broker keeps certificate loading serialized so we can refresh without mutexes.
	ticker := time.NewTicker(reloadEvery)
	defer ticker.Stop()

	var cached *tls.Certificate
	var cachedErr error
	load := func() {
		cached, cachedErr = loadCertificate(paths)
	}
	load()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			load()
		case request := <-broker.requests:
			request.response <- certResponse{cert: cached, err: cachedErr}
		}
	}
}

// ---- Certificate inspection ----

type certStatus struct {
	needsRenewal bool
	err          error
}

func inspectCertificate(paths Paths, renewBefore time.Duration) certStatus {
	// We read the current certificate to decide whether it needs a refresh.
	certPEM, err := os.ReadFile(paths.CertFile)
	if err != nil {
		return certStatus{needsRenewal: true, err: err}
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return certStatus{needsRenewal: true, err: fmt.Errorf("failed to decode cert PEM")}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certStatus{needsRenewal: true, err: err}
	}
	if time.Until(cert.NotAfter) <= renewBefore {
		return certStatus{needsRenewal: true}
	}
	return certStatus{needsRenewal: false}
}

// ---- Certificate issuance ----

func issueSelfSigned(paths Paths, domain string, email string, ttl time.Duration) error {
	// Self-signed certificates keep the system independent from external tooling.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate tls key: %w", err)
	}
	// We limit serial numbers to 128 bits for compatibility with common TLS tooling.
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}
	notBefore := time.Now().Add(-time.Hour)
	if ttl <= 0 {
		ttl = defaultCertificateTTL
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		EmailAddresses:        nonEmptyEmail(email),
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(ttl),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create tls cert: %w", err)
	}

	if err := writePEM(paths.KeyFile, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privateKey), 0o600); err != nil {
		return err
	}
	if err := writePEM(paths.CertFile, "CERTIFICATE", certDER, 0o644); err != nil {
		return err
	}
	return nil
}

// ---- Helpers ----

func applyDefaults(config *Config) {
	// Defaults keep callers minimal while still allowing overrides.
	if config.BaseDir == "" {
		config.BaseDir = defaultBaseDir
	}
	if config.RenewBefore == 0 {
		config.RenewBefore = defaultRenewBefore
	}
	if config.CertificateTTL == 0 {
		config.CertificateTTL = defaultCertificateTTL
	}
}

func certificatePaths(domain string, baseDir string) Paths {
	// We keep paths deterministic so other parts of the system can predict them.
	certFile := filepath.Join(baseDir, domain+".crt")
	keyFile := filepath.Join(baseDir, domain+".key")
	return Paths{CertFile: certFile, KeyFile: keyFile}
}

func loadCertificate(paths Paths) (*tls.Certificate, error) {
	// Loading from disk lets us pick up new certificates without restarting.
	cert, err := tls.LoadX509KeyPair(paths.CertFile, paths.KeyFile)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func writePEM(path string, blockType string, bytes []byte, perm os.FileMode) error {
	// Using a temporary file keeps partially written certificates from leaking.
	tempPath := path + ".tmp"
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("open pem file: %w", err)
	}
	defer file.Close()
	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: bytes}); err != nil {
		return fmt.Errorf("write pem: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync pem: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close pem: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("finalize pem: %w", err)
	}
	return nil
}

func nonEmptyEmail(email string) []string {
	// We only include email when provided so the certificate stays clean.
	if email == "" {
		return nil
	}
	return []string{email}
}
