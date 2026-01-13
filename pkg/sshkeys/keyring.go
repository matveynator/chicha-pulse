package sshkeys

// Package sshkeys stores SSH credentials securely for reuse across checks.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	masterKeyPath   = "/var/lib/chicha-pulse/sshkey.master"
	settingsPath    = "/var/lib/chicha-pulse/settings.conf"
	keyringFilePath = "/var/lib/chicha-pulse/sshkeys.json"
	keyringTableSQL = `CREATE TABLE IF NOT EXISTS setup_ssh_keys (
id TEXT,
label TEXT,
public_key TEXT,
private_key_enc TEXT,
passphrase_enc TEXT,
created_at TEXT
)`
)

// KeyRecord holds decrypted SSH material for runtime usage.
type KeyRecord struct {
	ID         string
	Label      string
	PublicKey  string
	PrivateKey []byte
	Passphrase []byte
	CreatedAt  time.Time
}

// EnsureKeyring prepares storage for encrypted SSH keys.
func EnsureKeyring(ctx context.Context, driverName, dsn string) error {
	if strings.TrimSpace(driverName) == "" || strings.TrimSpace(dsn) == "" {
		return nil
	}
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, keyringTableSQL)
	return err
}

// SaveKey encrypts and stores key material so future checks can reuse it.
func SaveKey(ctx context.Context, driverName, dsn, label, publicKey string, privateKey, passphrase []byte) error {
	masterKey, err := loadOrCreateMasterKey()
	if err != nil {
		return err
	}
	privateKeyEnc, err := encrypt(masterKey, privateKey)
	if err != nil {
		return err
	}
	passphraseEnc, err := encrypt(masterKey, passphrase)
	if err != nil {
		return err
	}
	if err := saveKeyFileRecord(label, publicKey, privateKeyEnc, passphraseEnc); err != nil {
		return err
	}

	if strings.TrimSpace(driverName) == "" || strings.TrimSpace(dsn) == "" {
		return nil
	}
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if _, err := db.ExecContext(ctx, keyringTableSQL); err != nil {
		return err
	}

	statement := fmt.Sprintf(`INSERT INTO setup_ssh_keys (
id, label, public_key, private_key_enc, passphrase_enc, created_at
) VALUES (%s, %s, %s, %s, %s, %s)`,
		placeholder(driverName, 1),
		placeholder(driverName, 2),
		placeholder(driverName, 3),
		placeholder(driverName, 4),
		placeholder(driverName, 5),
		placeholder(driverName, 6),
	)
	_, err = db.ExecContext(ctx, statement,
		fmt.Sprintf("%d", time.Now().UnixNano()),
		label,
		publicKey,
		privateKeyEnc,
		passphraseEnc,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

// LoadKeyring returns up to the most recent three keys so SSH checks can try them in order.
func LoadKeyring(ctx context.Context, driverName, dsn string) ([]KeyRecord, error) {
	if strings.TrimSpace(driverName) == "" || strings.TrimSpace(dsn) == "" {
		return loadKeyringFile()
	}
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	statement := `SELECT id, label, public_key, private_key_enc, passphrase_enc, created_at
FROM setup_ssh_keys ORDER BY created_at DESC LIMIT 3`
	rows, err := db.QueryContext(ctx, statement)
	if err != nil {
		if isUnsupportedQuery(err) {
			return loadKeyringFile()
		}
		return nil, err
	}
	defer rows.Close()

	masterKey, err := loadOrCreateMasterKey()
	if err != nil {
		return nil, err
	}

	var records []KeyRecord
	for rows.Next() {
		var record KeyRecord
		var privateKeyEnc string
		var passphraseEnc string
		var createdAt string
		if err := rows.Scan(&record.ID, &record.Label, &record.PublicKey, &privateKeyEnc, &passphraseEnc, &createdAt); err != nil {
			return nil, err
		}
		record.PrivateKey, err = decrypt(masterKey, privateKeyEnc)
		if err != nil {
			return nil, err
		}
		record.Passphrase, err = decrypt(masterKey, passphraseEnc)
		if err != nil {
			return nil, err
		}
		if createdAt != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
				record.CreatedAt = parsed
			}
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

// LoadKeyringFromSettings reads database credentials from the settings file.
func LoadKeyringFromSettings(ctx context.Context) ([]KeyRecord, error) {
	values, err := readSettingsFile()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return loadKeyringFile()
		}
		return nil, err
	}
	return LoadKeyring(ctx, values["db_driver"], values["db_dsn"])
}

func readSettingsFile() (map[string]string, error) {
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	lines := strings.Split(string(data), "\n")
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
	return values, nil
}

type keyringFileRecord struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	PublicKey    string `json:"public_key"`
	PrivateKey   string `json:"private_key_enc"`
	Passphrase   string `json:"passphrase_enc"`
	CreatedAtUTC string `json:"created_at"`
}

func loadOrCreateMasterKey() ([]byte, error) {
	if data, err := os.ReadFile(masterKeyPath); err == nil {
		return data, nil
	}
	if err := os.MkdirAll(filepath.Dir(masterKeyPath), 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(masterKeyPath, key, 0o400); err != nil {
		return nil, err
	}
	return key, nil
}

func saveKeyFileRecord(label, publicKey, privateKeyEnc, passphraseEnc string) error {
	// Store key data on disk so placeholder SQL drivers still have SSH keys available.
	records, err := readKeyringFileRaw()
	if err != nil {
		return err
	}
	record := keyringFileRecord{
		ID:           fmt.Sprintf("%d", time.Now().UnixNano()),
		Label:        label,
		PublicKey:    publicKey,
		PrivateKey:   privateKeyEnc,
		Passphrase:   passphraseEnc,
		CreatedAtUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	records = append([]keyringFileRecord{record}, records...)
	if len(records) > 3 {
		records = records[:3]
	}
	return writeKeyringFile(records)
}

func loadKeyringFile() ([]KeyRecord, error) {
	// Load key material from disk when SQL drivers cannot handle queries.
	raw, err := readKeyringFileRaw()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	masterKey, err := loadOrCreateMasterKey()
	if err != nil {
		return nil, err
	}
	var records []KeyRecord
	for _, item := range raw {
		privateKey, err := decrypt(masterKey, item.PrivateKey)
		if err != nil {
			return nil, err
		}
		passphrase, err := decrypt(masterKey, item.Passphrase)
		if err != nil {
			return nil, err
		}
		record := KeyRecord{
			ID:         item.ID,
			Label:      item.Label,
			PublicKey:  item.PublicKey,
			PrivateKey: privateKey,
			Passphrase: passphrase,
		}
		if item.CreatedAtUTC != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, item.CreatedAtUTC); err == nil {
				record.CreatedAt = parsed
			}
		}
		records = append(records, record)
	}
	return records, nil
}

func readKeyringFileRaw() ([]keyringFileRecord, error) {
	data, err := os.ReadFile(keyringFilePath)
	if err != nil {
		return nil, err
	}
	var records []keyringFileRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func writeKeyringFile(records []keyringFileRecord) error {
	if err := os.MkdirAll(filepath.Dir(keyringFilePath), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(keyringFilePath, data, 0o600)
}

func isUnsupportedQuery(err error) bool {
	// Detect placeholder SQL drivers that do not support QueryContext.
	return strings.Contains(err.Error(), "query not supported")
}

func encrypt(key []byte, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	encrypted := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func decrypt(key []byte, ciphertext string) ([]byte, error) {
	if ciphertext == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := raw[:gcm.NonceSize()]
	payload := raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, payload, nil)
}

func placeholder(driverName string, index int) string {
	if driverName == "postgres" {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}
