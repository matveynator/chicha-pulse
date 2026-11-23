package fleet

// Fleet credentials are stored separately from the Nagios settings. The
// encrypted file and its randomly generated key are local to the monitor
// machine and restricted to the service user (0600).
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Settings struct {
	RobotUser       string `json:"robot_user"`
	RobotPassword   string `json:"robot_password"`
	CloudToken      string `json:"cloud_token"`
	SelectelAccount string `json:"selectel_account"`
	SelectelUser    string `json:"selectel_user"`
	SelectelPassword string `json:"selectel_password"`
	SelectelToken   string `json:"selectel_token"`
	SSHUser         string `json:"ssh_user"`
	SSHKeyPath      string `json:"ssh_key_path"`
	SSHPort         int    `json:"ssh_port"`
	PollSeconds     int    `json:"poll_seconds"`
}

func SettingsPath() string {
	if path := strings.TrimSpace(os.Getenv("CHICHA_FLEET_SETTINGS_FILE")); path != "" {
		return path
	}
	return "/var/lib/chicha-pulse/fleet-settings.enc"
}

// LoadSettings doesn't create a key if there are no saved settings. Missing
// files are normal on a fresh installation; corrupt files are reported.
func LoadSettings(path string) (Settings, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	key, err := os.ReadFile(path + ".key")
	if err != nil {
		return Settings{}, fmt.Errorf("cannot read fleet settings key: %w", err)
	}
	if len(key) != 32 {
		return Settings{}, errors.New("invalid fleet settings key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Settings{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Settings{}, err
	}
	if len(data) < gcm.NonceSize() {
		return Settings{}, errors.New("fleet settings ciphertext too short")
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return Settings{}, errors.New("fleet settings cannot be decrypted")
	}
	var settings Settings
	if err := json.Unmarshal(plain, &settings); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func SaveSettings(path string, settings Settings) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	key, err := loadOrCreateKey(path + ".key")
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	encrypted := gcm.Seal(nonce, nonce, data, nil)
	file, err := os.CreateTemp(filepath.Dir(path), ".fleet-settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(encrypted); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func loadOrCreateKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, errors.New("fleet master key is not 32 bytes")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateKey(path)
	}
	if err != nil {
		return nil, err
	}
	if _, err := file.Write(key); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

// ResolveSettings merges entered settings over environment and command-line
// defaults. Secrets saved through the web UI override environment values.
func ResolveSettings(path string, env Config, ssh SSHOptions, interval time.Duration) (Config, SSHOptions, time.Duration, error) {
	saved, err := LoadSettings(path)
	if err != nil {
		return env, ssh, interval, err
	}
return MergeSettings(env, ssh, interval, saved)
}

// MergeSettings is also used by the web form's "Test" action: it can verify
// entered credentials in memory without writing them to disk.
func MergeSettings(env Config, ssh SSHOptions, interval time.Duration, saved Settings) (Config, SSHOptions, time.Duration, error) {
	if saved.RobotUser != "" { env.HetznerUser = saved.RobotUser }
	if saved.RobotPassword != "" { env.HetznerPassword = saved.RobotPassword }
	if saved.CloudToken != "" { env.HetznerCloudToken = saved.CloudToken }
	if saved.SelectelAccount != "" { env.SelectelAccountID = saved.SelectelAccount }
	if saved.SelectelUser != "" { env.SelectelUser = saved.SelectelUser }
	if saved.SelectelPassword != "" {
		env.SelectelPassword = saved.SelectelPassword
		env.SelectelToken = ""
	}
	if saved.SelectelToken != "" { env.SelectelToken = saved.SelectelToken }
	if saved.SSHUser != "" { ssh.User = saved.SSHUser }
	if saved.SSHKeyPath != "" { ssh.KeyPath = saved.SSHKeyPath }
	if saved.SSHPort > 0 { ssh.Port = saved.SSHPort }
	if saved.PollSeconds >= 30 && saved.PollSeconds <= 3600 {
		interval = time.Duration(saved.PollSeconds) * time.Second
	}
	return env, ssh, interval, nil
}
