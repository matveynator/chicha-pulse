package fleet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSettingsEncryptAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.enc")
	first, err := LoadSettings(path)
	if err != nil || first.RobotUser != "" {
		t.Fatalf("unexpected empty settings: %+v %v", first, err)
	}
	want := Settings{
		RobotUser: "testuser", RobotPassword: "ROBOT_SECRET_NOT_IN_PLAINTEXT",
		CloudToken: "CLOUD_SECRET_NOT_IN_PLAINTEXT",
		SelectelAccount: "123", SelectelUser: "service",
		SelectelPassword: "SELECTEL_SECRET_NOT_IN_PLAINTEXT",
		SSHUser: "inventory", SSHKeyPath: "/home/inventory/.ssh/id_ed25519",
		SSHPort: 2222, PollSeconds: 90,
	}
	if err := SaveSettings(path, want); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	for _, secret := range []string{want.RobotPassword, want.CloudToken, want.SelectelPassword} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("secret %s leaked into ciphertext", secret)
		}
	}
	for _, item := range []string{path, path+".key"} {
		info, err := os.Stat(item)
		if err != nil { t.Fatal(err) }
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s should be mode 0600, got %v", item, info.Mode().Perm())
		}
	}
	loaded, err := LoadSettings(path)
	if err != nil { t.Fatal(err) }
	if loaded != want {
		t.Fatalf("settings roundtrip differ: got %+v", loaded)
	}
	if err := SaveSettings(path, Settings{RobotUser: "second"}); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadSettings(path)
	if err != nil || reloaded.RobotUser != "second" {
		t.Fatalf("atomic replacement failed: %+v %v", reloaded, err)
	}
}

func TestSettingsEncryptedFileTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.enc")
	if err := SaveSettings(path, Settings{CloudToken: "token"}); err != nil { t.Fatal(err) }
	data, err := os.ReadFile(path)
	if err != nil {t.Fatal(err)}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {t.Fatal(err)}
	if _, err := LoadSettings(path); err == nil {
		t.Fatal("tampering should fail authentication")
	}
}

func TestMergeSettings(t *testing.T) {
	base := Config{HetznerUser:"env-user",HetznerPassword:"env-password",SelectelToken:"env-iam-token"}
	ssh := SSHOptions{User:"root", Port:22}
	cfg, opts, interval, err := MergeSettings(base, ssh, time.Minute, Settings{
		RobotUser:"new-user",RobotPassword:"new-password",
		SelectelAccount:"0123", SelectelUser:"bot",SelectelPassword:"iam-password",
		SSHUser:"inventory",SSHPort:2222,PollSeconds:300,
	})
	if err != nil { t.Fatal(err) }
	if cfg.HetznerUser != "new-user" || cfg.HetznerPassword != "new-password" || cfg.SelectelToken != "" || cfg.SelectelPassword != "iam-password" {
		t.Fatalf("provider settings not applied: %+v", cfg)
	}
	if opts.User != "inventory" || opts.Port != 2222 || interval != 5*time.Minute {
		t.Fatalf("ssh settings not applied: %+v %v", opts, interval)
	}
}
