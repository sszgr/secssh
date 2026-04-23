package runner

import (
	"reflect"
	"testing"
	"time"

	"github.com/sszgr/secssh/vault"
	"github.com/sszgr/secssh/workspace"
)

func TestResolvePasswordSessionUsesCache(t *testing.T) {
	workspace.ClearPasswordCache()
	opts := Options{Target: "prod", SessionExp: time.Now().Add(1 * time.Minute).Unix()}
	cfg := vault.HostAuth{PasswordPolicy: "session", PasswordRef: "pwd-prod"}
	workspace.PutCachedPassword(sessionCacheKey("prod", opts, cfg), "cached-secret", time.Now().Add(time.Minute))

	pw, err := resolvePassword(opts, "prod", cfg, &vault.Payload{Secrets: map[string]string{}})
	if err != nil {
		t.Fatalf("resolvePassword returned error: %v", err)
	}
	if pw != "cached-secret" {
		t.Fatalf("expected cached password, got %q", pw)
	}
}

func TestResolvePasswordStored(t *testing.T) {
	opts := Options{Target: "prod"}
	cfg := vault.HostAuth{PasswordPolicy: "stored", PasswordRef: "pwd-prod"}
	pw, err := resolvePassword(opts, "prod", cfg, &vault.Payload{Secrets: map[string]string{"pwd-prod": "s3cr3t"}})
	if err != nil {
		t.Fatalf("resolvePassword returned error: %v", err)
	}
	if pw != "s3cr3t" {
		t.Fatalf("expected stored secret, got %q", pw)
	}
}

func TestResolveAuthArgsPasswordByUserAtAlias(t *testing.T) {
	args, pw, err := resolveAuthArgs(
		Options{Target: "root@prod"},
		&vault.Payload{
			Hosts:    map[string]vault.HostAuth{"prod": {Mode: "password", PasswordPolicy: "stored", PasswordRef: "pwd-prod"}},
			Machines: map[string]vault.HostMachine{"prod": {HostName: "10.0.0.10"}},
			Secrets:  map[string]string{"pwd-prod": "s3cr3t"},
		},
	)
	if err != nil {
		t.Fatalf("resolveAuthArgs returned error: %v", err)
	}
	if len(args) == 0 || pw != "s3cr3t" {
		t.Fatalf("expected password auth args and stored secret, got args=%v pw=%q", args, pw)
	}
}

func TestResolveAuthArgsPasswordByManagedHostName(t *testing.T) {
	args, pw, err := resolveAuthArgs(
		Options{Target: "10.0.0.10"},
		&vault.Payload{
			Hosts:    map[string]vault.HostAuth{"prod": {Mode: "password", PasswordPolicy: "stored", PasswordRef: "pwd-prod"}},
			Machines: map[string]vault.HostMachine{"prod": {HostName: "10.0.0.10"}},
			Secrets:  map[string]string{"pwd-prod": "s3cr3t"},
		},
	)
	if err != nil {
		t.Fatalf("resolveAuthArgs returned error: %v", err)
	}
	if len(args) == 0 || pw != "s3cr3t" {
		t.Fatalf("expected password auth args and stored secret, got args=%v pw=%q", args, pw)
	}
}

func TestResolveAuthArgsPassword(t *testing.T) {
	args, pw, err := resolveAuthArgs(
		Options{Target: "prod"},
		&vault.Payload{
			Hosts:   map[string]vault.HostAuth{"prod": {Mode: "password", PasswordPolicy: "stored", PasswordRef: "pwd-prod"}},
			Secrets: map[string]string{"pwd-prod": "s3cr3t"},
		},
	)
	if err != nil {
		t.Fatalf("resolveAuthArgs returned error: %v", err)
	}
	wantArgs := []string{
		"-o", "PubkeyAuthentication=no",
		"-o", "PasswordAuthentication=yes",
		"-o", "KbdInteractiveAuthentication=yes",
		"-o", "PreferredAuthentications=keyboard-interactive,password",
	}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("unexpected auth args: got=%v want=%v", args, wantArgs)
	}
	if pw != "s3cr3t" {
		t.Fatalf("expected stored secret, got %q", pw)
	}
}
