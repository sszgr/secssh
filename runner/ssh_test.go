package runner

import (
	"testing"
	"time"

	"github.com/sszgr/secssh/vault"
	"github.com/sszgr/secssh/workspace"
)

func TestResolvePasswordSessionUsesCache(t *testing.T) {
	workspace.ClearPasswordCache()
	opts := Options{Target: "prod", SessionExp: time.Now().Add(1 * time.Minute).Unix()}
	cfg := vault.HostAuth{PasswordPolicy: "session", PasswordRef: "pwd-prod"}
	workspace.PutCachedPassword(sessionCacheKey(opts, cfg), "cached-secret", time.Now().Add(time.Minute))

	pw, err := resolvePassword(opts, cfg, &vault.Payload{Secrets: map[string]string{}})
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
	pw, err := resolvePassword(opts, cfg, &vault.Payload{Secrets: map[string]string{"pwd-prod": "s3cr3t"}})
	if err != nil {
		t.Fatalf("resolvePassword returned error: %v", err)
	}
	if pw != "s3cr3t" {
		t.Fatalf("expected stored secret, got %q", pw)
	}
}
