package cli

import (
	"testing"

	"github.com/sszgr/secssh/vault"
)

func TestRecordHostConnection(t *testing.T) {
	p := vault.NewEmptyPayload()
	recordHostConnection(p, "prod", "key")
	recordHostConnection(p, "prod", "password")

	h, ok := p.Connections["prod"]
	if !ok {
		t.Fatalf("expected host connection history")
	}
	if h.ConnectCount != 2 {
		t.Fatalf("expected count=2 got=%d", h.ConnectCount)
	}
	if h.LastAuthMode != "password" {
		t.Fatalf("expected last auth mode password got=%s", h.LastAuthMode)
	}
	if h.LastConnectedAt == "" {
		t.Fatalf("expected last connected timestamp")
	}
}

func TestResolveAuthModeForRecord(t *testing.T) {
	p := vault.NewEmptyPayload()
	p.Hosts["prod"] = vault.HostAuth{Mode: "key"}

	if got := resolveAuthModeForRecord(p, "prod", "password"); got != "password" {
		t.Fatalf("override should win, got=%s", got)
	}
	if got := resolveAuthModeForRecord(p, "prod", ""); got != "key" {
		t.Fatalf("host policy should apply, got=%s", got)
	}
	if got := resolveAuthModeForRecord(p, "unknown", ""); got != "auto" {
		t.Fatalf("default should be auto, got=%s", got)
	}
}
