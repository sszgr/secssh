package vault

import (
	"path/filepath"
	"testing"
)

func TestVaultLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")
	pw := []byte("master-1")

	if err := Initialize(path, pw); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	h, p, err := Load(path, pw)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if h.KDFType == "" || h.CipherType == "" {
		t.Fatalf("expected header crypto fields")
	}

	p.SSHConfig = "Host prod\n  HostName 10.0.0.1\n"
	p.Keys["prod"] = []byte("PRIVATE_KEY")
	p.Secrets["pwd-prod"] = "s3cr3t"
	params := h.KDFParams
	if err := Save(path, pw, p, SaveOptions{KDFType: h.KDFType, CipherType: h.CipherType, KDFParams: &params}); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	_, p2, err := Load(path, pw)
	if err != nil {
		t.Fatalf("Load after Save failed: %v", err)
	}
	if p2.SSHConfig == "" || string(p2.Keys["prod"]) != "PRIVATE_KEY" || p2.Secrets["pwd-prod"] != "s3cr3t" {
		t.Fatalf("payload mismatch after roundtrip")
	}
}

func TestChangePasswordAndCrypto(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")
	oldPW := []byte("old-master")
	newPW := []byte("new-master")

	if err := Initialize(path, oldPW); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	_, p, err := Load(path, oldPW)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	p.Secrets["a"] = "b"
	if err := Save(path, oldPW, p, SaveOptions{KDFType: "argon2id", CipherType: "aes-256-gcm"}); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if err := ChangePassword(path, oldPW, newPW); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}
	if _, _, err := Load(path, oldPW); err == nil {
		t.Fatalf("expected old password to fail")
	}
	if _, _, err := Load(path, newPW); err != nil {
		t.Fatalf("expected new password to pass: %v", err)
	}

	if err := ChangeCrypto(path, newPW, "pbkdf2-sha256", "xchacha20-poly1305"); err != nil {
		t.Fatalf("ChangeCrypto failed: %v", err)
	}
	h, _, err := Load(path, newPW)
	if err != nil {
		t.Fatalf("Load after ChangeCrypto failed: %v", err)
	}
	if h.KDFType != "pbkdf2-sha256" || h.CipherType != "xchacha20-poly1305" {
		t.Fatalf("unexpected crypto settings: kdf=%s cipher=%s", h.KDFType, h.CipherType)
	}
}
