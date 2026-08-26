package vault

import (
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/sszgr/secssh/crypto"
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

func TestParseFileRejectsUnsafeHeaderBeforeKeyDerivation(t *testing.T) {
	header := FileHeader{
		Version:    FileVersion,
		KDFType:    "argon2id",
		KDFParams:  crypto.KDFParams{Salt: []byte("1234567890abcdef"), Memory: crypto.MaxArgon2MemoryKiB + 1, Iterations: 1, Parallelism: 1, KeyLen: 32},
		CipherType: "aes-256-gcm",
		Nonce:      make([]byte, 12),
	}
	raw, err := packFile(&header, []byte("ciphertext"))
	if err != nil {
		t.Fatalf("packFile failed: %v", err)
	}
	if _, _, err := parseFile(raw); err == nil {
		t.Fatal("expected unsafe KDF parameters to be rejected")
	}
}

func TestParseFileRejectsOversizedHeader(t *testing.T) {
	raw := make([]byte, len(FileMagic)+4+1)
	copy(raw, FileMagic)
	binary.BigEndian.PutUint32(raw[len(FileMagic):], maxFileHeaderSize+1)
	if _, _, err := parseFile(raw); err == nil {
		t.Fatal("expected oversized header to be rejected")
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
