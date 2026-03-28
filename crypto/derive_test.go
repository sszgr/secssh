package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKeyArgon2idDeterministic(t *testing.T) {
	params := KDFParams{Salt: []byte("1234567890abcdef"), Memory: 32 * 1024, Iterations: 2, Parallelism: 1, KeyLen: 32}
	k1, err := DeriveKey([]byte("pw"), "argon2id", params)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	k2, err := DeriveKey([]byte("pw"), "argon2id", params)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatalf("expected deterministic derivation")
	}
	if len(k1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(k1))
	}
}

func TestDeriveKeyPBKDF2Deterministic(t *testing.T) {
	params := KDFParams{Salt: []byte("1234567890abcdef"), Iterations: 1000, KeyLen: 32}
	k1, err := DeriveKey([]byte("pw"), "pbkdf2-sha256", params)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	k2, err := DeriveKey([]byte("pw"), "pbkdf2-sha256", params)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatalf("expected deterministic derivation")
	}
}

func TestDeriveKeyErrors(t *testing.T) {
	if _, err := DeriveKey([]byte("pw"), "argon2id", KDFParams{}); err == nil {
		t.Fatalf("expected error for missing salt")
	}
	if _, err := DeriveKey([]byte("pw"), "unknown", KDFParams{Salt: []byte("x")}); err == nil {
		t.Fatalf("expected error for unsupported kdf")
	}
}
