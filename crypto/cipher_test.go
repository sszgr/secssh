package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptAESGCM(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	nonce := bytes.Repeat([]byte{2}, 12)
	plain := []byte("hello-world")
	aad := []byte("aad")

	ct, err := Encrypt("aes-256-gcm", key, nonce, plain, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	pt, err := Decrypt("aes-256-gcm", key, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestEncryptDecryptXChaCha20(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	nonce := bytes.Repeat([]byte{4}, 24)
	plain := []byte("hello-world")

	ct, err := Encrypt("xchacha20-poly1305", key, nonce, plain, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	pt, err := Decrypt("xchacha20-poly1305", key, nonce, ct, nil)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestNonceSizeAndErrors(t *testing.T) {
	n, err := NonceSize("aes-256-gcm")
	if err != nil || n != 12 {
		t.Fatalf("unexpected aes nonce size: n=%d err=%v", n, err)
	}
	n, err = NonceSize("xchacha20-poly1305")
	if err != nil || n != 24 {
		t.Fatalf("unexpected xchacha nonce size: n=%d err=%v", n, err)
	}
	if _, err := NonceSize("bad"); err == nil {
		t.Fatalf("expected unsupported cipher error")
	}
	if _, err := Encrypt("aes-256-gcm", bytes.Repeat([]byte{1}, 31), bytes.Repeat([]byte{2}, 12), []byte("x"), nil); err == nil {
		t.Fatalf("expected invalid key length error")
	}
	if _, err := Encrypt("aes-256-gcm", bytes.Repeat([]byte{1}, 32), []byte{1}, []byte("x"), nil); err == nil {
		t.Fatalf("expected invalid nonce length error")
	}
}
