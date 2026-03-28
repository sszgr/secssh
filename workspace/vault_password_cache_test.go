package workspace

import (
	"testing"
	"time"
)

func TestVaultPasswordCache(t *testing.T) {
	ClearVaultPasswords()
	now := time.Now()
	PutVaultPassword("/tmp/v.enc", []byte("pw"), now.Add(2*time.Second))

	pw, ok := GetVaultPassword("/tmp/v.enc", now)
	if !ok || string(pw) != "pw" {
		t.Fatalf("expected cache hit")
	}

	_, ok = GetVaultPassword("/tmp/v.enc", now.Add(3*time.Second))
	if ok {
		t.Fatalf("expected cache miss after expiry")
	}
}
