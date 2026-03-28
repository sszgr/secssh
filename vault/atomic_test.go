package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteCreatesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")

	if err := atomicWrite(path, []byte("v1"), 0o600); err != nil {
		t.Fatalf("atomicWrite(create) failed: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(b) != "v1" {
		t.Fatalf("unexpected content: %q", string(b))
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected mode: %o", st.Mode().Perm())
	}

	if err := atomicWrite(path, []byte("v2"), 0o600); err != nil {
		t.Fatalf("atomicWrite(replace) failed: %v", err)
	}
	b, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(b) != "v2" {
		t.Fatalf("unexpected replaced content: %q", string(b))
	}
}

func TestAtomicWriteInvalidDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "vault.enc")
	if err := atomicWrite(path, []byte("x"), 0o600); err == nil {
		t.Fatalf("expected error for missing parent dir")
	}
}
