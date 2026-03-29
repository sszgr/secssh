package vault

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestResolveSourceDefaultPath(t *testing.T) {
	src, err := ResolveSource("")
	if err != nil {
		t.Fatalf("ResolveSource failed: %v", err)
	}
	if src.Path == "" || src.Input == "" {
		t.Fatalf("expected non-empty source path")
	}
	if src.ReadOnly {
		t.Fatalf("default source should be writable")
	}
}

func TestResolveSourceRemoteURL(t *testing.T) {
	dir := t.TempDir()
	vaultPath := dir + "/vault.enc"
	pw := []byte("secret")
	if err := Initialize(vaultPath, pw); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	raw, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	src, err := ResolveSource(srv.URL + "/vault.enc")
	if err != nil {
		t.Fatalf("ResolveSource failed: %v", err)
	}
	if !src.ReadOnly {
		t.Fatalf("remote source should be read-only")
	}
	if !strings.Contains(src.Path, "remote-vaults") {
		t.Fatalf("expected cached remote vault path, got %s", src.Path)
	}
	if _, _, err := Load(src.Path, pw); err != nil {
		t.Fatalf("cached remote vault should be loadable: %v", err)
	}
}
