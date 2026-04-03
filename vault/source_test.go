package vault

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveSourceDefaultPathFallsBackToHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	wd := t.TempDir()
	t.Chdir(wd)

	src, err := ResolveSource("")
	if err != nil {
		t.Fatalf("ResolveSource failed: %v", err)
	}
	want := filepath.Join(home, DefaultDirName, DefaultFileName)
	if src.Path != want || src.Input != want {
		t.Fatalf("expected fallback path %s, got path=%s input=%s", want, src.Path, src.Input)
	}
	if src.ReadOnly {
		t.Fatalf("default source should be writable")
	}
}

func TestResolveSourceDefaultPathPrefersCurrentDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	wd := t.TempDir()
	t.Chdir(wd)

	localVault := filepath.Join(wd, DefaultFileName)
	if err := Initialize(localVault, []byte("secret")); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	src, err := ResolveSource("")
	if err != nil {
		t.Fatalf("ResolveSource failed: %v", err)
	}
	if src.Path != localVault || src.Input != localVault {
		t.Fatalf("expected current directory path %s, got path=%s input=%s", localVault, src.Path, src.Input)
	}
	if src.ReadOnly {
		t.Fatalf("default source should be writable")
	}
}

func TestResolveSourceDefaultPathRejectsInvalidCurrentDirFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	wd := t.TempDir()
	t.Chdir(wd)

	localVault := filepath.Join(wd, DefaultFileName)
	if err := os.WriteFile(localVault, nil, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err := ResolveSource("")
	if err == nil {
		t.Fatalf("expected invalid current directory vault to fail")
	}
	if !strings.Contains(err.Error(), "invalid vault file") || !strings.Contains(err.Error(), "vault file too small") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveSourceExplicitPathRejectsInvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.enc")
	if err := os.WriteFile(path, []byte("not-a-vault"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err := ResolveSource(path)
	if err == nil {
		t.Fatalf("expected invalid explicit vault path to fail")
	}
	if !strings.Contains(err.Error(), "invalid vault file") {
		t.Fatalf("unexpected error: %v", err)
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
