package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderConfigRewritesIdentityFile(t *testing.T) {
	runDir := t.TempDir()
	cfg := "Host prod\n  IdentityFile secssh://keys/prod\n  User root\n"
	keys := map[string][]byte{"prod": []byte("KEY_DATA")}

	rendered, err := renderConfig(cfg, keys, runDir)
	if err != nil {
		t.Fatalf("renderConfig failed: %v", err)
	}
	if strings.Contains(rendered, "secssh://keys/prod") {
		t.Fatalf("expected identity file reference replaced")
	}

	keyPath := filepath.Join(runDir, "keys", "prod")
	b, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("expected key file written: %v", err)
	}
	if string(b) != "KEY_DATA" {
		t.Fatalf("unexpected key data: %q", string(b))
	}
	st, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file failed: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected key file mode: %o", st.Mode().Perm())
	}
}

func TestRenderConfigMissingKey(t *testing.T) {
	_, err := renderConfig("IdentityFile secssh://keys/missing\n", map[string][]byte{}, t.TempDir())
	if err == nil {
		t.Fatalf("expected missing key error")
	}
}

func TestRenderConfigRewritesQuotedIdentityFile(t *testing.T) {
	runDir := t.TempDir()
	cfg := "Host prod\n  IdentityFile \"secssh://keys/prod\"\n"
	keys := map[string][]byte{"prod": []byte("KEY_DATA")}

	rendered, err := renderConfig(cfg, keys, runDir)
	if err != nil {
		t.Fatalf("renderConfig failed: %v", err)
	}
	if strings.Contains(rendered, "secssh://keys/prod") {
		t.Fatalf("expected quoted identity file reference replaced")
	}
}
