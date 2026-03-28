package workspace

import (
	"os"
	"testing"
)

func TestEnsureRuntimeRoot(t *testing.T) {
	if err := EnsureRuntimeRoot(); err != nil {
		t.Fatalf("EnsureRuntimeRoot failed: %v", err)
	}
	st, err := os.Stat(RuntimeRoot())
	if err != nil {
		t.Fatalf("stat runtime root failed: %v", err)
	}
	if !st.IsDir() {
		t.Fatalf("runtime root is not directory")
	}
}
