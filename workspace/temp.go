package workspace

import (
	"os"
	"path/filepath"
)

func RuntimeRoot() string {
	return filepath.Join(os.TempDir(), "secssh", "runtime")
}

func EnsureRuntimeRoot() error {
	return os.MkdirAll(RuntimeRoot(), 0o700)
}

func CleanupRuntimeArtifacts() {
	root := RuntimeRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, ent := range entries {
		if ent.IsDir() {
			_ = os.RemoveAll(filepath.Join(root, ent.Name()))
		}
	}
}
