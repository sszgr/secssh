package vault

import (
	"os"
	"path/filepath"
)

const (
	DefaultDirName  = ".secssh"
	DefaultFileName = "vault.enc"
)

func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, DefaultDirName, DefaultFileName), nil
}

func CurrentDirPath() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, DefaultFileName), nil
}
