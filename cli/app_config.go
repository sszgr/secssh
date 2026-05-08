package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sszgr/secssh/vault"
)

type appConfig struct {
	REPLPrefix string
}

func defaultAppConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, vault.DefaultDirName, "config"), nil
}

func loadAppConfig(path string, required bool) (appConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !required {
			return appConfig{}, nil
		}
		return appConfig{}, err
	}
	return parseAppConfig(string(raw))
}

func parseAppConfig(raw string) (appConfig, error) {
	var cfg appConfig
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return appConfig{}, fmt.Errorf("invalid config line %d: expected key=value", lineNo)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "prefix":
			cfg.REPLPrefix = value
		default:
			return appConfig{}, fmt.Errorf("invalid config line %d: unknown key %q", lineNo, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return appConfig{}, err
	}
	return cfg, nil
}
