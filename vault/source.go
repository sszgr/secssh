package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Source struct {
	Input    string
	Path     string
	ReadOnly bool
}

func ResolveSource(input string) (*Source, error) {
	if strings.TrimSpace(input) == "" {
		path, err := DefaultPath()
		if err != nil {
			return nil, err
		}
		return &Source{
			Input: path,
			Path:  path,
		}, nil
	}

	if isRemoteURL(input) {
		path, err := downloadRemoteVault(input)
		if err != nil {
			return nil, err
		}
		return &Source{
			Input:    input,
			Path:     path,
			ReadOnly: true,
		}, nil
	}

	return &Source{
		Input: input,
		Path:  input,
	}, nil
}

func isRemoteURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func downloadRemoteVault(rawURL string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download remote vault failed: http %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if len(body) == 0 {
		return "", fmt.Errorf("download remote vault failed: empty response body")
	}

	sum := sha256.Sum256([]byte(rawURL))
	name := hex.EncodeToString(sum[:]) + "-" + DefaultFileName
	path := filepath.Join(os.TempDir(), "secssh", "remote-vaults", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return "", err
	}
	return path, nil
}
