package sshkey

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func GeneratePair(keyType string, bits int, comment string) (privateKey []byte, publicKey []byte, err error) {
	keyType = strings.TrimSpace(strings.ToLower(keyType))
	if keyType == "" {
		keyType = "ed25519"
	}
	switch keyType {
	case "ed25519", "rsa":
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
	if keyType == "rsa" && bits <= 0 {
		bits = 4096
	}

	tmpDir, err := os.MkdirTemp("", "secssh-keygen-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "id_key")
	args := []string{"-q", "-t", keyType, "-f", keyPath, "-N", ""}
	if keyType == "rsa" {
		args = append(args, "-b", strconv.Itoa(bits))
	}
	if strings.TrimSpace(comment) != "" {
		args = append(args, "-C", comment)
	}

	cmd := exec.Command("ssh-keygen", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("ssh-keygen failed: %v: %s", err, strings.TrimSpace(string(out)))
	}

	privateKey, err = os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err = os.ReadFile(keyPath + ".pub")
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}
