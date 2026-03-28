package runner

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/sszgr/secssh/vault"
	"github.com/sszgr/secssh/workspace"
	"golang.org/x/term"
)

func RunSSH(opts Options) error {
	if opts.Vault == nil {
		return errors.New("vault payload is required")
	}
	if strings.TrimSpace(opts.Target) == "" {
		return errors.New("target is required")
	}

	workspace.CleanupRuntimeArtifacts()
	if err := workspace.EnsureRuntimeRoot(); err != nil {
		return err
	}

	runDir, err := os.MkdirTemp(workspace.RuntimeRoot(), "run-")
	if err != nil {
		return err
	}
	if err := os.Chmod(runDir, 0o700); err != nil {
		_ = os.RemoveAll(runDir)
		return err
	}
	defer os.RemoveAll(runDir)

	rendered, err := renderConfig(opts.Vault.SSHConfig, opts.Vault.Keys, runDir)
	if err != nil {
		return err
	}

	authCfg, password, err := resolveAuth(opts, opts.Vault)
	if err != nil {
		return err
	}
	if authCfg != "" {
		rendered += "\n" + authCfg
	}

	configPath := filepath.Join(runDir, "ssh_config")
	if err := os.WriteFile(configPath, []byte(rendered), 0o600); err != nil {
		return err
	}

	args, env, useAskPass := buildSSHInvocation(configPath, opts.Target, opts.PassArgs, password, filepath.Join(runDir, "askpass.sh"), os.Environ())
	if useAskPass {
		script := "#!/bin/sh\nprintf '%s' \"$SECSSH_SSH_PASSWORD\"\n"
		if err := os.WriteFile(filepath.Join(runDir, "askpass.sh"), []byte(script), 0o700); err != nil {
			return err
		}
	}
	cmd := exec.Command("ssh", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = env
	if useAskPass {
		cmd.Stdin = nil
	}

	signal.Ignore(os.Interrupt)
	defer signal.Reset(os.Interrupt)

	return cmd.Run()
}

func buildSSHInvocation(configPath, target string, passArgs []string, password, askpassPath string, baseEnv []string) (args []string, env []string, useAskPass bool) {
	args = append([]string{"-F", configPath, target}, passArgs...)
	env = append([]string{}, baseEnv...)
	if password == "" {
		return args, env, false
	}
	env = append(env,
		"SSH_ASKPASS="+askpassPath,
		"SSH_ASKPASS_REQUIRE=force",
		"DISPLAY=secssh:0",
		"SECSSH_SSH_PASSWORD="+password,
	)
	return args, env, true
}

func renderConfig(src string, keys map[string][]byte, runDir string) (string, error) {
	var out strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(src))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		replaced, err := rewriteIdentityFile(line, keys, runDir)
		if err != nil {
			return "", fmt.Errorf("line %d: %w", lineNo, err)
		}
		out.WriteString(replaced)
		out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return out.String(), nil
}

func rewriteIdentityFile(line string, keys map[string][]byte, runDir string) (string, error) {
	trim := strings.TrimSpace(line)
	if trim == "" || strings.HasPrefix(trim, "#") {
		return line, nil
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "IdentityFile") {
		return line, nil
	}
	ref := strings.Trim(fields[len(fields)-1], "\"'")
	if !strings.HasPrefix(ref, "secssh://keys/") {
		return line, nil
	}
	name := strings.TrimPrefix(ref, "secssh://keys/")
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("empty key reference")
	}
	k, ok := keys[name]
	if !ok {
		return "", fmt.Errorf("missing key %q in vault", name)
	}
	keyDir := filepath.Join(runDir, "keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return "", err
	}
	keyPath := filepath.Join(keyDir, sanitizeFileName(name))
	if err := os.WriteFile(keyPath, k, 0o600); err != nil {
		return "", err
	}
	// Preserve original indentation and replace only the value token.
	idx := strings.LastIndex(line, fields[len(fields)-1])
	if idx < 0 {
		return fmt.Sprintf("IdentityFile %s", keyPath), nil
	}
	return line[:idx] + keyPath, nil
}

func resolveAuth(opts Options, payload *vault.Payload) (extraConfig string, password string, err error) {
	hostCfg := payload.Hosts[opts.Target]
	mode := strings.TrimSpace(hostCfg.Mode)
	if opts.AuthMode != "" {
		mode = opts.AuthMode
	}
	if mode == "" {
		mode = "auto"
	}
	if mode == "ask" {
		mode, err = promptAuthMode()
		if err != nil {
			return "", "", err
		}
	}

	switch mode {
	case "key":
		return fmt.Sprintf("Host %s\n  PubkeyAuthentication yes\n  PasswordAuthentication no\n  KbdInteractiveAuthentication no\n", opts.Target), "", nil
	case "auto":
		return "", "", nil
	case "password":
		pw, err := resolvePassword(opts, hostCfg, payload)
		if err != nil {
			return "", "", err
		}
		cfg := fmt.Sprintf("Host %s\n  PubkeyAuthentication no\n  PasswordAuthentication yes\n  KbdInteractiveAuthentication yes\n  PreferredAuthentications keyboard-interactive,password\n", opts.Target)
		return cfg, pw, nil
	default:
		return "", "", fmt.Errorf("unsupported auth mode: %s", mode)
	}
}

func resolvePassword(opts Options, cfg vault.HostAuth, payload *vault.Payload) (string, error) {
	if opts.Prompt {
		return promptSecret("SSH password: ")
	}
	if opts.UseSecret != "" {
		v, ok := payload.Secrets[opts.UseSecret]
		if !ok {
			return "", fmt.Errorf("secret not found: %s", opts.UseSecret)
		}
		return v, nil
	}
	policy := strings.TrimSpace(cfg.PasswordPolicy)
	if policy == "" {
		policy = "prompt"
	}
	switch policy {
	case "prompt":
		return promptSecret("SSH password: ")
	case "session":
		cacheKey := sessionCacheKey(opts, cfg)
		now := time.Now()
		if v, ok := workspace.GetCachedPassword(cacheKey, now); ok {
			return v, nil
		}
		pw, err := promptSecret("SSH password: ")
		if err != nil {
			return "", err
		}
		exp := time.Unix(opts.SessionExp, 0)
		if opts.SessionExp <= 0 {
			exp = now.Add(10 * time.Minute)
		}
		workspace.PutCachedPassword(cacheKey, pw, exp)
		return pw, nil
	case "stored":
		if strings.TrimSpace(cfg.PasswordRef) == "" {
			return "", errors.New("password_ref is required for stored policy")
		}
		v, ok := payload.Secrets[cfg.PasswordRef]
		if !ok {
			return "", fmt.Errorf("secret not found: %s", cfg.PasswordRef)
		}
		return v, nil
	default:
		return "", fmt.Errorf("unsupported password policy: %s", policy)
	}
}

func sessionCacheKey(opts Options, cfg vault.HostAuth) string {
	ref := strings.TrimSpace(cfg.PasswordRef)
	if ref == "" {
		ref = opts.Target
	}
	return "host=" + opts.Target + ";ref=" + ref
}

func promptAuthMode() (string, error) {
	fmt.Fprintln(os.Stdout, "Select auth mode: [1] key [2] password")
	v, err := promptLine("mode> ")
	if err != nil {
		return "", err
	}
	switch strings.TrimSpace(v) {
	case "1", "key":
		return "key", nil
	case "2", "password":
		return "password", nil
	default:
		return "", errors.New("invalid selection")
	}
}

func promptLine(prompt string) (string, error) {
	fmt.Fprint(os.Stdout, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func promptSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stdout, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stdout)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(pw)), nil
	}
	return promptLine("")
}

func sanitizeFileName(name string) string {
	name = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, name)
	if name == "" {
		return fmt.Sprintf("key-%d", time.Now().UnixNano())
	}
	return name
}
