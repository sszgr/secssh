package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sszgr/secssh/vault"
	"github.com/sszgr/secssh/workspace"
)

func TestParseVaultArg(t *testing.T) {
	args, source, err := parseVaultArg([]string{"--vault", "https://example.com/vault.enc", "status"})
	if err != nil {
		t.Fatalf("parseVaultArg failed: %v", err)
	}
	if source != "https://example.com/vault.enc" {
		t.Fatalf("unexpected source: %s", source)
	}
	if !reflect.DeepEqual(args, []string{"status"}) {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestParseVaultArgEqualsForm(t *testing.T) {
	args, source, err := parseVaultArg([]string{"--vault=/tmp/vault.enc", "status"})
	if err != nil {
		t.Fatalf("parseVaultArg failed: %v", err)
	}
	if source != "/tmp/vault.enc" {
		t.Fatalf("unexpected source: %s", source)
	}
	if !reflect.DeepEqual(args, []string{"status"}) {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestParseGlobalArgsPrefix(t *testing.T) {
	args, opts, err := parseGlobalArgs([]string{"--prefix", ".", "--vault=/tmp/vault.enc", "env"})
	if err != nil {
		t.Fatalf("parseGlobalArgs failed: %v", err)
	}
	if opts.VaultSource != "/tmp/vault.enc" {
		t.Fatalf("unexpected vault source: %q", opts.VaultSource)
	}
	if opts.REPLPrefix != "." {
		t.Fatalf("unexpected repl prefix: %q", opts.REPLPrefix)
	}
	if !reflect.DeepEqual(args, []string{"env"}) {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestParseGlobalArgsPrefixFromConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("prefix=.\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, opts, err := parseGlobalArgs([]string{"--config", path, "env"})
	if err != nil {
		t.Fatalf("parseGlobalArgs failed: %v", err)
	}
	if opts.ConfigPath != path {
		t.Fatalf("unexpected config path: %q", opts.ConfigPath)
	}
	if opts.REPLPrefix != "." {
		t.Fatalf("unexpected repl prefix: %q", opts.REPLPrefix)
	}
}

func TestParseGlobalArgsConfigFromEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("prefix=.\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("SECSSH_CONFIG", path)

	_, opts, err := parseGlobalArgs([]string{"env"})
	if err != nil {
		t.Fatalf("parseGlobalArgs failed: %v", err)
	}
	if opts.ConfigPath != path {
		t.Fatalf("unexpected config path: %q", opts.ConfigPath)
	}
	if opts.REPLPrefix != "." {
		t.Fatalf("unexpected repl prefix: %q", opts.REPLPrefix)
	}
}

func TestParseGlobalArgsExplicitMissingConfigFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	if _, _, err := parseGlobalArgs([]string{"--config", path, "env"}); err == nil {
		t.Fatalf("expected missing explicit config to fail")
	}
}

func TestParseGlobalArgsPrefixPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("prefix=,\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("SECSSH_PREFIX", ".")

	_, opts, err := parseGlobalArgs([]string{"--config", path, "--prefix", ";", "env"})
	if err != nil {
		t.Fatalf("parseGlobalArgs failed: %v", err)
	}
	if opts.REPLPrefix != ";" {
		t.Fatalf("unexpected repl prefix: %q", opts.REPLPrefix)
	}
}

func TestParseGlobalArgsPrefixFromEnv(t *testing.T) {
	t.Setenv("SECSSH_PREFIX", ".")
	_, opts, err := parseGlobalArgs([]string{"env"})
	if err != nil {
		t.Fatalf("parseGlobalArgs failed: %v", err)
	}
	if opts.REPLPrefix != "." {
		t.Fatalf("unexpected repl prefix: %q", opts.REPLPrefix)
	}
}

func TestParseGlobalArgsRejectsInvalidPrefix(t *testing.T) {
	if _, _, err := parseGlobalArgs([]string{"--prefix", "cmd"}); err == nil {
		t.Fatalf("expected multi-character prefix to fail")
	}
	if _, _, err := parseGlobalArgs([]string{"--prefix", " "}); err == nil {
		t.Fatalf("expected whitespace prefix to fail")
	}
}

func TestParseAppConfig(t *testing.T) {
	cfg, err := parseAppConfig("# secssh\nprefix=.\n")
	if err != nil {
		t.Fatalf("parseAppConfig failed: %v", err)
	}
	if cfg.REPLPrefix != "." {
		t.Fatalf("unexpected prefix: %q", cfg.REPLPrefix)
	}
}

func TestSplitSSHArgsOnlyRunnerFlags(t *testing.T) {
	runnerArgs, passArgs := splitTransportArgs([]string{"--auth", "password", "--prompt"})
	wantRunner := []string{"--auth", "password", "--prompt"}
	if !reflect.DeepEqual(runnerArgs, wantRunner) {
		t.Fatalf("unexpected runner args: got=%v want=%v", runnerArgs, wantRunner)
	}
	if passArgs != nil {
		t.Fatalf("expected nil pass args, got=%v", passArgs)
	}
}

func TestSplitSSHArgsWithPassthrough(t *testing.T) {
	runnerArgs, passArgs := splitTransportArgs([]string{"--auth", "key", "--", "-p", "2222", "-o", "StrictHostKeyChecking=no"})
	wantRunner := []string{"--auth", "key"}
	wantPass := []string{"-p", "2222", "-o", "StrictHostKeyChecking=no"}

	if !reflect.DeepEqual(runnerArgs, wantRunner) {
		t.Fatalf("unexpected runner args: got=%v want=%v", runnerArgs, wantRunner)
	}
	if !reflect.DeepEqual(passArgs, wantPass) {
		t.Fatalf("unexpected pass args: got=%v want=%v", passArgs, wantPass)
	}
}

func TestSplitSSHArgsLeadingPassthroughSeparator(t *testing.T) {
	runnerArgs, passArgs := splitTransportArgs([]string{"--", "-vvv"})
	if len(runnerArgs) != 0 {
		t.Fatalf("expected no runner args, got=%v", runnerArgs)
	}
	wantPass := []string{"-vvv"}
	if !reflect.DeepEqual(passArgs, wantPass) {
		t.Fatalf("unexpected pass args: got=%v want=%v", passArgs, wantPass)
	}
}

func TestParseTransportArgsInterspersedFlags(t *testing.T) {
	parsed, err := parseTransportArgs([]string{"src.txt", "--auth", "password", "--prompt", "prod:/tmp/dst.txt", "--", "-P", "2222"}, 2)
	if err != nil {
		t.Fatalf("parseTransportArgs failed: %v", err)
	}
	if !reflect.DeepEqual(parsed.Targets, []string{"src.txt", "prod:/tmp/dst.txt"}) {
		t.Fatalf("unexpected targets: %v", parsed.Targets)
	}
	if parsed.AuthMode != "password" || !parsed.Prompt {
		t.Fatalf("unexpected auth flags: %+v", parsed)
	}
	if !reflect.DeepEqual(parsed.PassArgs, []string{"-P", "2222"}) {
		t.Fatalf("unexpected pass args: %v", parsed.PassArgs)
	}
}

func TestResolveSCPRemoteTarget(t *testing.T) {
	target, err := resolveSCPRemoteTarget("local.txt", "root@prod:/tmp/remote.txt")
	if err != nil {
		t.Fatalf("resolveSCPRemoteTarget failed: %v", err)
	}
	if target != "prod" {
		t.Fatalf("unexpected target: %s", target)
	}
}

func TestMergeManagedHostsConfigIncludesKeyRef(t *testing.T) {
	cfg := mergeManagedHostsConfig("", map[string]vault.HostMachine{
		"prod": {HostName: "10.0.0.10", User: "root", Port: 22, KeyRef: "prod-key"},
	})

	if !strings.Contains(cfg, "IdentityFile secssh://keys/prod-key") {
		t.Fatalf("expected IdentityFile key ref, got:\n%s", cfg)
	}
}

func TestCmdHostAddStoresPasswordValue(t *testing.T) {
	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "vault.enc"
	password := []byte("vault-pass")
	if err := vault.Initialize(path, password); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	workspace.PutVaultPassword(path, password, time.Now().Add(time.Minute))
	defer workspace.ClearVaultPasswords()

	ref := vaultRef{Source: path, Path: path}
	code := cmdHost([]string{
		"add", "prod",
		"--hostname", "10.0.0.10",
		"--user", "root",
		"--password-value", "ssh-pass",
		"--password-name", "prod-password",
	}, ref)
	if code != 0 {
		t.Fatalf("cmdHost add failed with code %d", code)
	}

	_, payload, err := vault.Load(path, password)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if got := payload.Secrets["prod-password"]; got != "ssh-pass" {
		t.Fatalf("unexpected stored password %q", got)
	}
	auth := payload.Hosts["prod"]
	if auth.Mode != "password" || auth.PasswordPolicy != "stored" || auth.PasswordRef != "prod-password" {
		t.Fatalf("unexpected host auth: %+v", auth)
	}
}

func TestCmdHostAddPasswordValueDefaultName(t *testing.T) {
	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "vault.enc"
	password := []byte("vault-pass")
	if err := vault.Initialize(path, password); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	workspace.PutVaultPassword(path, password, time.Now().Add(time.Minute))
	defer workspace.ClearVaultPasswords()

	ref := vaultRef{Source: path, Path: path}
	code := cmdHost([]string{"add", "prod", "--hostname", "10.0.0.10", "--password-value", "ssh-pass"}, ref)
	if code != 0 {
		t.Fatalf("cmdHost add failed with code %d", code)
	}
	_, payload, err := vault.Load(path, password)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	wantName := defaultHostPasswordSecretName("prod")
	if got := payload.Secrets[wantName]; got != "ssh-pass" {
		t.Fatalf("unexpected stored password %q for %s", got, wantName)
	}
	if payload.Hosts["prod"].PasswordRef != wantName {
		t.Fatalf("unexpected password ref: %+v", payload.Hosts["prod"])
	}
}
