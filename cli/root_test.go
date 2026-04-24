package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sszgr/secssh/vault"
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
