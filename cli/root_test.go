package cli

import (
	"reflect"
	"testing"
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
	runnerArgs, passArgs := splitSSHArgs([]string{"--auth", "password", "--prompt"})
	wantRunner := []string{"--auth", "password", "--prompt"}
	if !reflect.DeepEqual(runnerArgs, wantRunner) {
		t.Fatalf("unexpected runner args: got=%v want=%v", runnerArgs, wantRunner)
	}
	if passArgs != nil {
		t.Fatalf("expected nil pass args, got=%v", passArgs)
	}
}

func TestSplitSSHArgsWithPassthrough(t *testing.T) {
	runnerArgs, passArgs := splitSSHArgs([]string{"--auth", "key", "--", "-p", "2222", "-o", "StrictHostKeyChecking=no"})
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
	runnerArgs, passArgs := splitSSHArgs([]string{"--", "-vvv"})
	if len(runnerArgs) != 0 {
		t.Fatalf("expected no runner args, got=%v", runnerArgs)
	}
	wantPass := []string{"-vvv"}
	if !reflect.DeepEqual(passArgs, wantPass) {
		t.Fatalf("unexpected pass args: got=%v want=%v", passArgs, wantPass)
	}
}
