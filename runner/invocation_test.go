package runner

import (
	"encoding/base64"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestBuildSSHInvocationNoPassword(t *testing.T) {
	args, env, useAskPass := buildSSHInvocation("/tmp/cfg", Options{Target: "prod", PassArgs: []string{"-p", "2222"}}, nil, "", "/tmp/askpass", []string{"PATH=/usr/bin"})
	wantArgs := []string{"-F", "/tmp/cfg", "prod", "-p", "2222"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("unexpected args: got=%v want=%v", args, wantArgs)
	}
	if useAskPass {
		t.Fatalf("expected askpass disabled")
	}
	if len(env) != 1 || env[0] != "PATH=/usr/bin" {
		t.Fatalf("unexpected env: %v", env)
	}
}

func TestBuildSSHInvocationWithPassword(t *testing.T) {
	args, env, useAskPass := buildSSHInvocation("/tmp/cfg", Options{Target: "prod"}, nil, "pw-123", "/tmp/askpass", []string{"PATH=/usr/bin"})
	wantArgs := []string{"-F", "/tmp/cfg", "prod"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("unexpected args: got=%v want=%v", args, wantArgs)
	}
	if !useAskPass {
		t.Fatalf("expected askpass enabled")
	}
	joined := strings.Join(env, "\n")
	wantEnv := []string{"SSH_ASKPASS=/tmp/askpass", "SSH_ASKPASS_REQUIRE=force", "DISPLAY=secssh:0"}
	if runtime.GOOS == "windows" {
		wantEnv = append(wantEnv, "SECSSH_SSH_PASSWORD_B64="+base64.StdEncoding.EncodeToString([]byte("pw-123")))
	} else {
		wantEnv = append(wantEnv, "SECSSH_SSH_PASSWORD=pw-123")
	}
	for _, key := range wantEnv {
		if !strings.Contains(joined, key) {
			t.Fatalf("missing env %q in %v", key, env)
		}
	}
}

func TestBuildSFTPInvocationNoPassword(t *testing.T) {
	args, env, useAskPass := buildSFTPInvocation("/tmp/cfg", Options{Target: "prod", PassArgs: []string{"-P", "2222"}}, nil, "", "/tmp/askpass", []string{"PATH=/usr/bin"})
	wantArgs := []string{"-F", "/tmp/cfg", "-P", "2222", "prod"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("unexpected args: got=%v want=%v", args, wantArgs)
	}
	if useAskPass {
		t.Fatalf("expected askpass disabled")
	}
	if len(env) != 1 || env[0] != "PATH=/usr/bin" {
		t.Fatalf("unexpected env: %v", env)
	}
}

func TestBuildSCPInvocationNoPassword(t *testing.T) {
	args, env, useAskPass := buildSCPInvocation("/tmp/cfg", "local.txt", "prod:/tmp/remote.txt", nil, []string{"-P", "2222"}, "", "/tmp/askpass", []string{"PATH=/usr/bin"})
	wantArgs := []string{"-F", "/tmp/cfg", "-P", "2222", "local.txt", "prod:/tmp/remote.txt"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("unexpected args: got=%v want=%v", args, wantArgs)
	}
	if useAskPass {
		t.Fatalf("expected askpass disabled")
	}
	if len(env) != 1 || env[0] != "PATH=/usr/bin" {
		t.Fatalf("unexpected env: %v", env)
	}
}

func TestBuildSSHInvocationWithAuthOptions(t *testing.T) {
	args, _, _ := buildSSHInvocation("/tmp/cfg", Options{Target: "prod"}, []string{"-o", "PasswordAuthentication=yes"}, "", "/tmp/askpass", []string{"PATH=/usr/bin"})
	wantArgs := []string{"-F", "/tmp/cfg", "-o", "PasswordAuthentication=yes", "prod"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("unexpected args: got=%v want=%v", args, wantArgs)
	}
}

func TestAskpassScriptPathMatchesPlatform(t *testing.T) {
	got := askpassScriptPath(filepath.Join("tmp", "run"))
	if runtime.GOOS == "windows" {
		if !strings.HasSuffix(got, "askpass.cmd") {
			t.Fatalf("expected windows askpass path, got=%s", got)
		}
		return
	}
	if !strings.HasSuffix(got, "askpass.sh") {
		t.Fatalf("expected posix askpass path, got=%s", got)
	}
}
