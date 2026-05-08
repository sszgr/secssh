package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseCommandLineSimple(t *testing.T) {
	got, err := parseCommandLine("status")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	want := []string{"status"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestParseCommandLineQuotes(t *testing.T) {
	got, err := parseCommandLine("key add prod --file '/tmp/my key.pem'")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	want := []string{"key", "add", "prod", "--file", "/tmp/my key.pem"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestParseCommandLineEscapes(t *testing.T) {
	got, err := parseCommandLine(`ssh prod -- -o ProxyCommand=ssh\ -W\ %h:%p\ jump`)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	want := []string{"ssh", "prod", "--", "-o", "ProxyCommand=ssh -W %h:%p jump"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestParseCommandLineUnterminatedQuote(t *testing.T) {
	if _, err := parseCommandLine("secret add 'bad"); err == nil {
		t.Fatalf("expected unterminated quote error")
	}
}

func TestCompletionCandidatesTopLevel(t *testing.T) {
	got := completionCandidates(nil, ":st")
	want := []string{":status"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestCompletionCandidatesKeySubcommands(t *testing.T) {
	got := completionCandidates([]string{":key"}, "g")
	want := []string{"gen"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestCompletionCandidatesHostAddFlags(t *testing.T) {
	got := completionCandidates([]string{":host", "add"}, "--")
	want := []string{"--hostname", "--key", "--password", "--password-name", "--password-value", "--port", "--user"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestCompletionCandidatesBareInputDoesNotCompleteSecsshCommands(t *testing.T) {
	got := completionCandidates(nil, "p")
	if len(got) != 0 {
		t.Fatalf("got=%v want no secssh completions", got)
	}
}

func TestCompletionCandidatesHistory(t *testing.T) {
	got := completionCandidates(nil, ":h")
	want := []string{":help", ":history", ":host"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestCompletionCandidatesVersion(t *testing.T) {
	got := completionCandidates(nil, ":v")
	want := []string{":version"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestCompletionCandidatesCustomPrefix(t *testing.T) {
	got := completionCandidatesWithPrefix(nil, ".st", ".")
	want := []string{".status"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestCompletionCandidatesBareInputWithCustomPrefix(t *testing.T) {
	got := completionCandidatesWithPrefix(nil, ":st", ".")
	if len(got) != 0 {
		t.Fatalf("got=%v want no secssh completions", got)
	}
}

func TestCompletionCandidatesHistorySubcommands(t *testing.T) {
	got := completionCandidates([]string{":history"}, "")
	want := []string{"clear", "limit"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestREPLHistoryStoresNewestForTerminalNavigation(t *testing.T) {
	history := newREPLHistory(3)
	history.Add("status")
	history.Add("host list")
	history.Add("  ")
	history.Add("history")

	if history.Len() != 3 {
		t.Fatalf("got len=%d want=3", history.Len())
	}
	if got, want := history.At(0), "history"; got != want {
		t.Fatalf("got newest=%q want=%q", got, want)
	}
	if got, want := history.At(1), "host list"; got != want {
		t.Fatalf("got second newest=%q want=%q", got, want)
	}
}

func TestREPLHistoryClear(t *testing.T) {
	history := newREPLHistory(3)
	history.Add("status")
	history.Clear()

	if history.Len() != 0 {
		t.Fatalf("got len=%d want=0", history.Len())
	}
}

func TestREPLHistorySetLimitTrimsOldEntries(t *testing.T) {
	history := newREPLHistory(10)
	history.Add("one")
	history.Add("two")
	history.Add("three")

	history.SetLimit(2)

	want := []string{"two", "three"}
	if got := history.Entries(); !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
	if got, want := history.At(0), "three"; got != want {
		t.Fatalf("got newest=%q want=%q", got, want)
	}
}

func TestPrintREPLHistory(t *testing.T) {
	history := newREPLHistory(10)
	history.Add("status")
	history.Add("host auth set prod")

	out := captureStdout(t, func() {
		printREPLHistory(nil, history)
	})
	if !strings.Contains(out, "1  status") || !strings.Contains(out, "2  host auth set prod") {
		t.Fatalf("unexpected history output: %q", out)
	}
}

func TestPrintREPLHistoryClear(t *testing.T) {
	history := newREPLHistory(10)
	history.Add("status")

	printREPLHistory([]string{"clear"}, history)

	if history.Len() != 0 {
		t.Fatalf("got len=%d want=0", history.Len())
	}
}

func TestPrintREPLHistoryLimit(t *testing.T) {
	history := newREPLHistory(10)
	history.Add("one")
	history.Add("two")
	history.Add("three")

	out := captureStdout(t, func() {
		printREPLHistory([]string{"limit", "2"}, history)
	})

	if !strings.Contains(out, "history limit set to 2") {
		t.Fatalf("unexpected limit output: %q", out)
	}
	want := []string{"two", "three"}
	if got := history.Entries(); !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestWantsBuiltinHelp(t *testing.T) {
	if !wantsBuiltinHelp([]string{"--help"}) {
		t.Fatalf("expected --help to trigger builtin help")
	}
	if !wantsBuiltinHelp([]string{"-h"}) {
		t.Fatalf("expected -h to trigger builtin help")
	}
	if wantsBuiltinHelp([]string{"ai"}) {
		t.Fatalf("did not expect regular target to trigger builtin help")
	}
}

func TestHandleREPLHelpHistory(t *testing.T) {
	out := captureStdout(t, func() {
		if !handleREPLHelp([]string{"history"}) {
			t.Fatalf("expected history builtin help to be handled")
		}
	})
	if !strings.Contains(out, "history clear") || !strings.Contains(out, "history limit <n>") {
		t.Fatalf("expected history help output, got %q", out)
	}
}

func TestHandleREPLLineExitBareAndPrefixed(t *testing.T) {
	if !handleREPLLine("exit", nil, vaultRef{}, nil, nil) {
		t.Fatalf("expected bare exit to quit")
	}
	if !handleREPLLine(":exit", nil, vaultRef{}, nil, nil) {
		t.Fatalf("expected :exit to quit")
	}
	if !handleREPLLineWithPrefix(".exit", nil, vaultRef{}, nil, nil, ".") {
		t.Fatalf("expected .exit to quit")
	}
	if !handleREPLLine("quit", nil, vaultRef{}, nil, nil) {
		t.Fatalf("expected bare quit to quit")
	}
}

func TestHostCommandCompletionFallsBackToPath(t *testing.T) {
	dir := t.TempDir()
	name := "tabcmd-test"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(""), 0o755); err != nil {
		t.Fatalf("write test executable: %v", err)
	}
	t.Setenv("PATH", dir)

	got := hostCommandCandidates("tabcmd")
	if !containsString(got, name) {
		t.Fatalf("expected %q in completions, got %v", name, got)
	}
}

func TestHostPathCompletionFallback(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	dir := t.TempDir()
	defer func() { _ = os.Chdir(old) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	if err := os.WriteFile("tab-file.txt", []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	got := hostPathCandidates("tab-fi")
	if !containsString(got, "tab-file.txt") {
		t.Fatalf("expected file completion, got %v", got)
	}
}

func TestHostPathCompletionMarksDirectories(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	dir := t.TempDir()
	defer func() { _ = os.Chdir(old) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	if err := os.Mkdir("tab-dir", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	got := hostPathCandidates("tab-d")
	if !containsString(got, "tab-dir/") {
		t.Fatalf("expected directory completion with slash, got %v", got)
	}
}

func TestMarkDirectoryPathCandidateExpandsHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.Mkdir(filepath.Join(home, ".secssh"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	got := markDirectoryPathCandidate("~/.secssh")
	if got != "~/.secssh/" {
		t.Fatalf("got %q want %q", got, "~/.secssh/")
	}
}

func TestCompleteLineDoesNotAddSpaceAfterDirectory(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	dir := t.TempDir()
	defer func() { _ = os.Chdir(old) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	if err := os.Mkdir("tab-dir", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	line := "cd tab-d"
	got, pos, _, ok := completeLine(line, len(line))
	if !ok {
		t.Fatalf("expected completion")
	}
	if got != "cd tab-dir/" {
		t.Fatalf("got line=%q want %q", got, "cd tab-dir/")
	}
	if pos != len(got) {
		t.Fatalf("got pos=%d want %d", pos, len(got))
	}
}

func TestPersistentCdChangesWorkingDirectory(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	defer func() { _ = os.Chdir(old) }()

	env := &replEnv{}
	dir := t.TempDir()
	if code := runPersistentCd([]string{dir}, env); code != 0 {
		t.Fatalf("cd failed with code %d", code)
	}
	got, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd after cd failed: %v", err)
	}
	if got != dir {
		t.Fatalf("got cwd=%q want=%q", got, dir)
	}
	if env.previousDir != old {
		t.Fatalf("got previousDir=%q want=%q", env.previousDir, old)
	}
}

func TestPersistentCdDetection(t *testing.T) {
	args, ok, err := parsePersistentCdLine("cd '/tmp/my dir'")
	if err != nil || !ok || !reflect.DeepEqual(args, []string{"/tmp/my dir"}) {
		t.Fatalf("expected simple quoted cd to be persistent")
	}
	if _, ok, err := parsePersistentCdLine("cd /tmp && pwd"); err != nil || ok {
		t.Fatalf("did not expect compound cd to be persistent")
	}
	if _, ok, err := parsePersistentCdLine("pwd"); err != nil || ok {
		t.Fatalf("did not expect pwd to be persistent cd")
	}
	args, ok, err = parsePersistentCdLine(`cd C:\Users\admin\project`)
	if err != nil || !ok || !reflect.DeepEqual(args, []string{`C:\Users\admin\project`}) {
		t.Fatalf("expected windows path to preserve backslashes, got args=%v ok=%v err=%v", args, ok, err)
	}
}

func TestSelectHostShellUnix(t *testing.T) {
	got := selectHostShell("linux", func(key string) string {
		if key == "SHELL" {
			return "/bin/zsh"
		}
		return ""
	}, func(string) (string, error) {
		t.Fatalf("lookPath should not be called for unix shell")
		return "", nil
	})
	want := shellSpec{Path: "/bin/zsh", Args: []string{"-lc"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestSelectHostShellWindowsFallbacks(t *testing.T) {
	got := selectHostShell("windows", func(string) string { return "" }, func(name string) (string, error) {
		if name == "powershell.exe" {
			return `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, nil
		}
		return "", os.ErrNotExist
	})
	want := shellSpec{Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Args: []string{"-NoLogo", "-NoProfile", "-Command"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()

	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("io.Copy failed: %v", err)
	}
	_ = r.Close()
	return buf.String()
}
