package cli

import (
	"bytes"
	"io"
	"os"
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
	got := completionCandidates(nil, "st")
	want := []string{"status"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestCompletionCandidatesKeySubcommands(t *testing.T) {
	got := completionCandidates([]string{"key"}, "g")
	want := []string{"gen"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestCompletionCandidatesHostAddFlags(t *testing.T) {
	got := completionCandidates([]string{"host", "add"}, "--")
	want := []string{"--hostname", "--key", "--port", "--user"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestCompletionCandidatesTopLevelShellBuiltins(t *testing.T) {
	got := completionCandidates(nil, "p")
	want := []string{"passwd", "pwd"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestCompletionCandidatesRemoteBuiltins(t *testing.T) {
	got := completionCandidates(nil, "r")
	want := []string{"rls", "rpwd"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestCompletionCandidatesHistory(t *testing.T) {
	got := completionCandidates(nil, "h")
	want := []string{"help", "history", "host"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestCompletionCandidatesHistorySubcommands(t *testing.T) {
	got := completionCandidates([]string{"history"}, "")
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

func TestHandleREPLHelpBuiltin(t *testing.T) {
	out := captureStdout(t, func() {
		if !handleREPLHelp([]string{"ls"}) {
			t.Fatalf("expected ls builtin help to be handled")
		}
	})
	if !strings.Contains(out, "ls [path]") {
		t.Fatalf("expected ls help output, got %q", out)
	}
}

func TestHandleREPLHelpRemoteBuiltin(t *testing.T) {
	out := captureStdout(t, func() {
		if !handleREPLHelp([]string{"rls"}) {
			t.Fatalf("expected rls builtin help to be handled")
		}
	})
	if !strings.Contains(out, "rls <host> [path]") {
		t.Fatalf("expected rls help output, got %q", out)
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
