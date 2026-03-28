package cli

import (
	"reflect"
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
