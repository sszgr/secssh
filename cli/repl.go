package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/sszgr/secssh/workspace"
	"golang.org/x/term"
)

type stdioRW struct{}

func (stdioRW) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdioRW) Write(p []byte) (int, error) { return os.Stdout.Write(p) }

const (
	keyCtrlC = byte(3)
	keyCtrlD = byte(4)
)

type terminalRW struct {
	interrupted *atomic.Bool
	eot         *atomic.Bool
}

func (rw terminalRW) Read(p []byte) (int, error) {
	buf := make([]byte, len(p))
	n, err := os.Stdin.Read(buf)
	if n <= 0 {
		return n, err
	}

	out := 0
	for i := 0; i < n; i++ {
		switch buf[i] {
		case keyCtrlC:
			if rw.interrupted != nil {
				rw.interrupted.Store(true)
			}
		case keyCtrlD:
			if rw.eot != nil {
				rw.eot.Store(true)
			}
		default:
			p[out] = buf[i]
			out++
		}
	}

	if out == 0 {
		return 0, io.EOF
	}
	return out, err
}

func (rw terminalRW) Write(p []byte) (int, error) { return os.Stdout.Write(p) }

func runREPL(app *workspace.SessionManager, vaultPath string) int {
	fmt.Fprintln(os.Stdout, "secssh interactive mode. press TAB for completion, type 'help' for commands, 'exit' to quit.")

	if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
		return runREPLTerminal(app, vaultPath)
	}
	fmt.Fprintln(os.Stdout, "(non-terminal input detected, TAB completion disabled)")
	return runREPLScanner(app, vaultPath)
}

func runREPLTerminal(app *workspace.SessionManager, vaultPath string) int {
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "terminal raw mode failed: %v\n", err)
		return runREPLScanner(app, vaultPath)
	}
	defer func() {
		_ = term.Restore(fd, oldState)
	}()

	var interrupted atomic.Bool
	var eot atomic.Bool
	newTerminal := func() *term.Terminal {
		tt := term.NewTerminal(terminalRW{interrupted: &interrupted, eot: &eot}, "secssh> ")
		tt.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
			if key != '\t' {
				return line, pos, false
			}
			newLine, newPos, list, ok := completeLine(line, pos)
			if list != "" {
				_, _ = tt.Write([]byte("\n" + list + "\n"))
			}
			return newLine, newPos, ok
		}
		return tt
	}
	t := newTerminal()

	for {
		line, err := t.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if interrupted.Swap(false) {
					_, _ = t.Write([]byte("\r\033[K^C\r\n"))
					continue
				}
				if eot.Swap(false) {
					_, _ = t.Write([]byte("\r\n"))
					return 0
				}
				// Real EOF (pipe/input closed).
				_, _ = t.Write([]byte("\r\n"))
				return 0
			}

			fmt.Fprintf(os.Stderr, "read failed: %v\n", err)
			return 1
		}

		// Run command in normal terminal mode so command output/input is stable.
		if err := term.Restore(fd, oldState); err != nil {
			fmt.Fprintf(os.Stderr, "terminal restore failed: %v\n", err)
			return 1
		}
		if handleREPLLine(line, app, vaultPath) {
			return 0
		}
		if _, err := term.MakeRaw(fd); err != nil {
			fmt.Fprintf(os.Stderr, "terminal raw mode failed: %v\n", err)
			return 1
		}
	}
}

func runREPLScanner(app *workspace.SessionManager, vaultPath string) int {
	s := bufio.NewScanner(os.Stdin)
	for {
		fmt.Fprint(os.Stdout, "secssh> ")
		if !s.Scan() {
			fmt.Fprintln(os.Stdout)
			return 0
		}
		if handleREPLLine(s.Text(), app, vaultPath) {
			return 0
		}
	}
}

func handleREPLLine(raw string, app *workspace.SessionManager, vaultPath string) bool {
	line := strings.TrimSpace(raw)
	if line == "" {
		return false
	}
	switch line {
	case "exit", "quit":
		return true
	case "help":
		usage()
		return false
	}
	args, err := parseCommandLine(line)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse failed: %v\n", err)
		return false
	}
	if len(args) == 0 {
		return false
	}
	_ = runCommand(args, app, vaultPath)
	return false
}

func completeLine(line string, pos int) (newLine string, newPos int, list string, ok bool) {
	if pos < 0 || pos > len(line) {
		return line, pos, "", false
	}
	prefix := line[:pos]
	start := 0
	if idx := strings.LastIndexAny(prefix, " \t"); idx >= 0 {
		start = idx + 1
	}
	atNewToken := len(prefix) > 0 && (prefix[len(prefix)-1] == ' ' || prefix[len(prefix)-1] == '\t')
	current := ""
	if !atNewToken {
		current = prefix[start:]
	}

	parts := strings.Fields(prefix)
	path := parts
	if !atNewToken && len(path) > 0 {
		path = path[:len(path)-1]
	}
	cands := completionCandidates(path, current)
	if len(cands) == 0 {
		return line, pos, "", false
	}
	if len(cands) == 1 {
		repl := cands[0]
		newPrefix := prefix[:start] + repl
		result := newPrefix + line[pos:]
		cursor := len(newPrefix)
		if pos == len(line) {
			result += " "
			cursor++
		}
		return result, cursor, "", true
	}
	common := longestCommonPrefix(cands)
	if common != "" && len(common) > len(current) {
		newPrefix := prefix[:start] + common
		return newPrefix + line[pos:], len(newPrefix), "", true
	}
	return line, pos, strings.Join(cands, "  "), false
}

func completionCandidates(path []string, current string) []string {
	base := []string{}
	switch len(path) {
	case 0:
		base = []string{"unlock", "lock", "status", "ssh", "config", "key", "secret", "host", "passwd", "crypto", "help", "exit", "quit"}
	case 1:
		switch path[0] {
		case "config":
			base = []string{"set", "show"}
		case "key":
			base = []string{"add", "gen", "copy", "list", "rm"}
		case "secret":
			base = []string{"add", "rm", "list"}
		case "host":
			base = []string{"add", "rm", "auth", "list"}
		case "crypto":
			base = []string{"show", "set"}
		case "ssh":
			base = []string{"--auth", "--prompt", "--use-secret", "--"}
		}
	case 2:
		switch path[0] {
		case "host":
			if path[1] == "auth" {
				base = []string{"set"}
			}
			if path[1] == "add" {
				base = []string{"--hostname", "--port", "--user"}
			}
		case "config":
			if path[1] == "set" {
				base = []string{"--file"}
			}
		case "key":
			if path[1] == "add" {
				base = []string{"--file"}
			}
			if path[1] == "gen" {
				base = []string{"--type", "--bits", "--comment"}
			}
			if path[1] == "copy" {
				base = []string{"--auth", "--prompt", "--use-secret"}
			}
		case "crypto":
			if path[1] == "set" {
				base = []string{"--kdf", "--cipher"}
			}
		case "ssh":
			base = []string{"--auth", "--prompt", "--use-secret", "--"}
		}
	default:
		if len(path) >= 3 && path[0] == "host" && path[1] == "auth" && path[2] == "set" {
			base = []string{"--mode", "--password-policy", "--password-ref"}
		}
		if len(path) >= 2 && path[0] == "host" && path[1] == "add" {
			base = []string{"--hostname", "--port", "--user"}
		}
		if len(path) >= 2 && path[0] == "key" && path[1] == "copy" {
			base = []string{"--auth", "--prompt", "--use-secret"}
		}
		if len(path) >= 2 && path[0] == "ssh" {
			base = []string{"--auth", "--prompt", "--use-secret", "--"}
		}
	}

	if current == "" {
		sort.Strings(base)
		return base
	}
	out := make([]string, 0, len(base))
	for _, v := range base {
		if strings.HasPrefix(v, current) {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func longestCommonPrefix(values []string) string {
	if len(values) == 0 {
		return ""
	}
	prefix := values[0]
	for _, v := range values[1:] {
		for !strings.HasPrefix(v, prefix) {
			if len(prefix) == 0 {
				return ""
			}
			prefix = prefix[:len(prefix)-1]
		}
	}
	return prefix
}

func parseCommandLine(s string) ([]string, error) {
	var args []string
	var b strings.Builder
	inSingle := false
	inDouble := false
	escaped := false

	flush := func() {
		if b.Len() == 0 {
			return
		}
		args = append(args, b.String())
		b.Reset()
	}

	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && !inSingle {
			escaped = true
			continue
		}
		if r == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if r == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if !inSingle && !inDouble && (r == ' ' || r == '\t') {
			flush()
			continue
		}
		b.WriteRune(r)
	}
	if escaped {
		b.WriteRune('\\')
	}
	if inSingle || inDouble {
		return nil, errors.New("unterminated quote")
	}
	flush()
	return args, nil
}
