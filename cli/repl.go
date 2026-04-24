package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sszgr/secssh/runner"
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

type replHistory struct {
	entries []string
	max     int
}

func newREPLHistory(max int) *replHistory {
	if max <= 0 {
		max = 100
	}
	return &replHistory{max: max}
}

func (h *replHistory) Add(entry string) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return
	}
	if len(h.entries) == h.max {
		copy(h.entries, h.entries[1:])
		h.entries[h.max-1] = entry
		return
	}
	h.entries = append(h.entries, entry)
}

func (h *replHistory) Clear() {
	h.entries = nil
}

func (h *replHistory) SetLimit(max int) {
	if max <= 0 {
		max = 1
	}
	h.max = max
	h.trimToLimit()
}

func (h *replHistory) Len() int {
	return len(h.entries)
}

func (h *replHistory) At(idx int) string {
	if idx < 0 || idx >= len(h.entries) {
		panic(fmt.Sprintf("history index %d out of range", idx))
	}
	return h.entries[len(h.entries)-1-idx]
}

func (h *replHistory) Entries() []string {
	out := make([]string, len(h.entries))
	copy(out, h.entries)
	return out
}

func (h *replHistory) trimToLimit() {
	if len(h.entries) <= h.max {
		return
	}
	h.entries = append([]string(nil), h.entries[len(h.entries)-h.max:]...)
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

func runREPL(app *workspace.SessionManager, ref vaultRef) int {
	fmt.Fprintln(os.Stdout, "secssh interactive mode. press TAB for completion, type 'help' for commands, 'exit' to quit.")

	history := newREPLHistory(100)
	if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
		return runREPLTerminal(app, ref, history)
	}
	fmt.Fprintln(os.Stdout, "(non-terminal input detected, TAB completion disabled)")
	return runREPLScanner(app, ref, history)
}

func runREPLTerminal(app *workspace.SessionManager, ref vaultRef, history *replHistory) int {
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "terminal raw mode failed: %v\n", err)
		return runREPLScanner(app, ref, history)
	}
	defer func() {
		_ = term.Restore(fd, oldState)
	}()

	var interrupted atomic.Bool
	var eot atomic.Bool
	newTerminal := func() *term.Terminal {
		tt := term.NewTerminal(terminalRW{interrupted: &interrupted, eot: &eot}, replPrompt())
		tt.History = history
		syncTerminalSize(tt, fd)
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
		if handleREPLLine(line, app, ref, history) {
			return 0
		}
		if _, err := term.MakeRaw(fd); err != nil {
			fmt.Fprintf(os.Stderr, "terminal raw mode failed: %v\n", err)
			return 1
		}
		t = newTerminal()
	}
}

func syncTerminalSize(t *term.Terminal, fd int) {
	width, height, err := term.GetSize(fd)
	if err != nil || width <= 0 {
		return
	}
	_ = t.SetSize(width, height)
}

func runREPLScanner(app *workspace.SessionManager, ref vaultRef, history *replHistory) int {
	s := bufio.NewScanner(os.Stdin)
	for {
		fmt.Fprint(os.Stdout, replPrompt())
		if !s.Scan() {
			fmt.Fprintln(os.Stdout)
			return 0
		}
		line := s.Text()
		if history != nil {
			history.Add(line)
		}
		if handleREPLLine(line, app, ref, history) {
			return 0
		}
	}
}

func handleREPLLine(raw string, app *workspace.SessionManager, ref vaultRef, history *replHistory) bool {
	line := strings.TrimSpace(raw)
	if line == "" {
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
	switch args[0] {
	case "exit", "quit":
		return true
	case "help":
		if handleREPLHelp(args[1:]) {
			return false
		}
		usage()
		return false
	}
	if handled := handleREPLBuiltin(args, app, ref, history); handled {
		return false
	}
	_ = runCommand(args, app, ref)
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
		base = []string{"unlock", "lock", "status", "ssh", "scp", "sftp", "pwd", "ls", "cd", "rpwd", "rls", "history", "config", "key", "secret", "host", "passwd", "crypto", "help", "exit", "quit"}
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
		case "scp":
			base = []string{"--auth", "--prompt", "--use-secret", "--"}
		case "sftp":
			base = []string{"--auth", "--prompt", "--use-secret", "--"}
		case "pwd":
			base = []string{}
		case "ls":
			base = []string{}
		case "cd":
			base = []string{}
		case "rpwd":
			base = []string{}
		case "rls":
			base = []string{}
		case "history":
			base = []string{"clear", "limit"}
		}
	case 2:
		switch path[0] {
		case "history":
			if path[1] == "limit" {
				base = []string{"10", "50", "100", "500"}
			}
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

func replPrompt() string {
	cwd, err := os.Getwd()
	if err != nil || strings.TrimSpace(cwd) == "" {
		return "secssh> "
	}
	return "secssh " + cwd + "> "
}

func handleREPLBuiltin(args []string, app *workspace.SessionManager, ref vaultRef, history *replHistory) bool {
	switch args[0] {
	case "history":
		if wantsBuiltinHelp(args[1:]) {
			printREPLBuiltinHelp("history")
			return true
		}
		printREPLHistory(args[1:], history)
		return true
	case "pwd":
		if wantsBuiltinHelp(args[1:]) {
			printREPLBuiltinHelp("pwd")
			return true
		}
		runREPLPwd(args[1:], app, ref)
		return true
	case "ls":
		if wantsBuiltinHelp(args[1:]) {
			printREPLBuiltinHelp("ls")
			return true
		}
		runREPLLs(args[1:], app, ref)
		return true
	case "cd":
		if wantsBuiltinHelp(args[1:]) {
			printREPLBuiltinHelp("cd")
			return true
		}
		runREPLCd(args[1:])
		return true
	case "rpwd":
		if wantsBuiltinHelp(args[1:]) {
			printREPLBuiltinHelp("rpwd")
			return true
		}
		runREPLRemotePwd(args[1:], app, ref)
		return true
	case "rls":
		if wantsBuiltinHelp(args[1:]) {
			printREPLBuiltinHelp("rls")
			return true
		}
		runREPLRemoteLs(args[1:], app, ref)
		return true
	default:
		return false
	}
}

func runREPLPwd(args []string, app *workspace.SessionManager, ref vaultRef) {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "pwd failed: usage: pwd")
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pwd failed: %v\n", err)
		return
	}
	fmt.Fprintln(os.Stdout, cwd)
}

func runREPLLs(args []string, app *workspace.SessionManager, ref vaultRef) {
	if len(args) == 0 {
		_ = listLocalDir(".")
		return
	}
	if len(args) > 1 {
		fmt.Fprintln(os.Stderr, "ls failed: usage: ls [path]")
		return
	}
	_ = listLocalDir(args[0])
}

func runREPLCd(args []string) {
	dest := ""
	switch len(args) {
	case 0:
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cd failed: %v\n", err)
			return
		}
		dest = home
	case 1:
		dest = args[0]
	default:
		fmt.Fprintln(os.Stderr, "cd failed: usage: cd [path]")
		return
	}
	if err := os.Chdir(dest); err != nil {
		fmt.Fprintf(os.Stderr, "cd failed: %v\n", err)
	}
}

func runREPLRemotePwd(args []string, app *workspace.SessionManager, ref vaultRef) {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintln(os.Stderr, "rpwd failed: usage: rpwd <host>")
		return
	}
	_ = runRemoteInspectCommand("rpwd", app, ref, strings.TrimSpace(args[0]), "pwd")
}

func runREPLRemoteLs(args []string, app *workspace.SessionManager, ref vaultRef) {
	if len(args) == 0 || len(args) > 2 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintln(os.Stderr, "rls failed: usage: rls <host> [path]")
		return
	}
	cmd := "ls -la"
	if len(args) == 2 && strings.TrimSpace(args[1]) != "" {
		cmd += " -- " + shellSingleQuote(args[1])
	}
	_ = runRemoteInspectCommand("rls", app, ref, strings.TrimSpace(args[0]), cmd)
}

func printREPLHistory(args []string, history *replHistory) {
	if history == nil {
		return
	}
	switch len(args) {
	case 0:
		for i, entry := range history.Entries() {
			fmt.Fprintf(os.Stdout, "%4d  %s\n", i+1, entry)
		}
		return
	case 1:
		if args[0] == "clear" {
			history.Clear()
			return
		}
	case 2:
		if args[0] == "limit" {
			max, err := strconv.Atoi(args[1])
			if err != nil || max <= 0 {
				fmt.Fprintln(os.Stderr, "history failed: limit must be a positive integer")
				return
			}
			history.SetLimit(max)
			fmt.Fprintf(os.Stdout, "history limit set to %d\n", max)
			return
		}
	}
	fmt.Fprintln(os.Stderr, "history failed: usage: history [clear|limit <n>]")
}

func historyUsageLines() []string {
	return []string{
		"history",
		"history clear",
		"history limit <n>",
		"  Show, clear, or resize command history for this interactive session.",
	}
}

func printHistoryUsage() {
	for _, line := range historyUsageLines() {
		fmt.Fprintln(os.Stdout, line)
	}
}

func listLocalDir(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "."
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ls failed: %v\n", err)
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += string(os.PathSeparator)
		}
		fmt.Fprintln(os.Stdout, name)
	}
	return nil
}

func wantsBuiltinHelp(args []string) bool {
	for _, arg := range args {
		switch strings.TrimSpace(arg) {
		case "-h", "--help", "help":
			return true
		}
	}
	return false
}

func handleREPLHelp(args []string) bool {
	if len(args) != 1 {
		return false
	}
	switch strings.TrimSpace(args[0]) {
	case "history", "pwd", "ls", "cd", "rpwd", "rls":
		printREPLBuiltinHelp(strings.TrimSpace(args[0]))
		return true
	default:
		return false
	}
}

func printREPLBuiltinHelp(name string) {
	switch name {
	case "history":
		printHistoryUsage()
	case "pwd":
		fmt.Fprintln(os.Stdout, "pwd")
		fmt.Fprintln(os.Stdout, "  Show local current directory.")
	case "ls":
		fmt.Fprintln(os.Stdout, "ls [path]")
		fmt.Fprintln(os.Stdout, "  List local directory entries.")
	case "cd":
		fmt.Fprintln(os.Stdout, "cd [path]")
		fmt.Fprintln(os.Stdout, "  Change local working directory.")
	case "rpwd":
		fmt.Fprintln(os.Stdout, "rpwd <host>")
		fmt.Fprintln(os.Stdout, "  Show remote current directory through SSH.")
	case "rls":
		fmt.Fprintln(os.Stdout, "rls <host> [path]")
		fmt.Fprintln(os.Stdout, "  List remote directory entries through SSH.")
	default:
		fmt.Fprintf(os.Stdout, "no help for %s\n", name)
	}
}

func runRemoteInspectCommand(op string, mgr *workspace.SessionManager, ref vaultRef, target, remoteCommand string) int {
	if err := mgr.RequireUnlocked(); err != nil {
		fmt.Fprintf(os.Stderr, "%s failed: %v\n", op, err)
		return 1
	}
	header, payload, _, err := loadVaultInteractive(ref)
	if err != nil {
		return cmdErr(op, err)
	}
	_ = header
	exp, err := mgr.ExpiresAt()
	if err != nil {
		exp = time.Time{}
	}
	runPayload := *payload
	runPayload.SSHConfig = mergeManagedHostsConfig(payload.SSHConfig, payload.Machines)
	if err := runner.RunSSH(runner.Options{
		Target:     strings.TrimSpace(target),
		PassArgs:   []string{remoteCommand},
		Vault:      &runPayload,
		VaultPath:  ref.Path,
		SessionExp: exp.Unix(),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "%s failed: %v\n", op, err)
		return 1
	}
	return 0
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
