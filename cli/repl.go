package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

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

type replEnv struct {
	hostShell   shellSpec
	previousDir string
	lastExit    int
}

type shellSpec struct {
	Path string
	Args []string
}

func newREPLEnv() *replEnv {
	return &replEnv{hostShell: selectHostShell(runtime.GOOS, os.Getenv, exec.LookPath)}
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

func runREPL(app *workspace.SessionManager, ref vaultRef, commandPrefix string) int {
	commandPrefix = normalizeREPLPrefix(commandPrefix)
	fmt.Fprintf(os.Stdout, "secssh environment. press TAB for completion, use '%shelp' for commands, '%sexit' to quit.\n", commandPrefix, commandPrefix)

	history := newREPLHistory(100)
	env := newREPLEnv()
	if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
		return runREPLTerminal(app, ref, history, env, commandPrefix)
	}
	fmt.Fprintln(os.Stdout, "(non-terminal input detected, TAB completion disabled)")
	return runREPLScanner(app, ref, history, env, commandPrefix)
}

func runREPLTerminal(app *workspace.SessionManager, ref vaultRef, history *replHistory, env *replEnv, commandPrefix string) int {
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "terminal raw mode failed: %v\n", err)
		return runREPLScanner(app, ref, history, env, commandPrefix)
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
			newLine, newPos, list, ok := completeLineWithPrefix(line, pos, commandPrefix)
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
					_, _ = os.Stdout.Write([]byte("^C\r\n"))
					t = newTerminal()
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
		if handleREPLLineWithPrefix(line, app, ref, history, env, commandPrefix) {
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

func runREPLScanner(app *workspace.SessionManager, ref vaultRef, history *replHistory, env *replEnv, commandPrefix string) int {
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
		if handleREPLLineWithPrefix(line, app, ref, history, env, commandPrefix) {
			return 0
		}
	}
}

func handleREPLLine(raw string, app *workspace.SessionManager, ref vaultRef, history *replHistory, env *replEnv) bool {
	return handleREPLLineWithPrefix(raw, app, ref, history, env, ":")
}

func handleREPLLineWithPrefix(raw string, app *workspace.SessionManager, ref vaultRef, history *replHistory, env *replEnv, commandPrefix string) bool {
	commandPrefix = normalizeREPLPrefix(commandPrefix)
	line := strings.TrimSpace(raw)
	if line == "" {
		return false
	}
	if line == "exit" || line == "quit" {
		return true
	}
	if strings.HasPrefix(line, commandPrefix) {
		return handleEnvBuiltin(strings.TrimSpace(strings.TrimPrefix(line, commandPrefix)), app, ref, history, commandPrefix)
	}

	if cdArgs, ok, err := parsePersistentCdLine(line); ok {
		if err != nil {
			fmt.Fprintf(os.Stderr, "cd failed: %v\n", err)
			return false
		}
		if env == nil {
			env = newREPLEnv()
		}
		env.lastExit = runPersistentCd(cdArgs, env)
		return false
	}
	if env == nil {
		env = newREPLEnv()
	}
	env.lastExit = runHostShell(line, app, ref, env)
	return false
}

func handleEnvBuiltin(line string, app *workspace.SessionManager, ref vaultRef, history *replHistory, commandPrefix string) bool {
	if line == "" {
		fmt.Fprintln(os.Stderr, "empty secssh command")
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
		envUsage(commandPrefix)
		return false
	case "history":
		if wantsBuiltinHelp(args[1:]) {
			printREPLBuiltinHelp("history")
			return false
		}
		printREPLHistory(args[1:], history)
		return false
	default:
		_ = runCommand(args, app, ref)
		return false
	}
}

func completeLine(line string, pos int) (newLine string, newPos int, list string, ok bool) {
	return completeLineWithPrefix(line, pos, ":")
}

func completeLineWithPrefix(line string, pos int, commandPrefix string) (newLine string, newPos int, list string, ok bool) {
	commandPrefix = normalizeREPLPrefix(commandPrefix)
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
	cands := completionCandidatesWithPrefix(path, current, commandPrefix)
	if len(cands) == 0 && !strings.HasPrefix(prefix, commandPrefix) {
		cands = hostCompletionCandidates(line, pos, path, current)
	}
	if len(cands) == 0 {
		return line, pos, "", false
	}
	if len(cands) == 1 {
		repl := cands[0]
		newPrefix := prefix[:start] + repl
		result := newPrefix + line[pos:]
		cursor := len(newPrefix)
		if pos == len(line) && completionShouldAddSpace(repl) {
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
	return completionCandidatesWithPrefix(path, current, ":")
}

func completionCandidatesWithPrefix(path []string, current, commandPrefix string) []string {
	commandPrefix = normalizeREPLPrefix(commandPrefix)
	base := []string{}
	if len(path) == 0 && !strings.HasPrefix(current, commandPrefix) {
		return nil
	}
	normalize := func(s string) string {
		return strings.TrimPrefix(s, commandPrefix)
	}
	switch len(path) {
	case 0:
		base = prefixedCommandCandidates(commandPrefix)
	case 1:
		switch normalize(path[0]) {
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
			base = []string{"-r", "--auth", "--prompt", "--use-secret", "--"}
		case "sftp":
			base = []string{"--auth", "--prompt", "--use-secret", "--"}
		case "history":
			base = []string{"clear", "limit"}
		}
	case 2:
		switch normalize(path[0]) {
		case "history":
			if path[1] == "limit" {
				base = []string{"10", "50", "100", "500"}
			}
		case "host":
			if path[1] == "auth" {
				base = []string{"set"}
			}
			if path[1] == "add" {
				base = []string{"--hostname", "--key", "--password", "--password-name", "--password-value", "--port", "--user"}
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
		case "scp":
			base = []string{"-r", "--auth", "--prompt", "--use-secret", "--"}
		case "sftp":
			base = []string{"--auth", "--prompt", "--use-secret", "--"}
		}
	default:
		root := normalize(path[0])
		if len(path) >= 3 && root == "host" && path[1] == "auth" && path[2] == "set" {
			base = []string{"--mode", "--password-policy", "--password-ref"}
		}
		if len(path) >= 2 && root == "host" && path[1] == "add" {
			base = []string{"--hostname", "--key", "--password", "--password-name", "--password-value", "--port", "--user"}
		}
		if len(path) >= 2 && root == "key" && path[1] == "copy" {
			base = []string{"--auth", "--prompt", "--use-secret"}
		}
		if len(path) >= 2 && root == "ssh" {
			base = []string{"--auth", "--prompt", "--use-secret", "--"}
		}
		if len(path) >= 2 && root == "scp" {
			base = []string{"-r", "--auth", "--prompt", "--use-secret", "--"}
		}
		if len(path) >= 2 && root == "sftp" {
			base = []string{"--auth", "--prompt", "--use-secret", "--"}
		}
	}

	if isTransportCompletionPath(path, commandPrefix, current) {
		return hostPathCandidates(current)
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

func isTransportCompletionPath(path []string, commandPrefix, current string) bool {
	if len(path) == 0 || current == "" || strings.HasPrefix(current, "-") {
		return false
	}
	root := strings.TrimPrefix(path[0], commandPrefix)
	if root != "ssh" && root != "scp" && root != "sftp" {
		return false
	}
	if isKnownTransportFlagValue(path) {
		return false
	}
	return true
}

func isKnownTransportFlagValue(path []string) bool {
	if len(path) == 0 {
		return false
	}
	switch path[len(path)-1] {
	case "--auth", "--use-secret":
		return true
	default:
		return false
	}
}

func prefixedCommandCandidates(commandPrefix string) []string {
	commands := []string{"unlock", "lock", "status", "ssh", "scp", "sftp", "history", "config", "key", "secret", "host", "passwd", "crypto", "version", "help", "exit", "quit"}
	out := make([]string, 0, len(commands))
	for _, command := range commands {
		out = append(out, commandPrefix+command)
	}
	return out
}

func normalizeREPLPrefix(commandPrefix string) string {
	if commandPrefix == "" {
		return ":"
	}
	return commandPrefix
}

func completionShouldAddSpace(candidate string) bool {
	return !strings.HasSuffix(candidate, "/") && !strings.HasSuffix(candidate, "\\")
}

func replPrompt() string {
	cwd, err := os.Getwd()
	if err != nil || strings.TrimSpace(cwd) == "" {
		return "(secssh) > "
	}
	return "(secssh) " + cwd + " > "
}

func runPersistentCd(args []string, env *replEnv) int {
	dest := ""
	switch len(args) {
	case 0:
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cd failed: %v\n", err)
			return 1
		}
		dest = home
	case 1:
		if args[0] == "-" {
			if env == nil || strings.TrimSpace(env.previousDir) == "" {
				fmt.Fprintln(os.Stderr, "cd failed: previous directory is not set")
				return 1
			}
			dest = env.previousDir
		} else {
			dest = args[0]
		}
	default:
		fmt.Fprintln(os.Stderr, "cd failed: usage: cd [path]")
		return 2
	}
	prev, _ := os.Getwd()
	if err := os.Chdir(dest); err != nil {
		fmt.Fprintf(os.Stderr, "cd failed: %v\n", err)
		return 1
	}
	if env != nil {
		env.previousDir = prev
	}
	return 0
}

func containsShellSyntax(raw string) bool {
	for _, token := range []string{"&&", "||", "|", ">", "<", ";"} {
		if strings.Contains(raw, token) {
			return true
		}
	}
	return false
}

func parsePersistentCdLine(raw string) (args []string, ok bool, err error) {
	line := strings.TrimSpace(raw)
	if line != "cd" && !strings.HasPrefix(line, "cd ") && !strings.HasPrefix(line, "cd\t") {
		return nil, false, nil
	}
	if containsShellSyntax(line) {
		return nil, false, nil
	}
	rest := strings.TrimSpace(line[2:])
	if rest == "" {
		return nil, true, nil
	}
	if strings.HasPrefix(rest, "'") || strings.HasPrefix(rest, "\"") {
		quote := rest[0]
		var b strings.Builder
		closed := false
		for i := 1; i < len(rest); i++ {
			if rest[i] == quote {
				if strings.TrimSpace(rest[i+1:]) != "" {
					return nil, true, errors.New("usage: cd [path]")
				}
				closed = true
				break
			}
			b.WriteByte(rest[i])
		}
		if !closed {
			return nil, true, errors.New("unterminated quote")
		}
		return []string{b.String()}, true, nil
	}
	return []string{rest}, true, nil
}

func runHostShell(line string, app *workspace.SessionManager, ref vaultRef, env *replEnv) int {
	if env == nil {
		env = newREPLEnv()
	}
	spec := env.hostShell
	if strings.TrimSpace(spec.Path) == "" {
		fmt.Fprintln(os.Stderr, "host shell failed: no shell available")
		return 127
	}
	args := append([]string{}, spec.Args...)
	args = append(args, line)
	cmd := exec.Command(spec.Path, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = buildHostEnv(app, ref)
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "host shell failed: %v\n", err)
		return 1
	}
	return 0
}

func buildHostEnv(app *workspace.SessionManager, ref vaultRef) []string {
	env := os.Environ()
	env = upsertEnv(env, "SECSSH_ENV", "1")
	env = upsertEnv(env, "SECSSH_VAULT", ref.Source)
	env = upsertEnv(env, "SECSSH_VAULT_PATH", ref.Path)
	status := "locked"
	if app != nil {
		if st, err := app.Status(); err == nil && st.Unlocked {
			status = "unlocked"
		}
	}
	env = upsertEnv(env, "SECSSH_SESSION_STATUS", status)
	return env
}

func upsertEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func selectHostShell(goos string, getenv func(string) string, lookPath func(string) (string, error)) shellSpec {
	if goos == "windows" {
		for _, name := range []string{"pwsh.exe", "powershell.exe", "cmd.exe"} {
			path, err := lookPath(name)
			if err != nil {
				continue
			}
			if strings.EqualFold(name, "cmd.exe") {
				return shellSpec{Path: path, Args: []string{"/S", "/C"}}
			}
			return shellSpec{Path: path, Args: []string{"-NoLogo", "-NoProfile", "-Command"}}
		}
		return shellSpec{Path: "cmd.exe", Args: []string{"/S", "/C"}}
	}
	if shell := strings.TrimSpace(getenv("SHELL")); shell != "" {
		return shellSpec{Path: shell, Args: []string{"-lc"}}
	}
	return shellSpec{Path: "/bin/sh", Args: []string{"-lc"}}
}

func hostCompletionCandidates(line string, pos int, path []string, current string) []string {
	if pos < 0 || pos > len(line) {
		return nil
	}
	if len(path) == 0 {
		return hostCommandCandidates(current)
	}
	return hostPathCandidates(current)
}

func hostCommandCandidates(prefix string) []string {
	if runtime.GOOS == "windows" {
		script := "$ErrorActionPreference='SilentlyContinue'; Get-Command -Name " + psSingleQuote(prefix+"*") + " | Select-Object -ExpandProperty Name -Unique"
		if cands := runCompletionCommand("powershell.exe", []string{"-NoLogo", "-NoProfile", "-Command", script}); len(cands) > 0 {
			return cands
		}
		return completePathExecutables(prefix)
	}
	script := "compgen -c -- " + shellSingleQuote(prefix)
	if cands := runCompletionCommand("bash", []string{"-lc", script}); len(cands) > 0 {
		return cands
	}
	return completePathExecutables(prefix)
}

func hostPathCandidates(prefix string) []string {
	if runtime.GOOS == "windows" {
		pattern := prefix + "*"
		script := "$ErrorActionPreference='SilentlyContinue'; Get-ChildItem -Force -Name " + psSingleQuote(pattern)
		if cands := runCompletionCommand("powershell.exe", []string{"-NoLogo", "-NoProfile", "-Command", script}); len(cands) > 0 {
			return markDirectoryPathCandidates(cands)
		}
		return completeLocalPathFallback(prefix)
	}
	script := "compgen -f -- " + shellSingleQuote(prefix)
	if cands := runCompletionCommand("bash", []string{"-lc", script}); len(cands) > 0 {
		return markDirectoryPathCandidates(cands)
	}
	return completeLocalPathFallback(prefix)
}

func runCompletionCommand(name string, args []string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
	seen := map[string]struct{}{}
	cands := make([]string, 0, len(lines))
	for _, line := range lines {
		v := strings.TrimSpace(line)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		cands = append(cands, v)
	}
	sort.Strings(cands)
	if len(cands) > 100 {
		return cands[:100]
	}
	return cands
}

func psSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func completeLocalPathFallback(prefix string) []string {
	pattern := prefix + "*"
	if strings.TrimSpace(prefix) == "" {
		pattern = "*"
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	matches = markDirectoryPathCandidates(matches)
	sort.Strings(matches)
	return matches
}

func markDirectoryPathCandidates(cands []string) []string {
	out := make([]string, 0, len(cands))
	for _, cand := range cands {
		if cand == "" {
			continue
		}
		out = append(out, markDirectoryPathCandidate(cand))
	}
	sort.Strings(out)
	return out
}

func markDirectoryPathCandidate(candidate string) string {
	if strings.HasSuffix(candidate, "/") || strings.HasSuffix(candidate, "\\") {
		return candidate
	}
	st, err := os.Stat(expandUserPathForStat(candidate))
	if err != nil || !st.IsDir() {
		return candidate
	}
	return filepath.ToSlash(candidate) + "/"
}

func expandUserPathForStat(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") && !strings.HasPrefix(path, `~\`) {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, path[2:])
}

func completePathExecutables(prefix string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	sort.Strings(out)
	if len(out) > 100 {
		return out[:100]
	}
	return out
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

func envUsage(commandPrefix string) {
	commandPrefix = normalizeREPLPrefix(commandPrefix)
	fmt.Fprintln(os.Stdout, "secssh environment command list:")
	for _, line := range []string{
		"unlock",
		"lock",
		"status",
		"ssh <target> -- [ssh args...]",
		"scp [-r] <src> <dst> -- [scp args...]",
		"sftp <target> -- [sftp args...]",
		"config set --file <path>",
		"config show",
		"key add <name> --file <private_key>",
		"key gen <name> [--type ed25519|rsa] [--bits 4096] [--comment <text>]",
		"key copy <name> <host-alias> [--auth ... --prompt --use-secret ...]",
		"key list",
		"key rm <name>",
		"secret add <name>",
		"secret rm <name>",
		"secret list",
		"host add <alias> --hostname <host> [--port 22] [--user <user>] [--key <key-name>] [--password|--password-value <value>]",
		"host rm <alias>",
		"host list",
		"host auth set <alias> ...",
		"passwd",
		"crypto show",
		"crypto set --kdf argon2id --cipher aes-256-gcm",
		"version",
		"history [clear|limit <n>]",
		"help",
		"exit",
	} {
		fmt.Fprintf(os.Stdout, "  %s%s\n", commandPrefix, line)
	}
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "Bare commands run in the host shell. Bare cd [path] changes the secssh environment directory.")
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
	case "history":
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
	default:
		fmt.Fprintf(os.Stdout, "no help for %s\n", name)
	}
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
