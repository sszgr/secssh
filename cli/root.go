package cli

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sszgr/secssh/crypto"
	"github.com/sszgr/secssh/host"
	"github.com/sszgr/secssh/runner"
	"github.com/sszgr/secssh/secret"
	"github.com/sszgr/secssh/sshkey"
	"github.com/sszgr/secssh/vault"
	"github.com/sszgr/secssh/workspace"
	"golang.org/x/term"
)

type vaultRef struct {
	Source   string
	Path     string
	ReadOnly bool
}

func Run(args []string) int {
	args, sourceArg, err := parseVaultArg(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	source, err := vault.ResolveSource(sourceArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve vault source failed: %v\n", err)
		return 1
	}
	ref := vaultRef{
		Source:   source.Input,
		Path:     source.Path,
		ReadOnly: source.ReadOnly,
	}
	workspace.CleanupRuntimeArtifacts()
	app := workspace.NewSessionManager(ref.Source, 10*time.Minute)
	if len(args) == 0 {
		return runREPL(app, ref)
	}
	return runCommand(args, app, ref)
}

func runCommand(args []string, app *workspace.SessionManager, ref vaultRef) int {
	root := newRootCommand(app, ref)
	root.SetArgs(args)
	root.SilenceUsage = true
	root.SilenceErrors = true
	if err := root.Execute(); err != nil {
		var coded *cliCodeError
		if errors.As(err, &coded) {
			return coded.code
		}
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}

type cliCodeError struct{ code int }

func (e *cliCodeError) Error() string { return fmt.Sprintf("exit code %d", e.code) }

func codeErr(code int) error {
	if code == 0 {
		return nil
	}
	return &cliCodeError{code: code}
}

func newRootCommand(app *workspace.SessionManager, ref vaultRef) *cobra.Command {
	root := &cobra.Command{
		Use:   "secssh",
		Short: "Encrypted closed SSH workspace manager",
	}
	root.PersistentFlags().String("vault", "", "vault file path or remote http(s) URL")

	root.AddCommand(&cobra.Command{
		Use:   "unlock",
		Short: "Unlock vault session",
		RunE:  func(cmd *cobra.Command, args []string) error { return codeErr(cmdUnlock(app, ref)) },
	})
	root.AddCommand(&cobra.Command{
		Use:   "lock",
		Short: "Lock vault session",
		RunE:  func(cmd *cobra.Command, args []string) error { return codeErr(cmdLock(app)) },
	})
	root.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show session status",
		RunE:  func(cmd *cobra.Command, args []string) error { return codeErr(cmdStatus(app)) },
	})

	sshCmd := &cobra.Command{
		Use:                "ssh <target> [-- [ssh args...]]",
		Short:              "Run OpenSSH through secssh workspace",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return codeErr(cmdSSH(args, app, ref))
		},
	}
	root.AddCommand(sshCmd)

	scpCmd := &cobra.Command{
		Use:                "scp <src> <dst> [-- [scp args...]]",
		Short:              "Run scp through secssh workspace",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return codeErr(cmdSCP(args, app, ref))
		},
	}
	root.AddCommand(scpCmd)

	sftpCmd := &cobra.Command{
		Use:                "sftp <target> [-- [sftp args...]]",
		Short:              "Run sftp through secssh workspace",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return codeErr(cmdSFTP(args, app, ref))
		},
	}
	root.AddCommand(sftpCmd)

	configCmd := &cobra.Command{Use: "config", Short: "Manage ssh_config in vault"}
	configCmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show stored ssh_config",
		RunE:  func(cmd *cobra.Command, args []string) error { return codeErr(cmdConfig([]string{"show"}, ref)) },
	})
	configSetFile := ""
	configSetCmd := &cobra.Command{
		Use:   "set",
		Short: "Set ssh_config from file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return codeErr(cmdConfig([]string{"set", "--file", configSetFile}, ref))
		},
	}
	configSetCmd.Flags().StringVar(&configSetFile, "file", "", "config file path")
	_ = configSetCmd.MarkFlagRequired("file")
	configCmd.AddCommand(configSetCmd)
	root.AddCommand(configCmd)

	keyCmd := &cobra.Command{Use: "key", Short: "Manage private keys"}
	keyAddName, keyAddFile := "", ""
	keyAddCmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add private key from file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyAddName = args[0]
			return codeErr(cmdKey([]string{"add", keyAddName, "--file", keyAddFile}, ref))
		},
	}
	keyAddCmd.Flags().StringVar(&keyAddFile, "file", "", "private key file path")
	_ = keyAddCmd.MarkFlagRequired("file")
	keyCmd.AddCommand(keyAddCmd)

	keyGenType, keyGenComment := "ed25519", ""
	keyGenBits := 4096
	keyGenCmd := &cobra.Command{
		Use:   "gen <name>",
		Short: "Generate key pair via ssh-keygen and store private key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			genArgs := []string{"gen", args[0], "--type", keyGenType, "--bits", fmt.Sprintf("%d", keyGenBits)}
			if strings.TrimSpace(keyGenComment) != "" {
				genArgs = append(genArgs, "--comment", keyGenComment)
			}
			return codeErr(cmdKey(genArgs, ref))
		},
	}
	keyGenCmd.Flags().StringVar(&keyGenType, "type", "ed25519", "key type: ed25519|rsa")
	keyGenCmd.Flags().IntVar(&keyGenBits, "bits", 4096, "key bits for rsa")
	keyGenCmd.Flags().StringVar(&keyGenComment, "comment", "", "public key comment")
	keyCmd.AddCommand(keyGenCmd)

	keyCopyAuth, keyCopySecret := "", ""
	keyCopyPrompt := false
	keyCopyCmd := &cobra.Command{
		Use:   "copy <key-name> <host-alias>",
		Short: "Copy selected key's public key to managed host",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			copyArgs := []string{"copy", args[0], args[1]}
			if strings.TrimSpace(keyCopyAuth) != "" {
				copyArgs = append(copyArgs, "--auth", keyCopyAuth)
			}
			if keyCopyPrompt {
				copyArgs = append(copyArgs, "--prompt")
			}
			if strings.TrimSpace(keyCopySecret) != "" {
				copyArgs = append(copyArgs, "--use-secret", keyCopySecret)
			}
			return codeErr(cmdKey(copyArgs, ref))
		},
	}
	keyCopyCmd.Flags().StringVar(&keyCopyAuth, "auth", "", "auth override: key|password|auto|ask")
	keyCopyCmd.Flags().BoolVar(&keyCopyPrompt, "prompt", false, "prompt password for this run")
	keyCopyCmd.Flags().StringVar(&keyCopySecret, "use-secret", "", "secret name for password mode")
	keyCmd.AddCommand(keyCopyCmd)

	keyCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List key names",
		RunE:  func(cmd *cobra.Command, args []string) error { return codeErr(cmdKey([]string{"list"}, ref)) },
	})
	keyCmd.AddCommand(&cobra.Command{
		Use:   "rm <name>",
		Short: "Remove key by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return codeErr(cmdKey([]string{"rm", args[0]}, ref))
		},
	})
	root.AddCommand(keyCmd)

	secretCmd := &cobra.Command{Use: "secret", Short: "Manage secrets"}
	secretCmd.AddCommand(&cobra.Command{
		Use:   "add <name>",
		Short: "Add secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return codeErr(cmdSecret([]string{"add", args[0]}, ref))
		},
	})
	secretCmd.AddCommand(&cobra.Command{
		Use:   "rm <name>",
		Short: "Remove secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return codeErr(cmdSecret([]string{"rm", args[0]}, ref))
		},
	})
	secretCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List secret names",
		RunE:  func(cmd *cobra.Command, args []string) error { return codeErr(cmdSecret([]string{"list"}, ref)) },
	})
	root.AddCommand(secretCmd)

	hostCmd := &cobra.Command{Use: "host", Short: "Manage host policies"}
	hostAddHostName, hostAddUser := "", ""
	hostAddPort := 22
	hostAddCmd := &cobra.Command{
		Use:   "add <alias>",
		Short: "Add managed host machine",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return codeErr(cmdHost([]string{"add", args[0], "--hostname", hostAddHostName, "--port", fmt.Sprintf("%d", hostAddPort), "--user", hostAddUser}, ref))
		},
	}
	hostAddCmd.Flags().StringVar(&hostAddHostName, "hostname", "", "remote host name or IP")
	hostAddCmd.Flags().IntVar(&hostAddPort, "port", 22, "ssh port")
	hostAddCmd.Flags().StringVar(&hostAddUser, "user", "", "default ssh user")
	_ = hostAddCmd.MarkFlagRequired("hostname")
	hostCmd.AddCommand(hostAddCmd)

	hostCmd.AddCommand(&cobra.Command{
		Use:   "rm <alias>",
		Short: "Remove managed host machine",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return codeErr(cmdHost([]string{"rm", args[0]}, ref))
		},
	})
	hostCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List managed hosts and connection history",
		RunE:  func(cmd *cobra.Command, args []string) error { return codeErr(cmdHost([]string{"list"}, ref)) },
	})
	hostAuthCmd := &cobra.Command{Use: "auth", Short: "Manage host auth policies"}
	mode, ppolicy, pref := "", "", ""
	hostAuthSetCmd := &cobra.Command{
		Use:   "set <alias>",
		Short: "Set host auth policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostArgs := []string{"auth", "set", args[0], "--mode", mode}
			if strings.TrimSpace(ppolicy) != "" {
				hostArgs = append(hostArgs, "--password-policy", ppolicy)
			}
			if strings.TrimSpace(pref) != "" {
				hostArgs = append(hostArgs, "--password-ref", pref)
			}
			return codeErr(cmdHost(hostArgs, ref))
		},
	}
	hostAuthSetCmd.Flags().StringVar(&mode, "mode", "", "auth mode: key|password|auto|ask")
	hostAuthSetCmd.Flags().StringVar(&ppolicy, "password-policy", "", "password policy: stored|prompt|session")
	hostAuthSetCmd.Flags().StringVar(&pref, "password-ref", "", "secret name for stored password")
	_ = hostAuthSetCmd.MarkFlagRequired("mode")
	hostAuthCmd.AddCommand(hostAuthSetCmd)
	hostCmd.AddCommand(hostAuthCmd)
	root.AddCommand(hostCmd)

	root.AddCommand(&cobra.Command{
		Use:   "passwd",
		Short: "Change vault password",
		RunE:  func(cmd *cobra.Command, args []string) error { return codeErr(cmdPasswd(ref)) },
	})

	cryptoCmd := &cobra.Command{Use: "crypto", Short: "Manage vault crypto settings"}
	cryptoCmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show current and supported crypto settings",
		RunE:  func(cmd *cobra.Command, args []string) error { return codeErr(cmdCrypto([]string{"show"}, ref)) },
	})
	kdf, cipher := "", ""
	cryptoSetCmd := &cobra.Command{
		Use:   "set",
		Short: "Set crypto settings with full re-encryption",
		RunE: func(cmd *cobra.Command, args []string) error {
			return codeErr(cmdCrypto([]string{"set", "--kdf", kdf, "--cipher", cipher}, ref))
		},
	}
	cryptoSetCmd.Flags().StringVar(&kdf, "kdf", "", "kdf name")
	cryptoSetCmd.Flags().StringVar(&cipher, "cipher", "", "cipher name")
	_ = cryptoSetCmd.MarkFlagRequired("kdf")
	_ = cryptoSetCmd.MarkFlagRequired("cipher")
	cryptoCmd.AddCommand(cryptoSetCmd)
	root.AddCommand(cryptoCmd)

	return root
}

func usage() {
	fmt.Println(`secssh command list:
 secssh unlock
  secssh lock
  secssh status
  secssh ssh <target> -- [ssh args...]
  secssh scp <src> <dst> -- [scp args...]
  secssh sftp <target> -- [sftp args...]
  secssh config set --file <path>
  secssh config show
  secssh key add <name> --file <private_key>
  secssh key gen <name> [--type ed25519|rsa] [--bits 4096] [--comment <text>]
  secssh key copy <name> <host-alias> [--auth ... --prompt --use-secret ...]
  secssh key list
  secssh key rm <name>
  secssh secret add <name>
  secssh secret rm <name>
  secssh secret list
  secssh host add <alias> --hostname <host> [--port 22] [--user <user>]
  secssh host rm <alias>
  secssh host list
  secssh host auth set <alias> ...
  secssh passwd
  secssh crypto show
  secssh crypto set --kdf argon2id --cipher aes-256-gcm`)
}

func cmdUnlock(mgr *workspace.SessionManager, ref vaultRef) int {
	if !vault.Exists(ref.Path) {
		if ref.ReadOnly {
			fmt.Fprintf(os.Stderr, "create vault failed: remote vault source is read-only: %s\n", ref.Source)
			return 1
		}
		newPassword, err := promptNewPassword()
		if err != nil {
			fmt.Fprintf(os.Stderr, "create vault failed: %v\n", err)
			return 1
		}
		if err := vault.Initialize(ref.Path, newPassword); err != nil {
			fmt.Fprintf(os.Stderr, "create vault failed: %v\n", err)
			return 1
		}
	}

	password, err := promptPassword("Vault password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "unlock failed: %v\n", err)
		return 1
	}
	if _, _, err := vault.Load(ref.Path, password); err != nil {
		fmt.Fprintf(os.Stderr, "unlock failed: %v\n", err)
		return 1
	}
	if err := mgr.Unlock(); err != nil {
		fmt.Fprintf(os.Stderr, "unlock failed: %v\n", err)
		return 1
	}
	exp, err := mgr.ExpiresAt()
	if err == nil {
		workspace.PutVaultPassword(ref.Path, password, exp)
	}
	fmt.Println("unlocked")
	return 0
}

func cmdLock(mgr *workspace.SessionManager) int {
	if err := mgr.Lock(); err != nil {
		fmt.Fprintf(os.Stderr, "lock failed: %v\n", err)
		return 1
	}
	workspace.ClearVaultPasswords()
	workspace.ClearPasswordCache()
	workspace.CleanupRuntimeArtifacts()
	fmt.Println("locked")
	return 0
}

func cmdStatus(mgr *workspace.SessionManager) int {
	st, err := mgr.Status()
	if err != nil {
		fmt.Fprintf(os.Stderr, "status failed: %v\n", err)
		return 1
	}
	if st.Unlocked {
		fmt.Printf("status: unlocked\nttl_remaining: %s\nvault: %s\n", st.TTLRemaining.Round(time.Second), st.VaultPath)
		return 0
	}
	fmt.Printf("status: locked\nttl_remaining: 0s\nvault: %s\n", st.VaultPath)
	return 0
}

func cmdSSH(args []string, mgr *workspace.SessionManager, ref vaultRef) int {
	parsed, err := parseTransportArgs(args, 1)
	if err != nil {
		fmt.Fprintln(os.Stderr, "usage: secssh ssh <target> [--auth ... --prompt --use-secret ...] -- [ssh args...]")
		return 2
	}
	return runRemoteCommand("ssh", mgr, ref, parsed, func(opts runner.Options) error {
		return runner.RunSSH(opts)
	})
}

func splitTransportArgs(args []string) (runnerArgs []string, passArgs []string) {
	for i, v := range args {
		if v == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

type transportArgs struct {
	Targets   []string
	AuthMode  string
	Prompt    bool
	UseSecret string
	PassArgs  []string
}

func parseTransportArgs(args []string, targetCount int) (*transportArgs, error) {
	runnerArgs, passArgs := splitTransportArgs(args)
	parsed := &transportArgs{PassArgs: passArgs}
	for i := 0; i < len(runnerArgs); i++ {
		arg := runnerArgs[i]
		switch arg {
		case "--auth":
			if i+1 >= len(runnerArgs) {
				return nil, errors.New("--auth requires a value")
			}
			parsed.AuthMode = runnerArgs[i+1]
			i++
		case "--prompt":
			parsed.Prompt = true
		case "--use-secret":
			if i+1 >= len(runnerArgs) {
				return nil, errors.New("--use-secret requires a value")
			}
			parsed.UseSecret = runnerArgs[i+1]
			i++
		default:
			parsed.Targets = append(parsed.Targets, arg)
		}
	}
	if len(parsed.Targets) != targetCount {
		return nil, fmt.Errorf("expected %d target arguments", targetCount)
	}
	if parsed.AuthMode != "" {
		if _, err := host.ParseAuthMode(parsed.AuthMode); err != nil {
			return nil, err
		}
	}
	return parsed, nil
}

func cmdSFTP(args []string, mgr *workspace.SessionManager, ref vaultRef) int {
	parsed, err := parseTransportArgs(args, 1)
	if err != nil {
		fmt.Fprintln(os.Stderr, "usage: secssh sftp <target> [--auth ... --prompt --use-secret ...] -- [sftp args...]")
		return 2
	}
	return runRemoteCommand("sftp", mgr, ref, parsed, func(opts runner.Options) error {
		return runner.RunSFTP(opts, parsed.Targets[0])
	})
}

func cmdSCP(args []string, mgr *workspace.SessionManager, ref vaultRef) int {
	parsed, err := parseTransportArgs(args, 2)
	if err != nil {
		fmt.Fprintln(os.Stderr, "usage: secssh scp <src> <dst> [--auth ... --prompt --use-secret ...] -- [scp args...]")
		return 2
	}
	target, err := resolveSCPRemoteTarget(parsed.Targets[0], parsed.Targets[1])
	if err != nil {
		return cmdErr("scp", err)
	}
	parsed.Targets = []string{target, parsed.Targets[0], parsed.Targets[1]}
	return runRemoteCommand("scp", mgr, ref, parsed, func(opts runner.Options) error {
		return runner.RunSCP(opts, parsed.Targets[1], parsed.Targets[2])
	})
}

func cmdConfig(args []string, ref vaultRef) int {
	if len(args) == 0 {
		return usageErr("usage: secssh config set|show")
	}
	switch args[0] {
	case "show":
		header, payload, password, err := loadVaultInteractive(ref)
		if err != nil {
			return cmdErr("config show", err)
		}
		_ = header
		_ = password
		fmt.Println(payload.SSHConfig)
		return 0
	case "set":
		fs := flag.NewFlagSet("config set", flag.ContinueOnError)
		file := fs.String("file", "", "config file")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *file == "" {
			return usageErr("--file is required")
		}
		content, err := os.ReadFile(*file)
		if err != nil {
			return cmdErr("config set", err)
		}
		if err := ensureWritable(ref, "config set"); err != nil {
			return cmdErr("config set", err)
		}
		header, payload, password, err := loadVaultInteractive(ref)
		if err != nil {
			return cmdErr("config set", err)
		}
		payload.SSHConfig = string(content)
		if err := saveVault(ref, password, header, payload); err != nil {
			return cmdErr("config set", err)
		}
		fmt.Println("config updated")
		return 0
	default:
		return usageErr("usage: secssh config set|show")
	}
}

func runRemoteCommand(op string, mgr *workspace.SessionManager, ref vaultRef, parsed *transportArgs, invoke func(opts runner.Options) error) int {
	if err := mgr.RequireUnlocked(); err != nil {
		fmt.Fprintf(os.Stderr, "%s failed: %v\n", op, err)
		return 1
	}
	target := strings.TrimSpace(parsed.Targets[0])
	header, payload, password, err := loadVaultInteractive(ref)
	if err != nil {
		return cmdErr(op, err)
	}
	exp, err := mgr.ExpiresAt()
	if err != nil {
		exp = time.Time{}
	}
	runPayload := *payload
	runPayload.SSHConfig = mergeManagedHostsConfig(payload.SSHConfig, payload.Machines)

	if err := invoke(runner.Options{
		Target:     target,
		AuthMode:   parsed.AuthMode,
		Prompt:     parsed.Prompt,
		UseSecret:  strings.TrimSpace(parsed.UseSecret),
		PassArgs:   parsed.PassArgs,
		Vault:      &runPayload,
		VaultPath:  ref.Path,
		SessionExp: exp.Unix(),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "%s failed: %v\n", op, err)
		return 1
	}
	if ref.ReadOnly {
		fmt.Fprintf(os.Stderr, "warning: remote vault is read-only; connection history was not persisted\n")
		return 0
	}
	recordHostConnection(payload, target, resolveAuthModeForRecord(payload, target, parsed.AuthMode))
	if err := saveVault(ref, password, header, payload); err != nil {
		return cmdErr(op, err)
	}
	return 0
}

func cmdKey(args []string, ref vaultRef) int {
	if len(args) == 0 {
		return usageErr("usage: secssh key add|gen|copy|list|rm")
	}
	switch args[0] {
	case "add":
		if len(args) < 2 {
			return usageErr("usage: secssh key add <name> --file <private_key>")
		}
		name := strings.TrimSpace(args[1])
		if name == "" {
			return usageErr("key name is required")
		}
		fs := flag.NewFlagSet("key add", flag.ContinueOnError)
		file := fs.String("file", "", "private key path")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		if *file == "" {
			return usageErr("--file is required")
		}
		keyBytes, err := os.ReadFile(*file)
		if err != nil {
			return cmdErr("key add", err)
		}
		if err := ensureWritable(ref, "key add"); err != nil {
			return cmdErr("key add", err)
		}
		header, payload, password, err := loadVaultInteractive(ref)
		if err != nil {
			return cmdErr("key add", err)
		}
		payload.Keys[name] = keyBytes
		if err := saveVault(ref, password, header, payload); err != nil {
			return cmdErr("key add", err)
		}
		fmt.Println("key added")
		return 0
	case "gen":
		if len(args) < 2 {
			return usageErr("usage: secssh key gen <name> [--type ed25519|rsa] [--bits 4096] [--comment <text>]")
		}
		name := strings.TrimSpace(args[1])
		if name == "" {
			return usageErr("key name is required")
		}
		fs := flag.NewFlagSet("key gen", flag.ContinueOnError)
		keyType := fs.String("type", "ed25519", "key type: ed25519|rsa")
		bits := fs.Int("bits", 4096, "key bits for rsa")
		comment := fs.String("comment", "", "public key comment")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		if err := ensureWritable(ref, "key gen"); err != nil {
			return cmdErr("key gen", err)
		}
		header, payload, password, err := loadVaultInteractive(ref)
		if err != nil {
			return cmdErr("key gen", err)
		}
		if _, exists := payload.Keys[name]; exists {
			return cmdErr("key gen", fmt.Errorf("key already exists: %s", name))
		}
		privateKey, publicKey, err := sshkey.GeneratePair(*keyType, *bits, *comment)
		if err != nil {
			return cmdErr("key gen", err)
		}
		payload.Keys[name] = privateKey
		payload.KeyPublics[name] = strings.TrimSpace(string(publicKey))
		if err := saveVault(ref, password, header, payload); err != nil {
			return cmdErr("key gen", err)
		}
		fmt.Println("key generated and added")
		fmt.Printf("public key (%s):\n%s", name, string(publicKey))
		if !strings.HasSuffix(string(publicKey), "\n") {
			fmt.Println()
		}
		return 0
	case "copy":
		if len(args) < 3 {
			return usageErr("usage: secssh key copy <name> <host-alias> [--auth ... --prompt --use-secret ...]")
		}
		keyName := strings.TrimSpace(args[1])
		target := strings.TrimSpace(args[2])
		fs := flag.NewFlagSet("key copy", flag.ContinueOnError)
		auth := fs.String("auth", "", "auth override: key|password|auto|ask")
		prompt := fs.Bool("prompt", false, "prompt password for this run")
		useSecret := fs.String("use-secret", "", "secret name for password mode")
		if err := fs.Parse(args[3:]); err != nil {
			return 2
		}
		if *auth != "" {
			if _, err := host.ParseAuthMode(*auth); err != nil {
				return usageErr(err.Error())
			}
		}
		if err := ensureWritable(ref, "key copy"); err != nil {
			return cmdErr("key copy", err)
		}
		header, payload, password, err := loadVaultInteractive(ref)
		if err != nil {
			return cmdErr("key copy", err)
		}
		if _, ok := payload.Keys[keyName]; !ok {
			return cmdErr("key copy", fmt.Errorf("key not found: %s", keyName))
		}
		if _, ok := payload.Machines[target]; !ok {
			return cmdErr("key copy", fmt.Errorf("host alias not found: %s (run 'secssh host add %s --hostname ...' first)", target, target))
		}
		pub := strings.TrimSpace(payload.KeyPublics[keyName])
		if pub == "" {
			return cmdErr("key copy", fmt.Errorf("public key for %s not found, please regenerate with 'secssh key gen %s ...'", keyName, keyName))
		}

		runPayload := *payload
		runPayload.SSHConfig = mergeManagedHostsConfig(payload.SSHConfig, payload.Machines)
		cmdline := buildInstallAuthorizedKeyCommand(pub)
		if err := runner.RunSSH(runner.Options{
			Target:     target,
			AuthMode:   *auth,
			Prompt:     *prompt,
			UseSecret:  strings.TrimSpace(*useSecret),
			PassArgs:   []string{cmdline},
			Vault:      &runPayload,
			VaultPath:  ref.Path,
			SessionExp: time.Now().Add(10 * time.Minute).Unix(),
		}); err != nil {
			return cmdErr("key copy", err)
		}
		m := payload.Machines[target]
		m.KeyRef = keyName
		payload.Machines[target] = m
		recordHostConnection(payload, target, resolveAuthModeForRecord(payload, target, *auth))
		if err := saveVault(ref, password, header, payload); err != nil {
			return cmdErr("key copy", err)
		}
		fmt.Printf("public key %s copied to host %s (bound key=%s)\n", keyName, target, keyName)
		return 0
	case "list":
		_, payload, _, err := loadVaultInteractive(ref)
		if err != nil {
			return cmdErr("key list", err)
		}
		names := sortedBytesMapKeys(payload.Keys)
		for _, n := range names {
			fmt.Println(n)
		}
		return 0
	case "rm":
		if len(args) < 2 {
			return usageErr("usage: secssh key rm <name>")
		}
		name := strings.TrimSpace(args[1])
		if err := ensureWritable(ref, "key rm"); err != nil {
			return cmdErr("key rm", err)
		}
		header, payload, password, err := loadVaultInteractive(ref)
		if err != nil {
			return cmdErr("key rm", err)
		}
		delete(payload.Keys, name)
		delete(payload.KeyPublics, name)
		if err := saveVault(ref, password, header, payload); err != nil {
			return cmdErr("key rm", err)
		}
		fmt.Println("key removed")
		return 0
	default:
		return usageErr("usage: secssh key add|gen|copy|list|rm")
	}
}

func cmdSecret(args []string, ref vaultRef) int {
	if len(args) == 0 {
		return usageErr("usage: secssh secret add|rm|list")
	}
	switch args[0] {
	case "add":
		if len(args) < 2 {
			return usageErr("usage: secssh secret add <name>")
		}
		name := secret.NormalizeName(args[1])
		if name == "" {
			return usageErr("secret name is required")
		}
		value, err := promptPassword("Secret value: ")
		if err != nil {
			return cmdErr("secret add", err)
		}
		if err := ensureWritable(ref, "secret add"); err != nil {
			return cmdErr("secret add", err)
		}
		header, payload, password, err := loadVaultInteractive(ref)
		if err != nil {
			return cmdErr("secret add", err)
		}
		payload.Secrets[name] = string(value)
		if err := saveVault(ref, password, header, payload); err != nil {
			return cmdErr("secret add", err)
		}
		fmt.Println("secret added")
		return 0
	case "rm":
		if len(args) < 2 {
			return usageErr("usage: secssh secret rm <name>")
		}
		name := secret.NormalizeName(args[1])
		if err := ensureWritable(ref, "secret rm"); err != nil {
			return cmdErr("secret rm", err)
		}
		header, payload, password, err := loadVaultInteractive(ref)
		if err != nil {
			return cmdErr("secret rm", err)
		}
		delete(payload.Secrets, name)
		if err := saveVault(ref, password, header, payload); err != nil {
			return cmdErr("secret rm", err)
		}
		fmt.Println("secret removed")
		return 0
	case "list":
		_, payload, _, err := loadVaultInteractive(ref)
		if err != nil {
			return cmdErr("secret list", err)
		}
		names := sortedStringMapKeys(payload.Secrets)
		for _, n := range names {
			fmt.Println(n)
		}
		return 0
	default:
		return usageErr("usage: secssh secret add|rm|list")
	}
}

func cmdHost(args []string, ref vaultRef) int {
	if len(args) == 0 {
		return usageErr("usage: secssh host add|rm|list|auth set ...")
	}
	switch args[0] {
	case "add":
		if len(args) < 2 {
			return usageErr("usage: secssh host add <alias> --hostname <host> [--port 22] [--user <user>]")
		}
		alias := strings.TrimSpace(args[1])
		if alias == "" {
			return usageErr("host alias is required")
		}
		fs := flag.NewFlagSet("host add", flag.ContinueOnError)
		hostname := fs.String("hostname", "", "remote host name or IP")
		user := fs.String("user", "", "ssh user")
		port := fs.Int("port", 22, "ssh port")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		if strings.TrimSpace(*hostname) == "" {
			return usageErr("--hostname is required")
		}
		if *port <= 0 || *port > 65535 {
			return usageErr("--port must be in range 1..65535")
		}
		if err := ensureWritable(ref, "host add"); err != nil {
			return cmdErr("host add", err)
		}
		header, payload, password, err := loadVaultInteractive(ref)
		if err != nil {
			return cmdErr("host add", err)
		}
		payload.Machines[alias] = vault.HostMachine{
			HostName: strings.TrimSpace(*hostname),
			User:     strings.TrimSpace(*user),
			Port:     *port,
		}
		if err := saveVault(ref, password, header, payload); err != nil {
			return cmdErr("host add", err)
		}
		fmt.Println("host added")
		return 0
	case "rm":
		if len(args) < 2 {
			return usageErr("usage: secssh host rm <alias>")
		}
		alias := strings.TrimSpace(args[1])
		if err := ensureWritable(ref, "host rm"); err != nil {
			return cmdErr("host rm", err)
		}
		header, payload, password, err := loadVaultInteractive(ref)
		if err != nil {
			return cmdErr("host rm", err)
		}
		delete(payload.Machines, alias)
		delete(payload.Hosts, alias)
		delete(payload.Connections, alias)
		if err := saveVault(ref, password, header, payload); err != nil {
			return cmdErr("host rm", err)
		}
		fmt.Println("host removed")
		return 0
	case "list":
		_, payload, _, err := loadVaultInteractive(ref)
		if err != nil {
			return cmdErr("host list", err)
		}
		names := sortedHostListKeys(payload.Machines, payload.Connections)
		if len(names) == 0 {
			fmt.Println("(no host records)")
			return 0
		}
		for _, name := range names {
			m := payload.Machines[name]
			a := payload.Hosts[name]
			c := payload.Connections[name]
			fmt.Printf("%s\thost=%s\tuser=%s\tport=%d\tkey=%s\tauth=%s\tcount=%d\tlast=%s\n",
				name,
				defaultText(m.HostName, "-"),
				defaultText(m.User, "-"),
				portOrDefault(m.Port, 22),
				defaultText(m.KeyRef, "-"),
				defaultText(a.Mode, "auto"),
				c.ConnectCount,
				defaultText(c.LastConnectedAt, "-"),
			)
		}
		return 0
	case "auth":
		if len(args) < 3 || args[1] != "set" {
			return usageErr("usage: secssh host auth set <alias> --mode <key|password|auto|ask> [--password-policy ... --password-ref ...]")
		}
		alias := strings.TrimSpace(args[2])
		if alias == "" {
			return usageErr("host alias is required")
		}

		fs := flag.NewFlagSet("host auth set", flag.ContinueOnError)
		mode := fs.String("mode", "", "auth mode")
		passwordPolicy := fs.String("password-policy", "", "password policy")
		passwordRef := fs.String("password-ref", "", "password secret ref")
		if err := fs.Parse(args[3:]); err != nil {
			return 2
		}
		if _, err := host.ParseAuthMode(*mode); err != nil {
			return usageErr(err.Error())
		}
		if *passwordPolicy != "" {
			if _, err := host.ParsePasswordPolicy(*passwordPolicy); err != nil {
				return usageErr(err.Error())
			}
		}
		if *mode == "password" && strings.TrimSpace(*passwordRef) == "" && *passwordPolicy == "stored" {
			return usageErr("--password-ref is required when mode=password and password-policy=stored")
		}

		if err := ensureWritable(ref, "host auth set"); err != nil {
			return cmdErr("host auth set", err)
		}
		header, payload, password, err := loadVaultInteractive(ref)
		if err != nil {
			return cmdErr("host auth set", err)
		}
		if _, ok := payload.Machines[alias]; !ok {
			return cmdErr("host auth set", fmt.Errorf("host alias not found: %s (run 'secssh host add %s --hostname ...' first)", alias, alias))
		}

		payload.Hosts[alias] = vault.HostAuth{
			Mode:           *mode,
			PasswordPolicy: *passwordPolicy,
			PasswordRef:    strings.TrimSpace(*passwordRef),
		}
		if err := saveVault(ref, password, header, payload); err != nil {
			return cmdErr("host auth set", err)
		}
		fmt.Println("host auth updated")
		return 0
	default:
		return usageErr("usage: secssh host add|rm|list|auth set ...")
	}
}

func cmdPasswd(ref vaultRef) int {
	if err := ensureWritable(ref, "passwd"); err != nil {
		return cmdErr("passwd", err)
	}
	if !vault.Exists(ref.Path) {
		return cmdErr("passwd", errors.New("vault does not exist, run secssh unlock first"))
	}
	oldPassword, err := promptPassword("Current vault password: ")
	if err != nil {
		return cmdErr("passwd", err)
	}
	newPassword, err := promptNewPassword()
	if err != nil {
		return cmdErr("passwd", err)
	}
	if err := vault.ChangePassword(ref.Path, oldPassword, newPassword); err != nil {
		return cmdErr("passwd", err)
	}
	fmt.Println("vault password updated")
	return 0
}

func cmdCrypto(args []string, ref vaultRef) int {
	if len(args) == 0 {
		return usageErr("usage: secssh crypto show|set")
	}
	switch args[0] {
	case "show":
		h, err := vault.LoadHeader(ref.Path)
		if err == nil {
			fmt.Printf("current kdf: %s\n", h.KDFType)
			fmt.Printf("current cipher: %s\n", h.CipherType)
		}
		fmt.Printf("kdf options: %s\n", strings.Join(crypto.SupportedKDFNames(), ", "))
		fmt.Printf("cipher options: %s\n", strings.Join(crypto.SupportedCipherNames(), ", "))
		return 0
	case "set":
		fs := flag.NewFlagSet("crypto set", flag.ContinueOnError)
		kdf := fs.String("kdf", "", "kdf name")
		cipher := fs.String("cipher", "", "cipher name")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *kdf == "" || *cipher == "" {
			return usageErr("--kdf and --cipher are required")
		}
		if !crypto.IsSupportedKDF(*kdf) {
			return usageErr("unsupported kdf")
		}
		if !crypto.IsSupportedCipher(*cipher) {
			return usageErr("unsupported cipher")
		}
		if err := ensureWritable(ref, "crypto set"); err != nil {
			return cmdErr("crypto set", err)
		}
		password, err := promptPassword("Vault password: ")
		if err != nil {
			return cmdErr("crypto set", err)
		}
		if err := vault.ChangeCrypto(ref.Path, password, *kdf, *cipher); err != nil {
			return cmdErr("crypto set", err)
		}
		fmt.Println("crypto policy updated")
		return 0
	default:
		return usageErr("usage: secssh crypto show|set")
	}
}

func loadVaultInteractive(ref vaultRef) (*vault.FileHeader, *vault.Payload, []byte, error) {
	if !vault.Exists(ref.Path) {
		return nil, nil, nil, errors.New("vault does not exist, run secssh unlock first")
	}

	if cached, ok := workspace.GetVaultPassword(ref.Path, time.Now()); ok {
		header, payload, err := vault.Load(ref.Path, cached)
		if err == nil {
			return header, payload, cached, nil
		}
		workspace.ClearVaultPasswords()
	}

	password, err := promptPassword("Vault password: ")
	if err != nil {
		return nil, nil, nil, err
	}
	header, payload, err := vault.Load(ref.Path, password)
	if err != nil {
		return nil, nil, nil, err
	}
	workspace.PutVaultPassword(ref.Path, password, time.Now().Add(10*time.Minute))
	return header, payload, password, nil
}

func saveVault(ref vaultRef, password []byte, header *vault.FileHeader, payload *vault.Payload) error {
	params := header.KDFParams
	return vault.Save(ref.Path, password, payload, vault.SaveOptions{
		KDFType:    header.KDFType,
		CipherType: header.CipherType,
		KDFParams:  &params,
	})
}

func ensureWritable(ref vaultRef, action string) error {
	if !ref.ReadOnly {
		return nil
	}
	return fmt.Errorf("%s is not supported for remote vault sources; use a local vault path instead", action)
}

func parseVaultArg(args []string) ([]string, string, error) {
	clean := make([]string, 0, len(args))
	var source string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--vault" {
			if i+1 >= len(args) {
				return nil, "", errors.New("--vault requires a value")
			}
			source = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(arg, "--vault=") {
			source = strings.TrimPrefix(arg, "--vault=")
			continue
		}
		clean = append(clean, arg)
	}
	return clean, source, nil
}

func promptNewPassword() ([]byte, error) {
	p1, err := promptPassword("New vault password: ")
	if err != nil {
		return nil, err
	}
	p2, err := promptPassword("Confirm new vault password: ")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(p1, p2) {
		return nil, errors.New("password confirmation mismatch")
	}
	if len(bytes.TrimSpace(p1)) == 0 {
		return nil, errors.New("empty password")
	}
	return p1, nil
}

func promptPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stdout, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stdout)
		if err != nil {
			return nil, err
		}
		return bytes.TrimSpace(pw), nil
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace([]byte(line)), nil
}

func sortedBytesMapKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedStringMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedHostMachineKeys(m map[string]vault.HostMachine) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedHostListKeys(machines map[string]vault.HostMachine, connections map[string]vault.HostConnection) []string {
	seen := map[string]struct{}{}
	for k := range machines {
		seen[k] = struct{}{}
	}
	for k := range connections {
		seen[k] = struct{}{}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func mergeManagedHostsConfig(base string, machines map[string]vault.HostMachine) string {
	if len(machines) == 0 {
		return base
	}
	var b strings.Builder
	b.WriteString(base)
	if !strings.HasSuffix(base, "\n") {
		b.WriteByte('\n')
	}
	names := sortedHostMachineKeys(machines)
	for _, alias := range names {
		m := machines[alias]
		if strings.TrimSpace(m.HostName) == "" {
			continue
		}
		b.WriteString("Host ")
		b.WriteString(alias)
		b.WriteByte('\n')
		b.WriteString("  HostName ")
		b.WriteString(m.HostName)
		b.WriteByte('\n')
		if strings.TrimSpace(m.User) != "" {
			b.WriteString("  User ")
			b.WriteString(m.User)
			b.WriteByte('\n')
		}
		if m.Port > 0 {
			b.WriteString("  Port ")
			b.WriteString(fmt.Sprintf("%d", m.Port))
			b.WriteByte('\n')
		}
		if strings.TrimSpace(m.KeyRef) != "" {
			b.WriteString("  IdentityFile secssh://keys/")
			b.WriteString(strings.TrimSpace(m.KeyRef))
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func buildInstallAuthorizedKeyCommand(pub string) string {
	key := strings.TrimSpace(pub)
	quoted := shellSingleQuote(key)
	return "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; grep -qxF " + quoted +
		" ~/.ssh/authorized_keys || printf '%s\\n' " + quoted + " >> ~/.ssh/authorized_keys"
}

func resolveSCPRemoteTarget(src, dst string) (string, error) {
	srcHost, srcRemote := remoteHostFromSpec(src)
	dstHost, dstRemote := remoteHostFromSpec(dst)
	switch {
	case srcRemote && !dstRemote:
		return srcHost, nil
	case !srcRemote && dstRemote:
		return dstHost, nil
	case srcRemote && dstRemote && srcHost == dstHost:
		return srcHost, nil
	case srcRemote || dstRemote:
		return "", errors.New("scp currently supports one remote endpoint, or the same remote alias on both sides")
	default:
		return "", errors.New("scp requires at least one remote endpoint")
	}
}

func remoteHostFromSpec(spec string) (string, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", false
	}
	if strings.HasPrefix(spec, "scp://") {
		u, err := url.Parse(spec)
		if err != nil || strings.TrimSpace(u.Host) == "" {
			return "", false
		}
		host := u.Hostname()
		return strings.TrimSpace(host), host != ""
	}
	if strings.HasPrefix(spec, "-") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") {
		return "", false
	}
	colon := strings.Index(spec, ":")
	if colon <= 0 {
		return "", false
	}
	head := spec[:colon]
	if strings.Contains(head, "/") {
		return "", false
	}
	if at := strings.LastIndex(head, "@"); at >= 0 {
		head = head[at+1:]
	}
	head = strings.TrimSpace(head)
	return head, head != ""
}

func shellSingleQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func recordHostConnection(payload *vault.Payload, target, authMode string) {
	if payload.Connections == nil {
		payload.Connections = map[string]vault.HostConnection{}
	}
	entry := payload.Connections[target]
	entry.ConnectCount++
	entry.LastConnectedAt = time.Now().UTC().Format(time.RFC3339)
	entry.LastAuthMode = authMode
	payload.Connections[target] = entry
}

func resolveAuthModeForRecord(payload *vault.Payload, target, override string) string {
	mode := strings.TrimSpace(override)
	if mode != "" {
		return mode
	}
	if payload != nil {
		if h, ok := payload.Hosts[target]; ok && strings.TrimSpace(h.Mode) != "" {
			return strings.TrimSpace(h.Mode)
		}
	}
	return "auto"
}

func defaultText(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func portOrDefault(port, fallback int) int {
	if port <= 0 {
		return fallback
	}
	return port
}

func usageErr(msg string) int {
	fmt.Fprintln(os.Stderr, msg)
	return 2
}

func cmdErr(op string, err error) int {
	fmt.Fprintf(os.Stderr, "%s failed: %v\n", op, err)
	return 1
}
