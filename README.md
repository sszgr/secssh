# secssh

**English** | [中文](./README.zh-CN.md)

`secssh` is an encrypted SSH workspace manager built with Go.

It keeps your SSH config, private keys, and optional secrets in an encrypted vault, then hands off actual connection behavior to system OpenSSH.

## Why secssh

Managing SSH access usually means scattering `ssh_config`, keys, and passwords across local files. `secssh` puts them behind one vault and gives you a consistent CLI for host, key, and auth workflows without replacing OpenSSH.

## Highlights

- Encrypted vault storage in `vault.enc` or `~/.secssh/vault.enc` for:
  - full `ssh_config`
  - private keys
  - public key parts for key-copy workflows
  - secrets/passwords
  - per-host auth policy and metadata
  - host connection history
- OpenSSH-compatible runtime:
  - no custom SSH protocol implementation
  - generates temporary config and key files at runtime
  - supports `IdentityFile secssh://keys/<name>` indirection
- Flexible crypto:
  - KDF: `argon2id` (default), `pbkdf2-sha256`
  - Cipher: `aes-256-gcm` (default), `xchacha20-poly1305`
  - full re-encryption on password or crypto changes
- Host and auth management:
  - managed host aliases with `host add/rm/list`
  - per-host auth mode: `key`, `password`, `auto`, `ask`
  - optional password policy: `stored`, `prompt`, `session`
- Environment shell:
  - run `secssh` directly for `(secssh) <cwd> >` mode
  - use `:<command>` for secssh built-ins by default, with a configurable prefix
  - run bare commands through the host shell
  - TAB completion for secssh commands, host commands, and paths; directories complete with `/`
  - bare `exit`/`quit` or `:exit`/`:quit` exits the shell
  - `Ctrl-C` interrupts current input without exiting
  - `Ctrl-D` exits the shell

## How It Works

`secssh` does not implement SSH itself. Instead, it:

1. unlocks and decrypts your vault
2. materializes temporary config and key files when needed
3. resolves host auth policy and runtime options
4. invokes system `ssh`
5. cleans up temporary artifacts

That keeps runtime behavior close to standard OpenSSH while centralizing sensitive material.

## Requirements

- Go `1.24+`
- OpenSSH client tools (`ssh`, `scp`, `sftp`)
- `ssh-keygen` for `key gen` and related workflows
- Linux/macOS preferred

## Build

Use the provided Make targets:

```bash
make build
make test
make run
make run PREFIX=.
make build-one PLATFORM=linux/amd64 VERSION=v0.1.0
make build-cross VERSION=v0.1.0
```

Build outputs:

- local build: `bin/secssh-<version>`
- cross builds: `dist/secssh-<version>-<os>-<arch>[.exe]`

## Quick Start

Initialize or unlock the vault:

```bash
secssh unlock
```

Generate a key:

```bash
secssh key gen prod-key
```

Add a managed host that will use that key:

```bash
secssh host add prod --hostname 10.0.0.10 --user root --port 22 --key prod-key
```

Copy the public key to the host, then switch the host to key auth and connect:

```bash
secssh key copy prod-key prod
secssh host auth set prod --mode key
secssh ssh prod
```

You can also add a managed host with a stored SSH password:

```bash
secssh host add prod --hostname 10.0.0.10 --user root --password
```

`--password-value <value>` is also available for scripts, but it is not recommended because the password can be exposed through shell history or process arguments.

Copy files with `scp` or open an `sftp` session through the same vault-managed runtime:

```bash
secssh scp local.txt prod:/tmp/local.txt
secssh sftp prod
```

Inspect stored hosts and connection history:

```bash
secssh host list
```

By default, `secssh` uses `./vault.enc` when it exists, otherwise it falls back to `~/.secssh/vault.enc`. Use `--vault` to choose a different local vault or a remote `http(s)` vault. Remote vaults are downloaded to a local cache and treated as read-only.

```bash
secssh --vault https://example.com/vault.enc status
```

## Command Summary

```text
secssh [--vault <path-or-url>] [--config <path>] [--prefix <char>] <command>

secssh unlock
secssh lock
secssh status
secssh version

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

secssh host add <alias> --hostname <host> [--port 22] [--user <user>] [--key <key-name>]
secssh host add <alias> --hostname <host> [--password|--password-value <value>] [--password-name <secret>]
secssh host rm <alias>
secssh host list
secssh host auth set <alias> --mode <key|password|auto|ask> [...]

secssh passwd

secssh crypto show
secssh crypto set --kdf <name> --cipher <name>
```

## Environment Shell

Run `secssh` without arguments to enter the environment shell. Inside this shell, secssh commands use a `:` prefix by default:

```text
(secssh) /work/project > :status
(secssh) /work/project > :host list
(secssh) /work/project > :ssh prod
(secssh) /work/project > :version
```

Bare commands are executed by the host shell:

```text
(secssh) /work/project > git status
(secssh) /work/project > cd /tmp
(secssh) /tmp > :scp local.txt prod:/tmp/
```

### Shell Configuration

You can change the secssh command prefix with `--prefix`, `SECSSH_PREFIX`, or a config file:

```bash
secssh --prefix .
SECSSH_PREFIX=. secssh
```

For a persistent setting, create `~/.secssh/config`:

```text
prefix=.
```

You can also choose a different config path:

```bash
secssh --config /path/to/config
SECSSH_CONFIG=/path/to/config secssh
```

The default config path is `~/.secssh/config`. Configuration precedence is `--prefix`, then `SECSSH_PREFIX`, then the config file, then the default `:`.

## Security Notes

- Secrets and private keys are encrypted at rest in the vault.
- Vault writes are atomic to reduce corruption risk.
- Runtime key files use restrictive permissions and are cleaned up after use.
- Sensitive values are not intended to be exposed in logs.
- Password and crypto changes trigger full vault re-encryption.

## Project Docs

- Requirements: `docs/requirements.md`
- Design notes: `docs/design.md`

## Status

The core workflows are functional and the project is still evolving.
Issues and pull requests are welcome.
