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
- Interactive shell:
  - run `secssh` directly for `secssh>` mode
  - TAB completion
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
- OpenSSH client tools (`ssh`)
- `ssh-keygen` for `key gen` and related workflows
- Linux/macOS preferred

## Build

Use the provided Make targets:

```bash
make build
make test
make build-one PLATFORM=linux/amd64 VERSION=v0.1.0
make build-cross VERSION=v0.1.0
```

Build outputs:

- local build: `bin/secssh-<version>`
- cross builds: `dist/secssh-<version>-<os>-<arch>[.exe]`

## Quick Start

By default, `secssh` uses `./vault.enc` when it exists, otherwise it falls back to `~/.secssh/vault.enc`. You can also point `secssh` at a custom vault source with `--vault`. A remote `http(s)` vault is downloaded to a local cache and treated as read-only.

```bash
secssh --vault https://example.com/vault.enc status
```

Copy files with `scp` or open an `sftp` session through the same vault-managed runtime:

```bash
secssh scp local.txt prod:/tmp/local.txt
secssh sftp prod
```

Initialize or unlock the vault:

```bash
secssh unlock
```

Add a managed host:

```bash
secssh host add prod --hostname 10.0.0.10 --user root --port 22
```

Generate a key and copy it to the host:

```bash
secssh key gen prod-key
secssh key copy prod-key prod
```

Set the host auth mode and connect:

```bash
secssh host auth set prod --mode key
secssh ssh prod
```

Inspect stored hosts and history:

```bash
secssh host list
```

## Command Summary

```text
secssh --vault <path-or-url> <command>

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
secssh host auth set <alias> --mode <key|password|auto|ask> [...]

secssh passwd

secssh crypto show
secssh crypto set --kdf <name> --cipher <name>
```

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
