# secssh

`secssh` is an encrypted SSH workspace manager built with Go.

It stores your SSH config, private keys, and secrets in an encrypted vault, while delegating all SSH protocol behavior to system OpenSSH.

## Features

- Encrypted vault storage (`~/.secssh/vault.enc`) for:
  - full `ssh_config`
  - private keys
  - key public parts (for key copy workflows)
  - secrets/passwords
  - host auth policy and host machine metadata
  - host connection history
- Crypto:
  - KDF: `argon2id` (default), `pbkdf2-sha256`
  - Cipher: `aes-256-gcm` (default), `xchacha20-poly1305`
  - full re-encryption on password/crypto change
  - atomic writes (`tmp` -> `fsync` -> `rename`)
- OpenSSH-compatible runtime:
  - no custom SSH protocol implementation
  - runtime temp config and temp key materialization
  - supports `IdentityFile secssh://keys/<name>` indirection
- Host and auth management:
  - managed host aliases (`host add/rm/list`)
  - per-host auth policy (`key|password|auto|ask`)
  - optional password policies (`stored|prompt|session`)
- Interactive shell:
  - run `secssh` directly for `secssh>` mode
  - TAB completion
  - `Ctrl-C` interrupts current input (does not exit)
  - `Ctrl-D` exits shell

## Requirements

- Go `1.24+`
- OpenSSH client tools (`ssh`)
- `ssh-keygen` (for `key gen` and related workflows)
- Linux/macOS preferred

## Build

Use Make targets:

```bash
make build
make test
make build-one PLATFORM=linux/amd64 VERSION=v0.1.0
make build-cross VERSION=v0.1.0
```

Output:

- local build: `bin/secssh-<version>`
- cross builds: `dist/secssh-<version>-<os>-<arch>[.exe]`

## Quick Start

Initialize/unlock vault:

```bash
secssh unlock
```

Add a managed host:

```bash
secssh host add prod --hostname 10.0.0.10 --user root --port 22
```

Generate and copy key to host:

```bash
secssh key gen prod-key
secssh key copy prod-key prod
```

Set host auth mode and connect:

```bash
secssh host auth set prod --mode key
secssh ssh prod
```

Inspect host records/history:

```bash
secssh host list
```

## Command Summary

```text
secssh unlock
secssh lock
secssh status

secssh ssh <target> -- [ssh args...]

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
- Runtime key files are materialized with restrictive permissions and cleaned up.
- Vault writes are atomic to reduce corruption risk.
- Sensitive values are not intended to be logged.

## Project Docs

- Requirements: `docs/requirements.md`
- Design notes: `docs/design.md`

## Status

Project is functional for core workflows and actively evolving.
Issues and pull requests are welcome.
