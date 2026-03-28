# secssh Requirements (MVP)

## Positioning

`secssh` is a closed SSH runtime environment manager:
- encrypted storage for `ssh_config`, private keys, and optional passwords
- OpenSSH-compatible runtime behavior
- vault password protected vault
- unlock session TTL
- vault password change
- crypto suite migration
- per-host auth policy (`key|password|auto|ask`)

## Vault

Default path: `~/.secssh/vault.enc`

Vault binary layout:
1. plaintext header:
   - `version`
   - `kdf_type`
   - `kdf_params` (`salt`, cost params)
   - `cipher_type`
   - `nonce`
2. ciphertext payload:
   - `ssh_config` (full text)
   - `keys` (private key collection)
   - `secrets` (password collection)
   - `hosts` (auth policies)
   - `metadata`

## Default crypto

- KDF: `argon2id`
- Cipher: `aes-256-gcm`

Supported in MVP:
- KDF: `argon2id`, `pbkdf2-sha256`
- Cipher: `aes-256-gcm`, `xchacha20-poly1305`

## Core command set

- session: `unlock`, `lock`, `status`
- runtime: `ssh <target> -- [ssh args...]`
- config: `config set`, `config show`
- key: `key add/list/rm`
- secret: `secret add/rm/list`
- host auth: `host auth set`
- vault password: `passwd`
- crypto: `crypto show`, `crypto set`

## Security constraints

- never log vault password, plaintext key, SSH password, derived key
- changing crypto suite requires full vault re-encryption
- changing vault password requires full vault re-encryption
- writes must be atomic (`tmp` + `fsync` + `rename`)
- failures must not corrupt existing vault
- temp dir `0700`, temp key file `0600`
- password must never hit command args or logs
- startup should clean stale temp artifacts
