# secssh Technical Design (Scaffold)

## Module layout

- `cli/`: command parsing and user interaction
- `vault/`: vault file format, load/store, migration
- `crypto/`: KDF + AEAD abstraction and implementations
- `workspace/`: unlock state, TTL, temp artifact lifecycle
- `runner/`: OpenSSH execution bridge
- `host/`: host auth policy model/validation
- `secret/`: secret naming and retrieval helpers

## Runtime boundaries

`secssh` does not implement SSH protocol. It shells out to OpenSSH:

`ssh -F <temp_config> <target> [passthrough args...]`

`secssh` is only responsible for:
1. decrypting vault content after unlock
2. materializing temporary key files from `secssh://keys/<name>`
3. generating temporary merged SSH config
4. selecting auth strategy per host and optional runtime override
5. invoking `ssh` and cleaning temporary artifacts

## Vault write protocol

All writes must use:
1. serialize new vault bytes
2. write to temp file in same directory
3. `fsync(temp-file)`
4. `rename(temp, vault)`
5. `fsync(parent-dir)` where supported

This guarantees crash-safe replacement.

## Re-encryption flows

Both flows are mandatory full re-encryption:
- `passwd`
- `crypto set`

Flow:
1. verify current vault password by decrypting current vault
2. generate fresh `salt`
3. generate fresh `nonce`
4. derive new key using target KDF params
5. encrypt full payload with target cipher
6. atomic write
7. refresh session cache in memory

## Session model

Unlock sets an in-memory session with expiration timestamp.
MVP scaffold currently persists TTL marker in temp storage as placeholder.
Production implementation should:
- hold decrypted data only in process memory
- support optional daemon/session process if cross-command unlock persistence is required
- clear sensitive bytes on `lock` and on TTL expiry

## Password auth for OpenSSH

Prefer key auth by default. Password auth is optional and host-scoped.
For password mode, use secure non-argv channel integration (e.g. askpass-compatible flow) so password never appears in command arguments or logs.
