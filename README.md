# Pass Manager

`pass-manager` is a security-focused Rust CLI vault with a terminal UI, authenticated encryption, memory hygiene for secrets, and a testable modular architecture.

## Highlights

- Argon2id key derivation with persisted parameters and per-vault salt
- ChaCha20Poly1305 authenticated encryption for the entire vault payload
- `secrecy::SecretString` for master passwords and stored passwords
- Best-effort secret wiping for decrypted buffers via `zeroize`
- Owner-only vault permissions (`0o600`) on Unix
- `clap`-based CLI plus a `ratatui` + `crossterm` terminal UI
- Auto-hide password reveal, clipboard clearing, and TUI auto-lock
- Password generation, fuzzy search, sorting, and last-accessed tracking

## Commands

```bash
cargo run -- add example.com
cargo run -- get example.com
cargo run -- list
cargo run -- delete example.com
cargo run -- generate --length 24
cargo run -- tui
```

If you run the binary without a subcommand, it opens the TUI by default.

## TUI

Layout:

- Left pane: entry list
- Right pane: entry details
- Bottom bar: status/help text

Keybindings:

- `j` / `k`: move through entries
- `/`: enter fuzzy search mode
- `Enter`: reveal the selected password temporarily
- `y`: copy the selected password to the clipboard
- `a`: add a new entry
- `d`: delete the selected entry with confirmation
- `s`: toggle sort mode
- `q`: quit immediately
- `Ctrl+C`: press twice within 2 seconds to quit

Security UX:

- password reveal auto-hides after 8 seconds
- clipboard is cleared after 15 seconds
- the TUI auto-locks after inactivity and requires the master password again
- `Ctrl+G` in the add-entry dialog generates a new 24-character password

## Vault Format

The on-disk vault is a single encrypted JSON document with a flat, explicit schema:

```json
{
  "version": 1,
  "kdf": { "m": 65536, "t": 3, "p": 1 },
  "salt": "hex-encoded-salt",
  "nonce": "hex-encoded-nonce",
  "ciphertext": "hex-encoded-ciphertext"
}
```

The plaintext vault itself is serialized JSON and encrypted as one AEAD payload.

## Project Layout

```text
src/
  cli/
    mod.rs
    commands.rs
  crypto/
    mod.rs
    kdf.rs
    cipher.rs
  security/
    mod.rs
    memory.rs
  ui/
    mod.rs
    tui.rs
  vault/
    mod.rs
    entry.rs
    store.rs
  error.rs
  lib.rs
  main.rs
tests/
  vault_roundtrip.rs
```

## Security Notes

- All new encryption uses audited crates instead of custom crypto.
- Legacy plaintext JSON vaults are detected and upgraded on next save.
- Legacy custom-crypto vault files are deliberately rejected by this build.
- Secrets are never logged and decrypted buffers are wiped after parsing.

## Testing

The test suite currently covers:

- Argon2 key derivation stability and salt sensitivity
- ChaCha20Poly1305 round-trip encryption
- vault add/delete/touch behavior
- wrong-master rejection
- JSON storage shape regression checks
- Unix file permission enforcement
- integration round-trip add -> save -> load -> verify

Run everything with:

```bash
cargo test
```
