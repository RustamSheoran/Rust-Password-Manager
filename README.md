# Pass Manager

`pass-manager` is a security-focused Rust password vault with a CLI and a terminal UI. It is designed to feel like a serious systems project rather than a toy demo: audited crypto primitives, secret-aware memory handling, auto-locking UX, portable storage, and a modular codebase backed by tests.

## Demo

Demo recording:
[demo.webm](assets/readme/demo.webm)

### Screenshots

#### Master password prompt

![Master password prompt](https://raw.githubusercontent.com/RustamSheoran/Rust-Password-Manager/main/assets/readme/master-password-prompt.png)

#### TUI with hidden password

![TUI with hidden password](https://raw.githubusercontent.com/RustamSheoran/Rust-Password-Manager/main/assets/readme/tui-hidden-password.png)

#### TUI with revealed password

![TUI with revealed password](https://raw.githubusercontent.com/RustamSheoran/Rust-Password-Manager/main/assets/readme/tui-revealed-password.png)

#### Test suite passing

![Cargo test suite passing](https://raw.githubusercontent.com/RustamSheoran/Rust-Password-Manager/main/assets/readme/cargo-test-passing.png)

## Why This Project Stands Out

- Replaces all custom crypto with `Argon2id` for key derivation and `ChaCha20Poly1305` for authenticated encryption.
- Uses `secrecy::SecretString` and `zeroize`-based cleanup for sensitive in-memory data.
- Ships both a scriptable CLI and a `ratatui` + `crossterm` TUI with security-focused behavior.
- Enforces owner-only vault file permissions on Unix.
- Includes unit and integration tests around crypto, storage, security regressions, and vault workflows.

## Security Design

- Master password -> Argon2id -> 32-byte key -> ChaCha20Poly1305 vault encryption.
- The on-disk file stores only `version`, `kdf` params, `salt`, `nonce`, and `ciphertext`.
- The stored vault file does not contain plaintext site names, usernames, or passwords.
- Wrong-password unlock attempts fail AEAD verification and do not produce partial plaintext.
- Legacy custom-crypto vaults are intentionally rejected by this build.

## Quick Start

### Build and run

```bash
cargo run -- --help
```

For the optimized binary:

```bash
cargo run --release
```

### Create your vault

On the first `add` or `tui` run, the app asks you to create a master password.

```bash
cargo run -- add github.com
```

You will be prompted for:

- a new master password
- the username for the site
- the password for the site

### Common commands

Create or update an entry:

```bash
cargo run -- add example.com
```

Read a stored credential:

```bash
cargo run -- get example.com
```

List all stored sites:

```bash
cargo run -- list
```

Delete an entry:

```bash
cargo run -- delete example.com
```

Generate a strong password:

```bash
cargo run -- generate --length 24
cargo run -- generate --length 24 --no-symbols
```

Launch the terminal UI:

```bash
cargo run -- tui
```

Use a custom vault path:

```bash
cargo run -- --vault ./my-vault.json tui
```

If you run the binary without a subcommand, it opens the TUI by default.

## TUI Experience

Layout:

- Left pane: entry list
- Right pane: selected entry details
- Bottom bar: live status and shortcut hints

Keybindings:

- `j` / `k`: move through entries
- `/`: enter fuzzy search mode, with site-name matches ranked ahead of username matches
- `Enter`: reveal or hide the selected password
- `y`: copy the selected password to the clipboard
- `a`: add a new entry
- `d`: open a full-screen delete confirmation for the selected entry, then press `d` or `Enter` to confirm
- `s`: toggle sort mode
- `?` or `F1`: open the full keybinding help overlay
- `Ctrl+C`: open a 3-second full-screen exit confirmation
- `Esc`: leave fuzzy search or close/cancel the active overlay
- `c`: cancel the delete or exit confirmation overlay

Security UX:

- password reveal shows a live countdown and auto-hides after 8 seconds
- switching focus to another entry hides the previously revealed password immediately
- deletion uses a dedicated full-screen confirmation before anything is removed
- clipboard contents auto-clear after 15 seconds
- the vault auto-locks after inactivity
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
assets/
  readme/
    cargo-test-passing.png
    demo.webm
    master-password-prompt.png
    tui-hidden-password.png
    tui-revealed-password.png
src/
  cli.rs
  cli/
    commands.rs
  crypto.rs
  crypto/
    cipher.rs
    kdf.rs
  security.rs
  security/
    memory.rs
  ui.rs
  ui/
    tui.rs
  vault.rs
  vault/
    entry.rs
    store.rs
  error.rs
  lib.rs
  main.rs
tests/
  vault_roundtrip.rs
```

## Verification

The current test suite covers:

- Argon2 key derivation stability and salt sensitivity
- ChaCha20Poly1305 round-trip encryption
- vault add/delete/touch behavior
- wrong-master rejection
- plaintext-secret regression checks on saved vaults
- JSON storage shape regression checks
- Unix file permission enforcement
- TUI reveal/hide and exit-confirmation behavior
- delete-confirmation and fuzzy-search ranking behavior
- integration round-trip add -> save -> load -> verify

Run the checks with:

```bash
cargo fmt
cargo test
cargo build --release
```
