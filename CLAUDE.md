# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rusticulum is a Rust implementation of the Reticulum encrypted mesh networking protocol (targeting interop with Python reference v1.1.3). The project is in early development — source is a library skeleton with a comprehensive implementation plan and 17 JSON test vector files ready for validation. The Python reference implementation is available at `.reference/reticulum/` for consulting when clarification on protocol behavior is needed.

## Build & Test Commands

```bash
cargo build              # Build the library
cargo test               # Run all tests
cargo test <test_name>   # Run a single test by name
cargo clippy             # Lint
cargo fmt --check        # Check formatting
```

Per-crate tests:
```bash
cargo test -p reticulum-crypto      # Test crypto primitives
cargo test -p reticulum-core        # Test types and wire formats
cargo test -p reticulum-protocol    # Test protocol state machines
cargo test -p reticulum-transport   # Test routing and path tables
```

Docker integration tests (requires Docker — always run after `cargo test`):
```bash
docker/scripts/test-announce.sh     # Announce exchange: Rust ↔ Python RNS
docker/scripts/test-link.sh         # Link establishment + encrypted data: Rust ↔ Python RNS
docker/scripts/test-resource.sh     # Resource transfer: Rust ↔ Python RNS
docker/scripts/test-channel.sh      # Channel messages + buffer streams: Rust ↔ Python RNS
```

These test real interop with the Python reference implementation over TCP. They build containers, run the test, and tear down automatically.

## Architecture

The implementation plan (`rusticulum-implementation-plan.md`) is the primary reference. It defines a workspace with six crates in a strict dependency hierarchy:

```
reticulum-crypto       Pure crypto (SHA, HMAC, HKDF, AES-CBC, Token, X25519, Ed25519)
       ↓
reticulum-core         Types, constants, wire formats, identity, addressing
       ↓
reticulum-protocol     State machines (link, resource, channel, buffer, request)
       ↓
reticulum-transport    Routing, announce propagation, path tables, dedup
       ↓
reticulum-interfaces   TCP/UDP/Serial/Local with HDLC/KISS framing, async I/O
       ↓
reticulum-node         Orchestration, config, storage
```

**Key design principle:** Protocol state machines produce `Vec<u8>` actions, never perform I/O directly. This keeps everything testable without networking.

## Test Vectors

`.test-vectors/` contains 17 JSON files extracted from the Python reference implementation. Tests should load them with `include_str!()` and `serde_json::from_str()`. Wire format tests must be bidirectional: parse raw bytes → verify fields, then serialize from fields → compare with original bytes.

## Protocol Subtleties

These gotchas are documented in the implementation plan (Part 8) and are critical to get right:

- **HKDF empty salt** = 32 zero bytes (explicit, not default)
- **Token key split** is `signing_key = key[0:32]`, `encryption_key = key[32:64]` (signing first)
- **Packet hashable part**: flags masked to lower 4 bits, hops stripped, transport_id stripped for HEADER_2
- **HDLC escape order**: escape ESC (0x7D) before FLAG (0x7E), not the reverse
- **Announce signed_data** includes destination_hash as the first field (not part of wire payload)
- **Link ID**: MTU signalling bytes must be stripped from hashable part before hashing

## Coding Conventions

- Rust edition 2024
- Strong newtypes for all byte-array protocol fields (no raw `[u8; N]` in APIs)
- Type-state pattern for link state machine (LinkPending → LinkHandshake → LinkActive → LinkClosed)
- `reticulum-crypto` and `reticulum-core` should support optional `no_std` (with `alloc`)
- RustCrypto family for crypto primitives (`sha2`, `hmac`, `aes`, `cbc`, `x25519-dalek`, `ed25519-dalek`)
- `rmpv` for msgpack, `thiserror` for errors, `tokio` for async

## Issue Tracking

This project uses **bd** (beads) for issue tracking. Run `bd onboard` to get started.

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status in_progress  # Claim work
bd close <id>         # Complete work
bd sync               # Sync with git
```

## Session Completion

When ending a work session, ALL steps below must be completed. Work is NOT complete until `git push` succeeds.

1. **File issues for remaining work** — Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) — `cargo test`, `cargo clippy`, then Docker integration tests (`docker/scripts/test-announce.sh`, `docker/scripts/test-link.sh`, `docker/scripts/test-resource.sh`, `docker/scripts/test-channel.sh`)
3. **Update issue status** — Close finished work, update in-progress items
4. **Push to remote** (MANDATORY):
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** — Clear stashes, prune remote branches
6. **Verify** — All changes committed AND pushed
7. **Hand off** — Provide context for next session

**Critical:** Never stop before pushing — that leaves work stranded locally. If push fails, resolve and retry until it succeeds.

## License

Reticulum License (MIT-derived with restrictions on use in harmful systems and AI training datasets).
