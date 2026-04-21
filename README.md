# macolinux-dspext

Rust/NixOS implementation work for a Linux peer that can eventually participate
in Apple's Universal Control protocol.

This is not an AirPlay, Sidecar, VNC, or screen-mirroring project. The target is
the Continuity/Rapport path that lets macOS move keyboard and pointer focus to a
trusted peer. Runtime code is being built in Rust; Python and disassembly output
live under `research/` as reverse-engineering scaffolding.

## Current Status

- `crates/macolinux-uc-core` contains stable protocol primitives:
  - TLV8 encode/decode
  - Rapport frame encode/decode
  - Bonjour `rpFl` to Rapport status flag mapping
  - PairVerify constants recovered from CoreUtils
- `crates/macolinux-ucd` is a daemon skeleton with inspection subcommands.
- `nix/module.nix` exposes a NixOS service module, but the service is still a
  placeholder until discovery, PairVerify, and `uinput` are implemented.

## Development

```sh
cargo test
cargo run -p macolinux-ucd -- --version
cargo run -p macolinux-ucd -- tlv8 decode '0601010303616263'
cargo run -p macolinux-ucd -- rapport dump '08000003010203'
```

Build through Nix:

```sh
nix build
nix run . -- --version
```

## NixOS Module

The flake exposes `nixosModules.default`. A later `/etc/nixos` integration for
a NixOS host should import this module and enable:

```nix
services.macolinux-uc.enable = true;
```

Do not deploy the service to a production host yet; the daemon currently only starts a
skeleton `serve` command.

## Research

See `research/README.md` and `research/docs/protocol-notes.md` for sanitized
reverse-engineering notes and Python capture tools. Raw packet captures, live
logs, dyld extracts, and disassembler output are local-only and gitignored.
