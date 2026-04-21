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
- `crates/macolinux-ucd` has inspection subcommands plus an experimental
  CompanionLink mDNS advertiser and TCP Rapport frame logger.
- `nix/module.nix` exposes a NixOS service module, but the service is still a
  research probe until PairVerify, encrypted OPACK, and `uinput` are
  implemented.

## Development

```sh
cargo test
cargo run -p macolinux-ucd -- --version
cargo run -p macolinux-ucd -- tlv8 decode '0601010303616263'
cargo run -p macolinux-ucd -- rapport dump '08000003010203'
cargo run -p macolinux-ucd -- serve --help
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
services.macolinux-uc.instance = "linux-peer";
services.macolinux-uc.ipv4 = "192.0.2.11";
services.macolinux-uc.bleAddress = "02:00:00:00:00:31";
```

Do not deploy the service to a production host yet; `serve` is currently a
CompanionLink visibility probe, not a working Universal Control peer.

## Research

See `research/README.md` and `research/docs/protocol-notes.md` for sanitized
reverse-engineering notes and Python capture tools. Raw packet captures, live
logs, dyld extracts, and disassembler output are local-only and gitignored.
