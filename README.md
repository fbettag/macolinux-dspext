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
  - OPACK encode/decode for Rapport pre-auth and pairing probes
  - Bonjour `rpFl` to Rapport status flag mapping
  - PairVerify constants and client-side X25519/HKDF/ChaCha20-Poly1305/Ed25519 helpers
- `crates/macolinux-ucd` has inspection subcommands plus experimental
  CompanionLink mDNS, Continuity BLE, PairSetup/PairVerify client probes, and
  an experimental Rapport server that handles `PA_Req`/`PA_Rsp`, PairVerify
  M1-M4, encrypted `E_OPACK`, and `_streamStart` replies backed by local TCP
  listeners. It can also generate and persist a Linux Ed25519 peer identity for
  the future macOS trust-bootstrap flow.
- `nix/module.nix` exposes a NixOS service module, but the service is still a
  research probe until macOS-side trust bootstrap, real peer admission, and
  decoded live-session events are implemented.

## Development

```sh
cargo test
cargo run -p macolinux-ucd -- --version
cargo run -p macolinux-ucd -- tlv8 decode '0601010303616263'
cargo run -p macolinux-ucd -- rapport dump '08000003010203'
cargo run -p macolinux-ucd -- identity create --path ./fistel.identity.json --identifier fistel
cargo run -p macolinux-ucd -- identity export-peer --path ./fistel.identity.json
cargo run -p macolinux-ucd -- input listen --dry-run
cargo run -p macolinux-ucd -- pairing resolve --addr endor.local:49427 --pairverify-client --identity ./fistel.identity.json
cargo run -p macolinux-ucd -- serve --identity ./fistel.identity.json --allow-unknown-peer --stream-advertise-addr 192.0.2.11
```

Build through Nix:

```sh
nix build
nix run . -- --version
nix run .#macolinux-uc-bootstrap -- --help
```

## macOS Bootstrap

If you are willing to run a helper on macOS, the flake now ships an
experimental `macolinux-uc-bootstrap` wrapper around the private
`RPPairingDistributedActor` PairVerify path already described in the research
notes. This is the shortest current path toward a trust bootstrap for a Linux
peer identity.

On Darwin, `nix build .#macolinux-ucd` installs:

- `macolinux-uc-bootstrap`
- `pairverify_actor_helper`
- `macolinux-network-actor-framer-probe`
- `macolinux-network-endpoint-c-probe`
- `macolinux-continuity-inspect`
- `macolinux-macos-input-forwarder`
- `Applications/MacolinuxBootstrap.app`

Example dry run:

```sh
cargo run -p macolinux-ucd -- identity create \
  --path ./fistel.identity.json \
  --identifier fistel

nix run .#macolinux-uc-bootstrap -- \
  pairverify-m3 \
  --peer-name endor \
  --identity ./fistel.identity.json \
  --dry-run
```

The wrapper generates the actor call UUIDs, resolves the installed helper
paths, resolves the pairing actor ID from the `_appSvcPrePair._tcp` TXT `sid`
when `--actor-id` is omitted, then falls back to the packaged
`macolinux-network-endpoint-c-probe` explicit-bundle application-service browse
path if normal Bonjour resolution does not surface the temporary pairing
service. On Darwin, `nix run .#macolinux-uc-bootstrap` now executes the copy
inside `MacolinuxBootstrap.app/Contents/MacOS/`, so the helper and its sibling
probes run with a real app-bundle main bundle instead of a bare CLI path. It
prints the exact payload and final probe command, and can execute the full
`pairverify-m3-sequence` against `_appSvcPrePair._tcp` when `--dry-run` is
omitted. It is still an experimental bootstrap tool, not a finished user
workflow. The remaining hard blockers are macOS trust persistence,
`DeviceAuthTag` visibility, and the later AWDL/live-session transport.

The same packaged helper also exposes the working Companion stream broker path:

```sh
nix run .#macolinux-uc-bootstrap -- \
  companion-stream publish \
  --bonjour-name e3a0d17e48fc \
  --relay 127.0.0.1:4711 \
  --reply endor-reply \
  --seconds 60
```

This temporarily enables `com.apple.Sharing` `AlwaysSendPayload`, restarts
`sharingd`, runs the packaged `macolinux-companion-service-probe`, prints the
binary-plist base64 message, and removes the temporary preference when the
publisher exits. The `--bonjour-name` value must be the active
`_continuity._tcp` instance name; on `endor` that was `e3a0d17e48fc`, visible
with `dns-sd -B _continuity._tcp local.` while the stream publisher is active.
A second Mac can open the stream with:

```sh
nix run .#macolinux-uc-bootstrap -- \
  companion-stream connect-b64 \
  --message-b64 '<publish-output-plist-b64>' \
  --relay 127.0.0.1:4712 \
  --write bespin-ping \
  --seconds 30
```

This is not yet a Universal Control UI session. It is a repeatable
Apple-accepted byte stream through `sharingd`, which is the bridge point for the
next Linux daemon integration. The `--reply` and `--write` options are only
smoke-test helpers; `--relay HOST:PORT` is the path intended for bridging this
Apple-owned stream into a local daemon.

The daemon side now has a matching TCP relay/debug endpoint:

```sh
nix run .#macolinux-ucd -- \
  relay listen \
  --bind 127.0.0.1:4711 \
  --send-text endor-relay-ready \
  --echo
```

Use this as the local target for `companion-stream ... --relay 127.0.0.1:4711`.
It prints raw byte chunks and opportunistically decodes Rapport/OPACK frames, so
the next live test can show whether the Companion stream is carrying normal
Rapport traffic, Universal Control stream setup traffic, or a different payload.

## Linux Input Receiver

The Linux side now has an experimental `/dev/uinput` receiver for decoded
keyboard and pointer events. It is intentionally a plain TCP line protocol so
the transport reverse-engineering can feed it without coupling event injection
to the Apple stream code:

```sh
nix run .#macolinux-ucd -- \
  input listen \
  --bind 127.0.0.1:4720 \
  --device /dev/uinput
```

The accepted commands are:

```text
MOVE dx dy
SCROLL vertical [horizontal]
BTN left|right|middle down|up|click
KEY CODE_OR_NAME down|up|tap
```

For local testing on macOS or on Linux without touching input devices, use
`--dry-run`:

```sh
nix run .#macolinux-ucd -- \
  input listen \
  --bind 127.0.0.1:4720 \
  --dry-run
```

On NixOS this can run as a separate root service because `/dev/uinput` needs
kernel and device access:

```nix
services.macolinux-uc.input.enable = true;
services.macolinux-uc.input.bind = "127.0.0.1:4720";
```

For a practical working session before the private Universal Control event
stream is fully decoded, macOS can run a non-Python event forwarder that captures
local keyboard/pointer events and sends the same line protocol to Linux:

```sh
nix run .#macolinux-macos-input-forwarder -- \
  --host 192.0.2.11 \
  --port 4720 \
  --edge right \
  --remote-width 1920 \
  --remote-height 1080
```

The forwarder uses a CoreGraphics HID event tap and requires macOS
Accessibility/Input Monitoring approval for the binary or the parent terminal.
Move the pointer into the configured edge to enter the Linux input region; move
back past the remote edge to release control to macOS. For validation without
sending events to Linux, add `--dry-run --always-grab`.

## NixOS Module

The flake exposes `nixosModules.default`. A later `/etc/nixos` integration for
a NixOS host should import this module and enable:

```nix
services.macolinux-uc.enable = true;
services.macolinux-uc.instance = "linux-peer";
services.macolinux-uc.ipv4 = "192.0.2.11";
services.macolinux-uc.identityPath = "/var/lib/macolinux-uc/identity.json";
services.macolinux-uc.allowUnknownPeer = true;
services.macolinux-uc.bleAddress = "02:00:00:00:00:31";
services.macolinux-uc.ble.enable = true;
services.macolinux-uc.input.enable = true;
```

Do not deploy the CompanionLink service to a production host yet; `serve` can
now complete PairVerify and reply to `_streamStart`, but it is still missing the
macOS trust bootstrap, AWDL admission, and decoded Universal Control session
events needed for a true native peer. The macOS input forwarder is a practical
bridge for keyboard/mouse sharing while that protocol work continues.

## Research

See `research/README.md` and `research/docs/protocol-notes.md` for sanitized
reverse-engineering notes and Python capture tools. Raw packet captures, live
logs, dyld extracts, and disassembler output are local-only and gitignored.
