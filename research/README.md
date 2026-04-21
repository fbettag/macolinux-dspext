# macolinux-dspext research

This directory contains reverse-engineering notes and Python capture tools. Raw
packet captures, live logs, dyld extracts, and disassembler output are kept
local-only under `research/analysis/`, which is gitignored. Commands below
assume the current working directory is `research/`.

Research tooling for building a Linux client that can participate in Apple's
Universal Control protocol as a native peer.

The target is not AirPlay, Sidecar, screen sharing, or video mirroring. Universal
Control is a Rapport/CompanionLink-based peer-to-peer control path where macOS
extends its keyboard and pointer focus to another trusted device. The visible
transport uses AWDL, Bonjour, encrypted Rapport streams, and HID/event reports.

## What We Know So Far

- Universal Control is launched as `com.apple.ensemble` from
  `/System/Library/CoreServices/UniversalControl.app`.
- Discovery is driven by Rapport matching for `_companion-link._tcp` and
  `com.apple.universalcontrol`.
- Normal LAN CompanionLink Bonjour records use TXT keys like `rpFl=0x20000` and
  `rpVr=715.2`.
- AWDL traffic includes separate ephemeral `CLink-...` `_companion-link._tcp`
  advertisements with `rpFl=0x800`.
- Active control traffic is TCP over AWDL IPv6 link-local addresses.
- Apple Continuity BLE manufacturer data is part of the visibility gate:
  macOS parses Apple company ID `4c00` followed by TLVs such as NearbyInfo
  (`0x10`) and NearbyAction (`0x0f`).
- The TCP payload has the Rapport `RPConnection` 4-byte record header:

```text
TT LL LL LL BODY...
```

`TT` is a one-byte frame type and `LL LL LL` is a 24-bit big-endian body
length. Live Universal Control event traffic observed so far uses `TT=0x08`,
which `Rapport.framework` labels `E_OPACK` (encrypted OPACK). Rizin analysis
also shows `TT=0x0a` as `PA_Req`, the unencrypted pre-auth request frame.

See [docs/protocol-notes.md](docs/protocol-notes.md) for the current notes.

## Tools

Advertise a synthetic CompanionLink peer and log inbound TCP connections:

```sh
./tools/companionlink-mdns-peer.py \
  --instance linux-peer \
  --hostname linux-peer.local \
  --ipv4 192.0.2.11 \
  --multicast-ipv4 192.0.2.11 \
  --port 49152
```

Capture AWDL traffic through root SSH:

```sh
./tools/capture-universal-control.sh 60 /tmp/universal-control-awdl.pcap
```

Summarize visible Universal Control stream framing:

```sh
./tools/uc-pcap-summary.py /tmp/universal-control-awdl.pcap
```

The parser is dependency-free and only understands enough classic pcap,
Ethernet, IPv6, and TCP to summarize Universal Control captures. It does not
decrypt Rapport payloads.

Dump raw Rapport frames from a TCP payload or hex string:

```sh
./tools/rapport-frame-dump.py --hex '08000003010203'
```

Decode or encode HomeKit/Continuity TLV8 blobs from PairVerify captures:

```sh
./tools/tlv8-tool.py decode '0601010303616263'
./tools/tlv8-tool.py encode 0x06=01 0x03=616263
```

Round-trip OPACK through the private macOS codec:

```sh
clang -fobjc-arc -framework Foundation tools/opack-tool.m -o /tmp/opack-tool
/tmp/opack-tool encode-json '{"_i":"probe","value":1}'
/tmp/opack-tool decode e2425f694570726f62654576616c756509
```

Advertise a synthetic Apple Continuity BLE NearbyAction/NearbyInfo payload from
a Linux BlueZ host:

```sh
./tools/ble-continuity-advertise.py \
  --host root@linux-peer \
  --run \
  --duration 20 \
  --nearby-action 0102030405 \
  --nearby-info 0000
```

That command currently reaches macOS `sharingd`/`rapportd` as a BLE
NearbyAction device. It does not yet satisfy pairing, IDS/iCloud identity, or
Universal Control peer admission.

## Current Blocker

The critical reverse-engineering task is the Continuity/Rapport trust and stream
crypto layer. HID report names and event report names are visible in the
Universal Control binary, but macOS will not accept a Linux peer until BLE or
Nearby discovery, known-peer visibility, pre-auth, PairVerify, and encrypted
OPACK stream setup are compatible.
