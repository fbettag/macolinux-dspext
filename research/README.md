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
- A forced live transition shows Universal Control first using an existing
  trusted CompanionLink connection to request AWDL, then opening an AWDL
  CompanionLink control connection, completing PairVerify, sending
  `com.apple.universalcontrol`, and accepting four P2P streams:
  `SYNC`, `EVNT`, `CLIP`, and `DRAG`.
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
Live probes against the local CompanionLink listener also confirmed
`0x03/0x04` as PairSetup frames and `0x05/0x06` as PairVerify frames.

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

Drive the current Rust PairVerify bootstrap probe:

```sh
cargo run -p macolinux-ucd -- identity create \
  --path ./fistel.identity.json \
  --identifier fistel

cargo run -p macolinux-ucd -- pairing resolve \
  --addr endor.local:49427 \
  --pairverify-client \
  --identity ./fistel.identity.json

cargo run -p macolinux-ucd -- serve \
  --identity ./fistel.identity.json \
  --allow-unknown-peer \
  --stream-advertise-addr 192.0.2.11
```

For PairSetup/PairVerify frames, Rapport expects an OPACK dictionary with the
short key `_pd`; the value is TLV8 bytes. Long keys such as `pairingInfo` are
not accepted on the wire.

When the peer is already trusted, the same probe can decrypt PairVerify M2,
verify the peer's Ed25519 signature if `--peer-ed25519-public-key-hex` is
provided, and send M3 when supplied with a Linux identity via `--identity`.
The older `--identity-id` and `--identity-ed25519-seed-hex` flags remain useful
for one-off experiments, but the product path should use the persisted identity
file. The current clean bootstrap blocker is still creating a macOS-side trust
record for that Linux identity.

The experimental Rust server can now answer `PA_Req`, complete PairVerify as
the server, derive the protected `main` stream keys from the raw X25519 shared
secret, decrypt encrypted `E_OPACK`, and reply to `_streamStart` with local TCP
listeners. That is enough to validate the server-side wire path locally, but it
does not bypass the macOS trust/bootstrap gates described in the notes.

Decrypt a captured post-PairVerify encrypted OPACK frame offline:

```sh
cargo run -p macolinux-ucd --bin macolinux-ucd -- \
  eopack decrypt \
  --psk-hex "$EOPACK_DECRYPT_PSK_HEX" \
  --frame-hex "$RAPPORT_FRAME_HEX"
```

Use `--body-hex` instead when the Rapport frame header has already been
removed. The actor helper now prints `shared_secret_hex`, and the
`pairverify-m3-sequence` actor probe echoes that value as
`eopack_decrypt_psk_hex`; that raw shared secret is the PSK for the normal
post-PairVerify `main` stream.

Round-trip OPACK through the private macOS codec:

```sh
clang -fobjc-arc -framework Foundation tools/opack-tool.m -o /tmp/opack-tool
/tmp/opack-tool encode-json '{"_i":"probe","value":1}'
/tmp/opack-tool decode e2425f694570726f62654576616c756509
```

Inspect Continuity/Rapport classes and pairing metadata without dumping private
key material:

```sh
clang -fobjc-arc -fblocks \
  -framework Foundation -framework Network -framework Security \
  tools/continuity-inspect.m \
  -o /tmp/continuity-inspect
/tmp/continuity-inspect classes Pairing
/tmp/continuity-inspect class CUPairingManager
/tmp/continuity-inspect protocol Rapport.RPPairingDaemonXPCInterface
/tmp/continuity-inspect pairing-summary
/tmp/continuity-inspect auth-types 16
/tmp/continuity-inspect coreutils-symbols
/tmp/continuity-inspect methods SessionPaired
/tmp/continuity-inspect class-imps RPIdentity AuthTag
/tmp/continuity-inspect rpidentity-peer /tmp/fistel-peer.json 24
/tmp/continuity-inspect rpclient-add-identity /tmp/fistel-peer.json 13 0
/tmp/continuity-inspect rpcl-browse com.apple.universalcontrol 8
/tmp/continuity-inspect rp-pairing-listen 10 visible
/tmp/continuity-inspect rd-pairing-server 10
```

Headless string xrefs against `rapportd` without relying on PyGhidra or Jython:

```sh
mkdir -p /tmp/ghidra-rapport-xrefs
'/nix/store/n4hv07zihdwil7mxh0g47mpz52vb4dik-ghidra-with-extensions-12.0/lib/ghidra/support/analyzeHeadless' \
  /tmp/ghidra-rapport-xrefs rapportd-xrefs \
  -import /usr/libexec/rapportd \
  -scriptPath ./tools \
  -postScript string_xrefs_ghidra.java \
  "Saving remote identity: %s" \
  "AuthTag matches existing identity %@" \
  "AuthTag doesn't match identity %@ - %s needs identity share" \
  -deleteProject
```

The current Ghidra build here can still complain about the bundled native
decompiler and GNU demangler binaries, but the Java post-script remains useful
for string/xref and per-function call-list extraction.

Headless caller xrefs for specific functions:

```sh
mkdir -p /tmp/ghidra-rapport-funcx
'/nix/store/n4hv07zihdwil7mxh0g47mpz52vb4dik-ghidra-with-extensions-12.0/lib/ghidra/support/analyzeHeadless' \
  /tmp/ghidra-rapport-funcx rapportd-funcx \
  -import /usr/libexec/rapportd \
  -scriptPath ./tools \
  -postScript function_xrefs_ghidra.java \
  100124280 \
  10013b7b0 \
  -deleteProject
```

Offline Swift field metadata dump from the x86_64 slice of `rapportd`:

```sh
python3 tools/swift_fieldmd_dump.py /usr/libexec/rapportd \
  --match selfPairingIdentity \
  --match deviceIRKData \
  --match pake \
  --match clientIdentityData \
  --match serverIdentityData
```

The script thins the binary with `lipo`, parses `__swift5_fieldmd` and
`__swift5_reflstr`, and prints stored-property layouts for Swift types even when
the headless Ghidra decompiler is unavailable.

Probe the hidden Network.framework application-service pairing listeners and
actor-message framer:

```sh
clang -fobjc-arc -fblocks \
  -framework Foundation -framework Network -framework Security \
  tools/network-actor-framer-probe.m \
  -o /tmp/network-actor-framer-probe

/tmp/network-actor-framer-probe \
  connect-service endor _appSvcPrePair._tcp local 12 \
  1 0 hex:0a096d61636f6c696e7578 tls stack actor
```

The `actor` framer mode emits the private
`com.apple.network.MessageActorSystem` 12-byte header before the payload.
`passthrough` is kept only as a negative-control mode, and `apple` attempts to
reuse a process-registered Apple framer definition when one is available.
Payloads can be supplied as `hex:<bytes>`, `b64:<base64>`, `file:<path>`,
`text:<utf8>`,
`remote-call:CALL_ID|ACTOR_NAME|ACTOR_IDENTIFIER|TARGET[|OPTIONS[|arg-hex:<bytes>|arg-b64:<base64>|arg-text:<utf8>|arg-json-string:<utf8>|arg-json-data-b64:<base64>|arg-json-data-hex:<bytes>|arg-json-bool:true|arg-json-bool:false|arg-empty...]]`,
`empty`, `zero`, or `rpnw-control`.
For the current PairVerify actor path there is also
`remote-call-sequence:CALL1;;;CALL2`, which sends two normal remote calls over
one actor connection,
`pairverify-sequence:CALL_ID_START|CALL_ID_PROCESS|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|M1_HEX`,
which sends the start and M1 processing calls over one actor connection, and
`pairverify-m3-sequence:CALL_ID_START|CALL_ID_M1|CALL_ID_M3|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|HELPER_PATH|IDENTITY_PATH`,
which asks the Rust `pairverify_actor_helper` to generate M1, decrypt M2, build
M3, and send all three actor calls on that same connection.
Use UUID-shaped `CALL_ID` values. Short IDs can reach the actor wire layer but
fail the Swift distributed actor envelope decoder.

Transport modes currently include `appsvc`, `tcp`, `tls`, `quic[:ALPN,...]`,
and research-only `appsvc-quic`. The probe also has:

```sh
/tmp/network-actor-framer-probe \
  connect-appsvc NAME [SECONDS] [TYPE] [OPTIONS] [PAYLOAD] [TRANSPORT]
```

for testing private application-service endpoints through
`nw_endpoint_create_application_service`.

The custom actor framer has confirmed the Network distributed actor wire header
and logical message type map used by the temporary pairing listeners:

```text
logical 1 -> cancelRemoteCall
logical 2 -> terminateProcess
logical 3 -> remoteCallProtobuf
logical 4 -> ReplyEnvelope
```

The type-3 `remoteCallProtobuf` body is a raw
`NWActorSystemProtobuf.RemoteCall`, not JSON or binary plist. The working field
layout is `1=callID`, `2=recipient ActorID`, `3=invocationTarget`,
`4=genericSubs`, `5=arguments`, and `6=options`; `ActorID` is
`1=actorName`, `2=identifier`. The temporary pairing actor resolves when
`actorName` is `RPPairingDistributedActor` and `identifier` is the listener's
advertised `service_id` UUID. Swift uses mangled distributed thunk symbols as
`invocationTarget` values, for example
`$s8rapportd25RPPairingDistributedActorC14resolveBonjour15clientPublicKeyAA0bF15ResolveResponseC10Foundation4DataV_tYaKFTE`
for `resolveBonjour(clientPublicKey:)`. The current Network.framework pairing
argument encoding is the target type's `JSONEncoder` representation inside
protobuf field 5, e.g. `Foundation.Data` as a quoted base64 JSON string and
`Bool` as `true`/`false`. The current actor path now reaches M3: the research
framer keeps one actor connection open, calls `startPairVerifyWithSessionID`,
extracts the returned UUID, sends PairVerify M1, receives/decrypts M2, builds
encrypted M3 with the Linux Ed25519 identity, and sends M3 back through
`processPairVerifyDataWithSessionID`. The server decrypts M3 and fails at the
expected trust boundary: `Resolve identity for signature failed` /
`PairVerify server M3 verify signature failed: kNotFoundErr`, because the Linux
identifier is not yet resolvable as an allowed `RPIdentity`.

The temporary pairing listener's `_appSvcPrePair._tcp` leg accepts
`RPPairingDistributedActor` over TLS with actor type `3`. A same-connection
`resolveBonjour(clientPublicKey:)` plus `resolveBonjourCompleted()` sequence
returns a follow-up `_asquic._udp` service ID and logs
`resolveBonjourCompleted` in `rapportd`. The current probe still gets an empty
`serverPublicKey` because `rapportd` cannot find QUIC protocol options on our
TCP/TLS actor connection; reproducing the real QUIC/asquic pairing connection is
the next pairing bootstrap target. Generic QUIC and application-service QUIC
parameter probes now build and run, but the returned `_asquic._udp` name is not
answering SRV/TXT as normal mDNS from `bespin` even though `_asquic._udp`
browse sees the instance add/remove; direct Bonjour and direct
application-service endpoint probes remain in `preparing`. Treat the returned
name as a Network/Rapport browse-response endpoint object until proven
otherwise.

The actor probe can now browse `_asquic._udp` with optional interface pinning
through `nw_interface_create_with_name` and `nw_parameters_require_interface`.
That ruled out a simple interface-selection bug: the temporary endpoint returned
by our TCP/TLS `resolveBonjour` path appears when pinned to `en0`, does not
appear when pinned to `awdl0`, and still stays in `preparing` when connected
from the exact browse-result endpoint. Existing Apple Universal Control
instances are visible on `awdl0`, so the next target remains the hidden
application-service QUIC/asquic browser/parameter shape.

The probe also exposes the hidden browse descriptor fields exported by
Network.framework: browse scope, device types, endpoints-only, and custom
service bytes. Live sweeps with default/all scope, several single-bit scope
masks, all device types, and custom-service variants (`pairing-only`,
`preferred-only`, `both`, `empty`, `none`) all reached a ready browser but
returned no app-service results. That makes the next useful target a real
caller trace of Apple's application-service pairing client or the hidden
Network actor/browser association, rather than more blind descriptor-mask
guessing.

Normal unsigned processes currently receive `kMissingEntitlementErr` from both
the PairingManager APIs and the `RPClient` identity APIs. Ad-hoc signing with
restricted Apple entitlements such as `com.apple.rapport.Client` or
`com.apple.PairingManager.Write` makes the helper die at launch under AMFI, so
this is not bypassed by root or local codesigning. That is expected and is
useful: a clean Linux peer bootstrap cannot rely on cloning an existing Mac's
Universal Control identity. It needs a separate pairing path for a new
`CUPairedPeer`/`RPIdentity` or a genuinely entitled macOS helper.

The `auth-types` and `rp-pairing-listen` probes are also read-only. On the
current test host, Sharing authentication type enumeration works, but actual
candidate/eligible device listing is rejected by `sharingd` without the private
authentication/unlock entitlement. Rapport's pairing receiver controller can be
started by an ordinary process, but it does not emit a PIN by itself; it appears
to wait for an incoming pairing initiator. Remote Display pairing server
activation is blocked without the private `com.apple.RemoteDisplay`
entitlement, so that path cannot be used directly from a normal helper.

An unsigned helper can also talk to the pairing mach service directly, but the
shape matters. The new broker-side probe:

```sh
clang -fobjc-arc -fblocks -framework Foundation \
  tools/rppairing-xpc-probe.m \
  -o /tmp/rppairing-xpc-probe

/tmp/rppairing-xpc-probe 4 controller skip
```

uses `NSXPCConnection` to `com.apple.rapport.RPPairing` and survives the
`startPairingReceiverController:` call only when it mirrors Apple's own
`RPPairingReceiverController` setup:

- exported interface: `Rapport.RPPairingReceiverControllerXPCClientInterface`
- exported object: real `Rapport.RPPairingReceiverController`
- remote interface: `Rapport.RPPairingDaemonXPCInterface`
- start argument: that same `Rapport.RPPairingReceiverController` instance
- no extra `NSXPCInterface setInterface:` / `setClasses:` hints

Custom callback objects or extra interface/class hints caused the broker
connection to interrupt. Matching Apple's exact controller shape kept the
connection alive until the probe invalidated it locally.

To recover the exact Apple-side NSXPC wiring from a live helper, inject:

```sh
clang -fobjc-arc -fblocks -dynamiclib -framework Foundation \
  tools/nsxpc-trace.m \
  -o /tmp/nsxpc-trace.dylib

DYLD_INSERT_LIBRARIES=/tmp/nsxpc-trace.dylib \
  /tmp/continuity-inspect rp-pairing-listen 4 visible
```

That confirms that Apple's controller uses the `com.apple.rapport.RPPairing`
mach service, exports the controller object itself, and passes that controller
instance into `startPairingReceiverController:`.

The PairingManager side now has a matching direct probe:

```sh
clang -fobjc-arc -fblocks -framework Foundation \
  tools/pairingmanager-xpc-probe.m \
  -o /tmp/pairingmanager-xpc-probe

/tmp/pairingmanager-xpc-probe get-identity 4
/tmp/pairingmanager-xpc-probe get-peers 4
/tmp/pairingmanager-xpc-probe monitor 6
```

That probe mirrors the real `CUPairingManager` NSXPC shape:

- mach service: `com.apple.PairingManager`
- exported interface: `CUPairingManagerXPCInterface`
- remote interface: `CUPairingDaemonXPCInterface`

Tracing `result/bin/macolinux-continuity-inspect pairing-summary` with
`DYLD_INSERT_LIBRARIES=/tmp/nsxpc-trace.dylib` confirms that wiring and shows
that even the direct probe still gets server-side
`kMissingEntitlementErr` for `getPairingIdentityWithOptions:`,
`getPairedPeersWithOptions:`, and `startMonitoringWithOptions:`. So the
PairingManager gate is enforced in `rapportd`, not just in the public wrapper.

The `sharingd.nsxpc` side now has two useful research probes:

```sh
clang -fobjc-arc -fblocks -framework Foundation \
  tools/autounlock-probe.m \
  -o /tmp/autounlock-probe

/tmp/autounlock-probe eligible 6
/tmp/autounlock-probe prompt-info 6
/tmp/autounlock-probe state 6
/tmp/autounlock-probe attempt 8
```

Those runs currently show that the auto-unlock/authentication branch is shaped
correctly but server-side gated. `sharingd` logs:

```text
Client (...) does not have unlock manager entitlement
```

and the direct API surface returns `SFAutoUnlockErrorDomain Code=111` for
`authPromptInfoWithCompletionHandler:` and
`autoUnlockStateWithCompletionHandler:`.

The more interesting sibling probe is the companion-service manager path:

```sh
clang -fobjc-arc -fblocks -framework Foundation \
  tools/companion-service-probe.m \
  -o /tmp/companion-service-probe

/tmp/companion-service-probe describe
/tmp/companion-service-probe proxy com.apple.universalcontrol 6
/tmp/companion-service-probe enable com.apple.CompanionAuthentication \
  com.apple.CompanionAuthentication 4
/tmp/companion-service-probe enable-full com.apple.CompanionAuthentication \
  com.apple.CompanionAuthentication 60
```

That probe confirms:

- `SFCompanionServiceManagerProtocol`
  - `enableService:`
  - `disableService:`
- `SFCompanionServiceManagerClient`
  - `streamToService:withFileHandle:acceptReply:`

and, importantly, `serviceManagerProxyForIdentifier:client:withCompletionHandler:`
returns a live `_NSXPCDistantObject` for both
`com.apple.universalcontrol` and `com.apple.CompanionAuthentication` from an
unsigned helper. Calling `enableService:` succeeds and `sharingd` logs:

```text
Client '<private>' lacks device name entitlement
Added service to publisher <private> with identifier <private>
```

So the auto-unlock/authentication branch is entitlement-gated, but the
companion-service publication branch is reachable and worth pushing further.

Export a fully populated companion-service message for a second Mac to consume:

```sh
UC_BONJOUR_NAME=UCSTREAMTEST \
  /tmp/companion-service-probe message-full \
  com.apple.CompanionAuthentication \
  com.apple.CompanionAuthentication
```

The command prints a binary-plist base64 value as
`messageFullDecoded.plist_b64=...`. On another Mac, feed that value into:

```sh
/tmp/companion-service-probe connect-b64 "$MESSAGE_PLIST_B64" 8
```

This calls `SFCompanionXPCManager streamsForMessage:withCompletionHandler:`
with the decoded dictionary. It is the current clean test for whether a real
Apple peer can request our published service while `sharingd` handles the
AppleID/Continuity trust layer.

The first real two-Mac run used `endor` as the publisher and `bespin` as the
requester. `bespin` accepted the message and started `sharingd`'s Bonjour stream
resolver, but after 30 seconds it returned `NSPOSIXErrorDomain Code=60`
(`Connection timed out`). `endor` never received
`streamToService:withFileHandle:acceptReply:`. A parallel
`dns-sd -L ENDORUCTEST2 _continuity._tcp local` from `bespin` also did not
resolve. So `enableService:` keeps a service publication alive inside
`sharingd`, but it is not enough by itself to create a normal remote
`_continuity._tcp` listener.

Local loopback shows the stream requester resolving
`<bonjour_name>._continuity._tcp.local`:

```sh
dns-sd -R UCSTREAMTEST _continuity._tcp local 55678

UC_BONJOUR_NAME=UCSTREAMTEST \
  /tmp/companion-service-probe loopback \
  com.apple.CompanionAuthentication \
  com.apple.CompanionAuthentication 8
```

With a plain TCP listener on port `55678`, the listener receives a TLS
ClientHello. With a temporary self-signed server:

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
  -subj '/CN=UCSTREAMTEST' \
  -keyout /tmp/ucstreamtest.key \
  -out /tmp/ucstreamtest.crt \
  -days 1

openssl s_server \
  -accept 55678 \
  -cert /tmp/ucstreamtest.crt \
  -key /tmp/ucstreamtest.key \
  -www
```

`sharingd` completes the TLS handshake and then rejects the certificate because
it is not an AppleID Continuity chain:

```text
SecTrustEvaluateWithError failed with error errSecMissingRequiredExtension
Client cert chain not trusted. SFAppleIDVerifyCertificateChainSync failed
```

The local AppleID identity probe confirms that a normal helper cannot retrieve
that identity:

```sh
clang -fobjc-arc -fblocks \
  -framework Foundation -framework Security \
  tools/appleid-identity-probe.m \
  -o /tmp/appleid-identity-probe

/tmp/appleid-identity-probe
```

The unsigned run returns `kSecurityRequiredErr`. An ad-hoc signed copy using
`tools/appleid-probe-entitlements.plist` is rejected by AMFI before launch with
`The file is adhoc signed but contains restricted entitlements`. The entitlement
test is useful as a negative control only; it does not expose any key material.

One caution from the control run: holding a
`com.apple.CompanionAuthentication` publication open through
`enableService:` does **not** make it appear to local generic
application-service browsers. Both:

```sh
result/bin/macolinux-continuity-inspect \
  nw-appsvc-browse com.apple.CompanionAuthentication \
  com.apple.universalcontrol 4

result/bin/macolinux-network-endpoint-c-probe \
  browse-appsvc-bundle com.apple.CompanionAuthentication \
  com.apple.universalcontrol 4 include-ble 1 use-awdl 1 use-p2p 1 \
  include-txt-record 1
```

reached `ready` and then timed out or cancelled without surfacing an endpoint.
So this publisher path is real, but it is not the same thing as a generic
browseable `NWBrowser` app-service endpoint in the current unsigned context.

The stream publisher is gated by a private Sharing preference. Static
disassembly shows `SDStreamManager addService:` calls `publish` only when
`SFActivityMonitor.sharedMonitor.alwaysSendPayload` returns true. That getter
reads `AlwaysSendPayload` from `com.apple.Sharing` first, then
`com.apple.NetworkBrowser`.

Temporary Mac-to-Mac stream proof:

```sh
defaults write com.apple.Sharing AlwaysSendPayload -bool true
killall sharingd || true

UC_BONJOUR_NAME=<published-_continuity-instance> \
  /tmp/companion-service-probe enable-full \
  com.apple.CompanionAuthentication \
  com.apple.CompanionAuthentication 60
```

With the actual published `_continuity._tcp` instance as `bonjour_name`, another
Mac can call `connect-b64` with the printed plist and receive:

```text
connect.stream.fileHandle.class=NSConcreteFileHandle
connect.stream.error=nil
```

The publishing Mac receives `streamToService:withFileHandle:acceptReply:` and
can accept the connection. The file handle carries arbitrary bidirectional
bytes; the current probe verified `bespin-ping` from the requester and
`endor-reply` from the publisher.

The packaged helper can also bridge the accepted Apple stream into a local TCP
daemon with `UC_STREAM_RELAY` / `companion-stream --relay`. Live test on
2026-05-02:

```sh
result/bin/macolinux-ucd relay listen \
  --bind 127.0.0.1:4717 \
  --send-text endor-relay-ready \
  --echo

result/bin/macolinux-uc-bootstrap companion-stream publish \
  --probe /tmp/companion-service-probe \
  --bonjour-name e3a0d17e48fc \
  --relay 127.0.0.1:4717 \
  --seconds 70

ssh bespin 'UC_STREAM_WRITE=bespin-via-apple \
  /tmp/companion-service-probe connect-b64 <publish-plist-b64> 12'
```

The local Rust relay received:

```text
relay recv: ... bytes=16 ... utf8="bespin-via-apple"
```

The remote requester read the daemon-originated bytes and echoed marker:

```text
connect.stream.read.utf8=endor-relay-readybespin-via-apple
```

This verifies the packaged bridge path is bidirectional:
`sharingd`-accepted stream <-> Objective-C helper <-> local TCP daemon.

After testing, clean the preference:

```sh
defaults delete com.apple.Sharing AlwaysSendPayload 2>/dev/null || true
killall sharingd || true
```

This is the first working Apple-accepted Continuity stream broker path. It
keeps the AppleID TLS material inside `sharingd`, which is important because a
normal helper cannot export that identity.

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

For a pragmatic bridge build, the next blocker is narrower: define the byte
protocol carried over the accepted companion stream and map it to local Linux
input/display events. The Apple trust problem can stay on the macOS helper side
for now.
