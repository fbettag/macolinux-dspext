# Universal Control Protocol Notes

These notes capture what is visible from a macOS 26.3 host that is already
using Universal Control with another Mac.

## Local Components

- The user agent is `/System/Library/CoreServices/UniversalControl.app`.
- Its bundle identifier is `com.apple.universalcontrol`.
- It is launched as `com.apple.ensemble` by
  `/System/Library/LaunchAgents/com.apple.ensemble.plist`.
- It depends on private frameworks including `UniversalControl.framework`,
  `Rapport.framework`, `Sharing.framework`, `HID.framework`,
  `TimeSync.framework`, `NearbyInteraction.framework`, and `SkyLight.framework`.
- Relevant private entitlements include `com.apple.CompanionLink`,
  `com.apple.wifip2pd`, `com.apple.wifi.peer_traffic_registration`,
  `com.apple.private.skylight.universal-control`,
  `com.apple.private.hid.client.admin`, and
  `com.apple.private.hid.client.event-dispatch`.

## Discovery

`launchctl print gui/$(id -u)/com.apple.ensemble` shows Universal Control being
activated through Rapport matching events:

- `com.apple.universalcontrol.discovery`: `stream = com.apple.rapport.matching`,
  descriptor `{ type = discovery, serviceType = _companion-link._tcp }`
- `com.apple.universalcontrol.server`: `stream = com.apple.rapport.matching`,
  descriptor `{ type = server, serviceType = com.apple.universalcontrol }`

The normal LAN CompanionLink Bonjour service advertises as
`_companion-link._tcp.local` with TXT keys such as:

- `rpMac=0`
- `rpFl=0x20000`
- `rpVr=715.2`
- `rpAD=...`
- `rpBA=...`
- `rpHN=...`
- `rpHI=...`

An AWDL capture also shows a separate ephemeral `CLink-...` CompanionLink
advertisement on AWDL. Its TXT shape differs from the LAN identity:

- service instance: `CLink-<hex>._companion-link._tcp.local`
- `rpFl=0x800`
- `rpVr=715.2`
- `rpAD=...`
- `rpBA=...`

This looks like the direct-link identity used after Rapport discovers a known
peer and upgrades onto AWDL.

## Linux Advertisement Experiments

A minimal mDNS/TCP peer was run on a NixOS laptop at a test LAN address using
`tools/companionlink-mdns-peer.py`.

The first useful fix was pinning mDNS multicast to the WLAN address with
`IP_MULTICAST_IF`; otherwise the laptop selected its WireGuard address and macOS
did not see the synthetic service.

With multicast pinned, macOS `dns-sd` can browse and resolve the fake peer:

```text
linux-peer._companion-link._tcp.local.
SRV linux-peer.local.:49152
TXT rpMac=0 rpHN=example-host rpFl=0x20000 rpHA=020000000031
    rpVr=715.2 rpAD=010203040506 rpHI=0000000000000000
    rpBA=02:00:00:00:00:31
```

The TCP listener is reachable from the Mac, verified with `nc`. However,
`rapportd` did not connect to the listener and did not log the fake peer as a
usable Universal Control candidate.

The AWDL-style service form was also tested over WLAN:

```text
CLink-020000000031._companion-link._tcp.local.
SRV CLink-020000000031.local.:49153
TXT rpBA=02:00:00:00:00:31 rpFl=0x800 rpAD=010203040506 rpVr=715.2
```

This also browsed and resolved via `dns-sd`, but `rapportd` still did not open a
TCP connection.

Current inference: plain mDNS visibility is not enough to enter the Universal
Control candidate path. Rapport appears to require additional Continuity context
such as BLE discovery, known-peer trust, iCloud/IDS identity, or a real AWDL
direct-link path before it attempts the CompanionLink stream connection.

## Static Symbols And Strings

The Universal Control binary contains class and string names that describe the
rough layering:

- Rapport/CompanionLink: `CompanionLinkClient`, `CompanionLinkServer`,
  `CompanionLinkSession`, `RapportStreamServer`, `RapportStreamSession`
- Peer-to-peer transport: `P2PController`, `P2PBrowser`, `P2PPeerCoordinator`,
  `P2PLink`, `P2PDirectLink`, `P2PStream`, `P2PMessage`
- Event and HID path: `EventController`, `EventDispatcher`,
  `EventConnection_macOS`, `PointerController_macOS`,
  `EnsembleHIDController`
- Reports: `KeyboardReport`, `PointerReport`, `ScrollReport`, `ButtonReport`,
  `ConsumerReport`, `AppleVendorKeyboardReport`,
  `AppleVendorTopCaseReport`, `FluidTouchGestureReport`,
  `NavigationSwipeReport`
- Event reports: `TargetReadyReport`, `TargetBeginReport`,
  `TargetReplyReport`, `FocusMoveReport`, `FocusResetReport`,
  `TargetConnectReport`, `TargetEventReport`

Useful internal source path strings include `P2PStream.swift`,
`P2PMessage.swift`, `EventController.swift`, `EventReport.swift`, and
`Glue/OPACKCoding.swift`.

## Dyld And Rizin Workflow

On current macOS releases, many private framework paths under
`/System/Library/PrivateFrameworks` are stubs or symlinks into the dyld shared
cache. Rizin does not currently load the arm64e dyld shared cache directly on
this host; it fails on slide info version 5. The practical workflow is to
extract the images first:

```sh
mkdir -p analysis/dyld-extract
nix-shell -p darwin.dyld --run \
  'DYLD_FALLBACK_LIBRARY_PATH=/nix/store/9mrn3fjjkx78gqynh5ziyqirq99vbwg8-dyld-1286.10-lib/lib \
   dsc_extractor /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e \
   analysis/dyld-extract'
```

The extracted images used for the current notes are:

- `analysis/dyld-extract/System/Library/PrivateFrameworks/Rapport.framework/Versions/A/Rapport`
- `analysis/dyld-extract/System/Library/PrivateFrameworks/Sharing.framework/Versions/A/Sharing`
- `analysis/dyld-extract/System/Library/PrivateFrameworks/UniversalControl.framework/Versions/A/UniversalControl`

Useful rizin entry points:

```sh
nix-shell -p rizin --run \
  'rizin -q -A analysis/dyld-extract/System/Library/PrivateFrameworks/Rapport.framework/Versions/A/Rapport'
```

Live attach to `UniversalControl` failed even as root via local SSH
with `unknown error in debug_attach`. That is probably SIP or hardened runtime,
so the current tracing is static disassembly plus packet captures.

## Universal Control Visibility Gates

The `UniversalControl` executable imports `OPACKDecodeData`,
`OPACKEncoderCreateData`, `RPCompanionLinkClient`,
`RPCompanionLinkDevice`, and `RPOptionSenderIDSDeviceID`. Swift and Objective-C
metadata expose the peer coordination layer:

- `CompanionLink.CompanionLinkClient`
- `CompanionLink.CompanionLinkServer`
- `CompanionLink.CompanionLinkSession`
- `CompanionLink.RapportStreamServer`
- `CompanionLink.RapportStreamSession`
- `EnsembleAgent.P2PBrowser`
- `EnsembleAgent.P2PPeerCoordinator`
- `EnsembleAgent.P2PStream`
- `EnsembleAgent.ProximityController`
- `EnsembleAgent.CloudPreferencesController`

The production process entitlements line up with that shape. UniversalControl
has `com.apple.CompanionLink`, HID admin/event-dispatch access, private
SkyLight Universal Control access, Wi-Fi peer traffic registration, and
`com.apple.wifip2pd`. `milod` also has `com.apple.CompanionLink`,
`com.apple.rapport.Client`, nearbyd access, private SkyLight display control,
and CoreWiFi/Wi-Fi privileges. A normal helper, even when run as root over
local SSH, cannot activate the same Rapport client path:

```sh
target/research/continuity-inspect \
  rpcl-browse com.apple.universalcontrol 2 0 0 0
```

returns:

```text
RPCompanionLinkClient activation error:
  kMissingEntitlementErr (Missing entitlement 'com.apple.CompanionLink')
activeDevices: 0
events: 0
```

Runtime introspection of the relevant Rapport classes is still useful for the
wire implementation:

- `RPCompanionLinkClient` exposes `registerEventID:options:handler:`,
  `registerRequestID:options:handler:`, `sendEventID:...`,
  `sendRequestID:...`, `serviceType`, `pairingInfo`, `pairSetupFlags`,
  `pairVerifyFlags`, and device found/lost/changed handlers.
- `RPStreamServer` exposes `serviceType`, `messenger`,
  `streamAcceptHandler`, `streamPrepareHandlerEx`, `streamFlags`, and
  `streamQoS`.
- `RPStreamSession` exposes `serviceType`, `streamID`, `streamType`,
  `pskData`, `streamKey`, `streamSocket`, `trafficSessionID`,
  `receivedEventHandler`, `receivedRequestHandler`, and
  `connectionReadyHandler`.

Static strings in the UniversalControl executable show the production stream
and message layer around those classes:

```text
CompanionLink.CompanionLinkClient
CompanionLink.RapportStreamServer
CompanionLink.RapportStreamSession
EnsembleAgent.P2PDirectLink
EnsembleAgent.P2PStream
EnsembleAgent.P2PPeerCoordinator
com.apple.universalcontrol.available
com.apple.universalcontrol.connected
com.apple.universalcontrol.inputstate
com.apple.universalcontrol.hid-activity
com.apple.universalcontrol.virtual-service
com.apple.universalcontrol.virtual-service-pool
com.apple.universalcontrol.transfer-source
com.apple.universalcontrol.transfer-destination
```

Relevant rejection strings are in the P2P/IDS path:

- `IDS ... Target Reply: Reject (No Link to Peer)`
- `IDS ... Target Reply: Reject (Incoming Peer Not Visible)`
- `IDS ... Target Reply: Reject (Unsupported For Devices Of Type ...)`
- `static links ignored, device not visible`
- `DEVICE MOVEMENT AVAILABLE`
- `no P2PPeerCoordinatorContext to check connected devices`

The `Incoming Peer Not Visible` string is reached from a boolean check in the
P2PPeerCoordinator accept path. That check appears after a target transition
request, not during raw Bonjour browsing. Current inference: our fake Linux
Bonjour peer never reaches this layer because the earlier Sharing/Rapport
discovery path has not marked it as a visible, known, compatible peer.

`RPCompanionLinkClient shouldReportDevice:...` has an earlier generic filter
that rejects devices carrying the unauthenticated device flag unless the client
asked for `RPOptionAllowUnauthenticated`. Universal Control contains pairing
and CompanionAuthentication strings, but no visible `allowUnauthenticated`
string in the executable. This matches the live behavior: `rapportd` can see
the Linux peer, but it remains a `Bonjour unauth` peer and does not get promoted
into the connectable Universal Control path.

A 55 second simultaneous live capture while moving the pointer between `endor`
and the already-paired MacBook produced no `UniversalControl` process lines and
no `P2PStream`/`RPStreamServer` log lines in the broad unified-log capture. The
logs were dominated by `nearbyd`, `sharingd`, `rapportd`, `milod`, BLE
NearbyInfo/NearbyAction, and `RPRemoteDisplayDaemon Ignoring unsupported BLE
device` messages. This is a negative result rather than a protocol conclusion:
the next capture needs either a forced connect/disconnect event or a narrower
predicate with any required log level enabled for the UniversalControl
subsystems.

## Live Universal Control Transition

A later forced transition capture did catch the production path. The raw pcap
and unified log are kept local-only under `target/research/` with tag
`20260422T174537Z`; they are intentionally not part of the public research
tree.

The transition shape is:

1. An already-trusted CompanionLink connection exists over infrastructure
   Ethernet/Wi-Fi. In the capture this connection completes PairVerify M1-M4
   and receives `peerDeviceInfo` whose service list includes
   `com.apple.universalcontrol`.
2. `UniversalControl` activates an `RPCompanionLinkClient` with AppID
   `com.apple.universalcontrol` and flags including BLE, AWDL, `ForceAWDL`,
   `NoiWiFi`, `Ensemble`, `NoL2CAP`, and `NoUSB`.
3. `rapportd` sends `_needsAWDL` over the existing CompanionLink connection.
4. `wifip2pd` starts browsing `_companion-link._tcp.local` on `awdl0` and
   finds an ephemeral `CLink-...` service. The TXT shape is the AWDL form:
   `rpFl=0x800`, `rpVr=715.2`, `rpAD=...`, and `rpBA=...`.
5. `RPIdentityDaemon` resolves the peer's device auth tag to an `RPIdentity`
   of type `SameAccountDevice`.
6. The AWDL CompanionLink TCP connection performs clear PairVerify frames, then
   switches to encrypted `E_OPACK` frames.
7. A request with ID `com.apple.universalcontrol` is sent over the encrypted
   AWDL CompanionLink connection. The peer responds by issuing `_streamStart`
   requests for the Universal Control P2P streams.

The live pcap sees the same clear PairVerify record shape as the local probes:

```text
0x05 PairVerifyStart body_len=47
0x06 PairVerifyNext  body_len=131
0x06 PairVerifyNext  body_len=94
0x06 PairVerifyNext  body_len=9
0x08 E_OPACK         after PairVerify
```

The first `_streamStart` batch used IDs `SYNC`, `EVNT`, `CLIP`, and `DRAG`
under UUID `C80A18DD-...`; macOS prepared local ports `60231..60234` but
returned `kUnexpectedErr` for all four sessions. About one second later a fresh
AWDL control connection succeeded. The successful batch used stream UUID
`6843EBDE-86D7-4842-8AF1-FE691AA0F913` and mapped as follows:

```text
SYNC:6843EBDE-...  local [awdl0]:60237  peer:63695  P2PStream Activated
EVNT:6843EBDE-...  local [awdl0]:60238  peer:63696  P2PStream Activated
CLIP:6843EBDE-...  local [awdl0]:60239  peer:63697  P2PStream Activated
DRAG:6843EBDE-...  local [awdl0]:60240  peer:63698  P2PStream Activated
```

`EVNT` explicitly changes QoS from Default to Voice before accepting the socket.
After all four streams activate, UniversalControl logs `Connection Ready`.

The pcap summary for the successful region shows high-volume encrypted traffic
on `SYNC`, a small encrypted exchange on `EVNT`, and mostly TCP setup/teardown
on `CLIP` and `DRAG` in this capture window. `SYNC` carries large encrypted
`E_OPACK` records such as body lengths `6383`, `9269`, and `9482`; `EVNT`
carries complete encrypted records with body lengths `44` and `48`. This does
not prove that `SYNC` is the only event-bearing stream, only that it was the
active stream in this particular transition.

Implementation consequence: once the Linux peer is trusted enough to complete
AWDL CompanionLink PairVerify, the macOS side is expected to send
`_streamStart` requests. The Linux peer must reply with per-stream endpoint
metadata equivalent to `RPStreamSession` preparation and accept inbound TCP
connections for at least `SYNC`, `EVNT`, `CLIP`, and `DRAG`. Those sockets then
carry Rapport records independently from the main CompanionLink control
connection.

`RPStreamServer _handleStartRequest:options:responseHandler:` confirms the
inner `_streamStart` request dictionary keys:

```text
_streamID
_streamType
_streamFlags
```

The stream type lookup table in Rapport maps `1 = UDPSocket`, `2 = RPCnx`, and
`3 = UDPNWPath`; `0` is treated as a missing stream type. The Universal Control
logs for the live transition say `Type RPCnx`, so the four `SYNC`, `EVNT`,
`CLIP`, and `DRAG` sessions are `RPStreamType` value `2` in this capture.
Adjacent `RPStreamSession` code references the response-side endpoint keys
`_streamAddr`, `_streamMACAddr`, `_streamPort`, `_streamSrv`, `_streamKey`, and
`pskD`.

## Rapport Frame Layer

`Rapport.framework` contains the record framing used by the live Universal
Control TCP streams. The key methods are:

- `-[RPConnection _sendFrameType:body:]`
- `-[RPConnection _sendFrameType:unencryptedObject:]`
- `-[RPConnection _receivedHeader:body:ctx:]`
- `-[RPConnection _receivedHeader:encryptedObjectData:ctx:]`
- `-[RPConnection _clientPreAuthStart]`
- `-[RPConnection _clientPairVerifyStart]`
- `-[RPConnection _serverPreAuthRequestWithData:]`
- `-[RPConnection _serverPairVerifyWithData:start:]`

`_sendFrameType:body:` writes a 4-byte header:

```text
TT LL LL LL BODY...
```

`TT` is the frame type byte. `LL LL LL` is the body length encoded as a 24-bit
big-endian integer. This matches the packet captures: total TCP payload length
is `4 + body_length`.

`_receivedHeader:body:ctx:` labels the frame types seen so far:

```text
0x00 Invalid
0x01 NoOp
0x03 PairSetupStart
0x04 PairSetupNext
0x05 PairVerifyStart
0x06 PairVerifyNext
0x07 U_OPACK
0x08 E_OPACK
0x09 P_OPACK
0x0a PA_Req
0x0b PA_Rsp
0x12 FamilyIdentityRequest
0x20 FamilyIdentityUpdate
0x21 FamilyIdentityResponse
0x22 FriendIdentityUpdate
0x30 WatchIdentityRequest
0x31 WatchIdentityResponse
0x40 FriendIdentityRequest
0x41 FriendIdentityResponse
0x42 FriendIdentityUpdate
```

The `0x03..0x06` mapping is confirmed by live probes against the local
CompanionLink listener: after `PA_Req`/`PA_Rsp`, frames `0x03` and `0x04`
enter `PairSetupServer`; frames `0x05` and `0x06` enter `PairVerifyServer`;
`0x02` is logged as an unhandled frame.

`_clientPreAuthStart` constructs an object, logs `Send PreAuthRequest`, and
sends it through `_sendFrameType:unencryptedObject:` with frame type `0x0a`.
That confirms `0x0a` is an unencrypted OPACK pre-auth request.

The OPACK data/string length boundary matters for pairing. Apple treats
`0x70..0x90` as inline data lengths `0..32`; `0x91` carries a one-byte length,
`0x92` a little-endian `uint16` length, and `0x93` a little-endian `uint32`
length. The same pattern applies to strings with base `0x40`. Encoding a
37-byte `_pd` value as `0x90 0x25 ...` shifts the TLV by one byte on macOS; the
correct marker is `0x91 0x25 ...`.

Live Universal Control pointer traffic used frame type `0x08`, which Rapport
labels `E_OPACK`. The captured bodies are high entropy and the framework logs
`Encryption not setup` in the encrypted send/receive paths when the crypto
state is absent. This strongly indicates the visible event stream is encrypted
OPACK after the 4-byte header.

Pairing/authentication strings in `Rapport.framework` point at the next layer to
reproduce:

- `RPPairingIdentity`
- `RPPairingTemporaryIdentity`
- `RPPairingBonjourResolveResponse`
- `RPPairingPINInfo`
- `AppleIDPairVerify`
- `PairVerify start client`
- `PairVerify completed client`
- `PairVerify completed server`
- `SessionPaired`
- `AdHocPaired`
- `AuthAWDLPairingMode`
- `CompanionAuthentication`

The implementation should expect to drive at least pre-auth, PairVerify, and
encrypted OPACK setup before any `P2PMessage` or HID/event report decoding is
useful.

## CoreUtils PairVerify and Paired Peers

`CoreUtils.framework` owns the `CUPairingSession` state machine used by the
PairVerify logs seen from real Apple devices. The live BLE/L2CAP capture shape
matches its HomeKit-flavored TLV8 exchange:

```text
M1: 0x06 State=01, 0x03 PublicKey=32 bytes, 0x19 AppFlags=01
M2: 0x06 State=02, 0x03 PublicKey=32 bytes, 0x05 EncryptedData=85 bytes
M3: 0x06 State=03, 0x05 EncryptedData=82 bytes
M4: 0x06 State=04
```

Relevant CoreUtils strings and symbols:

- `_VerifyClientM1`, `_VerifyClientM2`, `_VerifyClientM3`, `_VerifyClientM4`
- `_VerifyServerM1`, `_VerifyServerM2`, `_VerifyServerM3`, `_VerifyServerM4`
- `PairVerifyClient`, `PairVerifyServer`
- `Public Key`, `EncryptedData`, `State`, `AppFlags`
- `CUPairingSession`, `CUPairingManager`, `CUPairingDaemon`, `CUPairedPeer`
- `HomeKitHAP`, `HomeKitUser`, `HomeKitLegacy`, `HomeKitLocalKey`

Disassembly of `_PairingSessionFindPeerEx` shows three lookup paths:

1. If the session has a custom find-peer handler at offset `0x40`, CoreUtils
   calls that first.
2. Otherwise, if the session flags do not request PairingManager lookup,
   CoreUtils queries the keychain via `KeychainCopyMatchingFormatted`, extracts
   a stored 32-byte public key, decodes optional OPACK metadata, and returns it.
3. If PairingManager lookup is enabled, CoreUtils asks `CUPairingDaemon` or a
   `CUPairingManager` XPC client for `findPairedPeer:options:error:` or
   `findPairedPeer:options:completion:`.

The successful PairingManager path returns a `CUPairedPeer`. CoreUtils then
requires:

- `publicKey` exists
- `publicKey.length == 32`
- optional `acl` can be returned to the caller

If there is no peer, no public key, or the public key is not exactly 32 bytes,
PairVerify fails before encrypted stream setup. This is the strongest evidence
so far that a Linux target must either appear as a previously paired
`CUPairedPeer` to macOS or complete the same pairing path that creates one.

Disassembly of `__PairingSessionSavePeerKeychain` shows the fallback keychain
writer deletes any existing peer first, hex-encodes the 32-byte peer public key,
serializes optional permissions/metadata, then writes a generic-password style
item through `KeychainAddFormatted`. The public CoreUtils surface also exposes
`PairingSessionSetFindPeerHandler_b`, `PairingSessionSetSavePeerHandler_b`,
`PairingSessionSavePeer`, and `PairingSessionSetSelfAppFlags`, which are useful
anchors for later experiments.

The PairVerify exchange uses the expected HomeKit primitives, but we now have
the exact CoreUtils constants and checkpoints:

- Both client and server generate 32 random bytes and call Curve25519 to
  produce the public key sent as TLV type `0x03`.
- The ephemeral Curve25519 shared secret is rejected if it is all zeroes.
- CoreUtils derives the PairVerify encryption key with SHA-512 HKDF:
  `salt="Pair-Verify-Encrypt-Salt"`, `info="Pair-Verify-Encrypt-Info"`,
  output length `32`.
- M2 encrypted data is ChaCha20-Poly1305 using nonce/AAD label `PV-Msg02`.
- M3 encrypted data is ChaCha20-Poly1305 using nonce/AAD label `PV-Msg03`.
- The client M2 and server M3 paths both extract TLV type `0x01`
  (`Identifier`), call `_PairingSessionFindPeerEx`, and then require TLV type
  `0x0a` (`Signature`) to verify against that paired peer's 32-byte public key.
- The client M4 path also references `PV-Msg4s`/`PV-Msg04`, MFi verification
  salts, and PairVerify resume-session-id salts. Those branches have not yet
  been reduced to pseudocode.

After PairVerify, `CUPairingSession openStreamWithName:type:error:` returns a
`CUPairingStream`; live logs show the stream name `main`. Disassembly of
`CUPairingStream prepareWithName:isClient:pskData:error:` shows the protected
stream key schedule:

- `pskData.length` must be at least `32`, otherwise the method reports
  `PSK too small`.
- The AEAD is `ChaCha20Poly1305`.
- The HKDF salt length is `0`.
- The HKDF info strings are formatted from the stream name:
  `ClientEncrypt-<name>` and `ServerEncrypt-<name>`.
- For an endpoint acting as client, the encrypt AEAD uses
  `ClientEncrypt-<name>` and the decrypt AEAD uses `ServerEncrypt-<name>`.
  The server side swaps those directions.
- `CUPairingStream init` sets `_authTagLength` to `16`.
- `encryptData:aadBytes:...` allocates `plaintext_length + authTagLength`
  bytes and writes the auth tag immediately after the ciphertext, so the
  protected Rapport body is `ciphertext || tag`.
- `decryptData:aadBytes:...` treats the final `_authTagLength` bytes as the
  tag and decrypts the preceding bytes into plaintext.
- The encrypt and decrypt nonces are 12-byte counters stored separately at
  `_encryptNonce` and `_decryptNonce`. Both start at zero and increment as
  little-endian 96-bit integers after every encrypt/decrypt attempt.

For the observed `main` stream, the stream AEAD keys are therefore derived from
the PairVerify Curve25519 shared secret with `ClientEncrypt-main` and
`ServerEncrypt-main`. The Pair-Verify-Encrypt HKDF output is used for M2/M3 TLV
encrypted data, but `CUPairingSessionDeriveKey` reads the raw 32-byte
Curve25519 result stored in the session at offset `0x28e` when deriving
post-PairVerify stream keys.

## Universal Control OPACK Codec

Universal Control itself imports `OPACKDecodeData` and
`OPACKEncoderCreateData`. Rizin xrefs show small wrapper functions around those
imports:

- `0x100081624`: retains an Objective-C `Data` object and calls
  `OPACKDecodeData`.
- `0x1001ca78c`: retains an object and calls `OPACKEncoderCreateData`.

The higher-level callers are Swift codec functions in
`Glue/OPACKCoding.swift`. Error strings identify the boundary:

- `OPACK decoding error`
- `OPACK encoding error`
- `unknown P2PMessage ID`

The nearby source path and type strings identify the next payload layer:

- `EnsembleAgent/P2PMessage.swift`
- `EnsembleAgent/EventReport.swift`
- `P2PMessage`
- `TargetReadyReport`
- `FocusMoveReport`
- `TargetEventReport`
- `KeyboardReport`
- `PointerReport`
- `ScrollReport`
- `AppleVendorKeyboardReport`

Practical implication: once a Linux client reaches decrypted `E_OPACK` bodies,
the next implementation unit is a standalone OPACK decoder/encoder plus
`P2PMessage` discriminators. HID report semantics are likely downstream of that
codec and are not the first blocker.

## Sharing And BLE Discovery

`Sharing.framework` exposes the likely visibility gate that our synthetic
Bonjour peer is missing. Key strings and methods include:

- `SFBLEAdvertiser`, `SFBLEClient`, `SFBLEConnection`, `SFBLEScanner`,
  `SFBLEDevice`, and `SFBLEPipe`
- `WPNearby`, `WPPairing`, `NearbyInfo`, `NearbyAction`, `WPAWDL`
- `WPNearbyKeyRSSI`, `WPNearbyKeyManufacturerData`,
  `WPNearbyKeyDeviceAddress`, `WPNearbyKeyPaired`,
  `WPNearbyKeyUseCaseList`
- `WPPairingKeyAdvertisingChannel`, `WPPairingKeyDeviceAddress`,
  `WPPairingKeyAccessoryStatusDecrypted`
- `-[SFBLEScanner _foundDevice:advertisementData:rssi:fields:]`
- `-[SFBLEScanner _nearbyParseManufacturerData:fields:]`
- `-[SFBLEScanner _nearbyParseNearbyInfoPtr:end:fields:]`
- `-[SFBLEScanner pairingParsePayload:identifier:bleDevice:peerInfo:]`
- `-[SFDeviceDiscovery triggerEnhancedDiscovery:useCase:completion:]`

The disassembly of `_nearbyParseNearbyInfoPtr:end:fields:` shows a compact
NearbyInfo parser that reads a flags byte and conditionally populates fields
used by the device discovery layer. `_foundDevice:advertisementData:rssi:fields:`
then records or updates the `SFBLEDevice` and known/paired state. This is
consistent with the Linux mDNS experiments: macOS can browse and resolve the
fake `_companion-link._tcp` record, but `rapportd` does not connect because the
peer has not been promoted by the BLE/Nearby/Pairing path.

Disassembly of `_nearbyParseManufacturerData:fields:` shows the raw BLE
manufacturer data shape:

```text
4c 00 TT LL BODY... [TT LL BODY...]
```

`4c 00` is Apple's Bluetooth company identifier in little-endian order. The
remaining bytes are Continuity TLVs. The TLV length byte stores the payload
length in its low five bits (`length_byte & 0x1f`); the high three bits are
flags. The parser dispatches at least these TLV types:

```text
0x0f NearbyAction
0x10 NearbyInfo
```

A short BlueZ scan from a Linux host captured nearby Apple Continuity
advertisements with the same shape. Representative payloads below are sanitized
documentation examples:

```text
0f 05 01 02 03 04 05   NearbyAction payload 0102030405
10 02 00 00            NearbyInfo payload 0000
```

Advertising that payload from Linux with `tools/ble-continuity-advertise.py`
was accepted by macOS:

```sh
./tools/ble-continuity-advertise.py \
  --host root@linux-peer \
  --run \
  --duration 20 \
  --nearby-action 0102030405 \
  --nearby-info 0000
```

The resulting raw advertising data is:

```text
02 01 06
0e ff 4c 00 10 02 00 00 0f 05 01 02 03 04 05
```

`sharingd` logged the exact action payload:

```text
BLE NearbyAction found ... AdvD <0102030405> ... Paired no, Cnx no, WiFiP2P
```

`rapportd` also saw the synthetic device:

```text
BLE device found ... WiFiP2P, DF 0x220 < Ranging DeviceClose > ... DFl 0x2 < Action >
```

This is the first confirmed Linux-origin signal that reaches the same
macOS BLE/Nearby/Rapport discovery path as real Apple devices. It still lands
as unpaired and does not create a Universal Control candidate by itself.

## Combined BLE And CompanionLink Probe

The next experiment ran BLE Continuity advertising and CompanionLink Bonjour at
the same time from a Linux host, using the Linux Bluetooth address as the
CompanionLink `rpBA`:

```sh
python3 /tmp/companionlink-mdns-peer.py \
  --duration 45 \
  --instance linux-peer \
  --hostname linux-peer.local \
  --ipv4 192.0.2.11 \
  --multicast-ipv4 192.0.2.11 \
  --port 49152 \
  --txt rpMac=0 \
  --txt rpHN=linux-peer \
  --txt rpFl=0x20000 \
  --txt rpHA=020000000031 \
  --txt rpVr=715.2 \
  --txt rpAD=010203040506 \
  --txt rpHI=0000 \
  --txt rpBA=02:00:00:00:00:31
```

Concurrently:

```sh
./tools/ble-continuity-advertise.py \
  --host root@linux-peer \
  --run \
  --duration 35 \
  --nearby-action 0102030405 \
  --nearby-info 0000
```

This produced the first explicit correlation in `rapportd`:

```text
CLink: Found CUBonjourDevice 02:00:00:00:00:31, 'linux-peer'
Bonjour unauth peer found. BLE Address: <02:00:00:00:00:31>,
device: CUBonjourDevice 02:00:00:00:00:31, "linux-peer",
TXT { "rpMac" : "0", "rpHN" : "linux-peer", "rpFl" : "0x20000",
      "rpVr" : "715.2", "rpHA" : "020000000031",
      "rpAD" : "010203040506", "rpHI" : "0000",
      "rpBA" : "02:00:00:00:00:31" },
found over AWDL: NO
```

At the same time, `sharingd` saw both Linux-origin BLE payloads:

```text
BLE NearbyAction found ... AdvD <0102030405> ... Paired no, Cnx no, WiFiP2P
BLE NearbyInfo found ... AdvD <0000> ... Paired no, Cnx no, WiFiP2P
```

A second run used the AWDL-style Bonjour shape:

```sh
python3 /tmp/companionlink-mdns-peer.py \
  --duration 35 \
  --instance CLink-020000000031 \
  --hostname CLink-020000000031.local \
  --ipv4 192.0.2.11 \
  --multicast-ipv4 192.0.2.11 \
  --port 49153 \
  --txt rpFl=0x800 \
  --txt rpVr=715.2 \
  --txt rpAD=010203040506 \
  --txt rpBA=02:00:00:00:00:31
```

`rapportd` accepted the shape as an unauthenticated CompanionLink peer update:

```text
Bonjour unauth peer changed. BLE Address: <02:00:00:00:00:31>,
device: CUBonjourDevice 02:00:00:00:00:31, "CLink-020000000031",
TT 0x3 < Enet WiFi >, TXT { "rpFl" : "0x800",
                            "rpAD" : "010203040506",
                            "rpBA" : "02:00:00:00:00:31",
                            "rpVr" : "715.2" },
found over AWDL: NO
```

Neither run caused a TCP accept on the Linux listener. Current inference: BLE
and Bonjour are now correlated correctly, but `rapportd` still refuses to start
the `RPConnection` stream because the peer remains unauthenticated/unpaired and
is not found over a real AWDL direct link.

A more aggressive combined probe advertised `rpFl=0xffffffff` with the same
BLE payload. That still did not produce a TCP accept on the Linux listener.
A later clean capture showed that nearby `CLinkCnx` reachability-probe logs
were from existing HomePod churn, not from the synthetic Linux peer.

Two clean Linux-focused runs used `rpFl=0xffffffff`, `rpMd=MacBookPro18,3`, and
the same `rpBA`/BLE address:

- Bonjour-first: `linux-peer-uc-clean`, port `49155`.
- BLE-first: `linux-peer-uc-blefirst`, port `49156`.

Both runs resolved with `dns-sd` and both reached `rapportd` as an
unauthenticated Bonjour peer. The BLE-first run confirmed discovery order does
not change the result:

```text
BLE NearbyAction found ... AdvD <0102030405> ... Paired no, Cnx no, WiFiP2P
BLE NearbyInfo found ... AdvD <0000> ... Paired no, Cnx no, WiFiP2P
Bonjour unauth peer changed. BLE Address: <02:00:00:00:00:31>,
device: CUBonjourDevice 02:00:00:00:00:31, "linux-peer-uc-blefirst",
TT 0x3 < Enet WiFi >, TXT { "rpMac" : "0", "rpHN" : "linux-peer-uc-blefirst",
                            "rpFl" : "0xffffffff",
                            "rpMd" : "MacBookPro18,3",
                            "rpBA" : "02:00:00:00:00:31", ... },
changed flags: 0x10 < Name >, found over AWDL: NO
```

Current inference: BLE and Bonjour correlation is real, but it still only
creates an unauthenticated non-AWDL CompanionLink peer. macOS does not attempt
the TCP `RPConnection` stream for that state.

The NixOS-deployed Rust daemon reproduced the same state with real Linux
Bluetooth hardware. `fistel` advertised this legacy BLE payload:

```text
02 01 06
0e ff 4c 00 10 02 22 04 0f 05 90 00 45 d5 46
```

macOS `sharingd` accepted both Continuity TLVs:

```text
BLE NearbyAction found ... AdvD <900045d546> ... Paired no, Cnx no, WiFiP2P
BLE NearbyInfo found ... AdvD <2204> ... Paired no, Cnx no, WiFiP2P
```

The same logs repeatedly rejected the synthetic device at the identification
layer:

```text
Max identification devices reached, skipping ... WiFiP2P,
DF 0x220 < Ranging DeviceClose >, DT Generic, AcLv ? (16)
```

By contrast, an already accepted Universal Control peer is reported by
`rapportd` as a paired iCloud/IDS identity:

```text
BLE device changed ... IDS ..., AltDSID ..., AID ..., DuetSync,
MRI ..., MRtI ..., PairedBT, PairedSys Conjectured, rapportID ...,
WiFiP2P, DF 0x29 < MyMe MyiCloud Ranging >, ARS Idle, DT Generic
```

When the real peer is user-active, the same device can temporarily include
`AirDrop` and `ARS High`, but the stable admission difference is the paired
system/iCloud identity state, not the raw NearbyAction value.

Bonjour comparisons also show that normal CompanionLink records are mostly
low-entropy routing and identity hints. Real peers on the LAN advertise
`rpFl=0x20000`, six-byte `rpHA`, six-byte `rpAD`, six-byte `rpHI`, `rpVr=715.2`,
and a Bluetooth address in `rpBA`. `fistel` resolves and correlates with BLE,
but changing `rpFl` and adding `rpMd` does not create the paired identity state
that Universal Control requires.

## Bonjour `rpFl` To Rapport Status Flags

`-[RPEndpoint updateWithBonjourDevice:]` reads the Bonjour TXT key `rpFl` and
translates it into endpoint `statusFlags`. The recovered bit construction is
implemented in `macolinux_dspext.rapport.status_flags_from_bonjour_rpfl`.

Observed direct mappings:

- status bit 2 is always set as the base flag.
- status bit 11 comes from `rpFl` bit 13.
- status bits 16 and 32 come from `rpFl` bit 14.
- status bit 18 comes from `rpFl` bit 16.
- status bit 31 comes from `rpFl` bit 19.
- status bit 34 comes from `rpFl` bit 23.
- status bit 35 comes from `rpFl` bit 31.
- status bit 42 comes from `rpFl` bit 32.
- status bit 24 is set when a device-info field contains either bit `0x08` or
  `0x10`.
- status bit 23 is added when the local Apple Pay support check succeeds.
- existing endpoint status is partially preserved with mask
  `0xfbf27eba7ffff7fb`.

For current probe values:

```text
rpFl=0x800        -> status bits [2]
rpFl=0x20000      -> status bits [2]
rpFl=0xffffffff   -> status bits [2, 11, 16, 18, 31, 32, 34, 35]
```

`RPRemoteDisplayDiscovery shouldReportDevice:` does not appear to report every
CompanionLink endpoint. The static gate checks status bit 19, or status bits
36/37 when matching discovery options are enabled. The direct `rpFl` mapping
above does not set bits 19, 36, or 37 by itself. That explains why simply
maxing out `rpFl` is not enough to make the Linux peer visible as a Universal
Control/RemoteDisplay candidate.

## Live Traffic Shape

During active pointer movement, Universal Control uses TCP streams over AWDL
IPv6 link-local addresses. A representative capture showed four Universal
Control-owned local ports connected to four remote ports:

- one low-volume stream exchanging larger control/sync records
- one high-volume stream carrying repeated pointer/event-sized records
- two additional streams that were mostly idle in that capture

The visible TCP payload framing is:

```text
TT LL LL LL BODY...
```

`TT` is the frame type byte. `LL LL LL` is a 24-bit big-endian body length.
Observed Universal Control event traffic uses `TT=0x08` (`E_OPACK`). Observed
TCP payload lengths match `4 + body_length`, for example:

- `08 00 02 44`: 580-byte body, 584-byte TCP payload
- `08 00 02 40`: 576-byte body, 580-byte TCP payload
- `08 00 00 8c`: 140-byte body, 144-byte TCP payload
- `08 00 00 5d`: 93-byte body, 97-byte TCP payload
- `08 00 00 33`: 51-byte body, 55-byte TCP payload

The body bytes appear high entropy in packet captures. That suggests the
Rapport/CompanionLink stream payload is encrypted or otherwise protected after
the 4-byte record header.

## Current Reverse-Engineering Blocker

The main blocker for a Linux client is not HID report semantics. The binary
already exposes enough names to identify the HID and event report layer. The
hard part is implementing the trusted Rapport/CompanionLink peer identity,
authentication, and encrypted stream setup that makes macOS accept the Linux
host as a Universal Control peer.

The next practical milestones are:

1. Reverse the unauthenticated Bonjour admission path and identify what state
   promotes a peer from `Bonjour unauth` to a connectable CompanionLink device.
2. Reproduce or satisfy the required pairing identity path. Live logs from real
   peers show `CUPairingSession` PairVerify M1-M4 over BLE/L2CAP PSM `0x0081`
   before an encrypted stream opens; CoreUtils requires a matching
   `CUPairedPeer.publicKey` of exactly 32 bytes during PairVerify.
3. Implement the Rapport `RPConnection` server side with unencrypted OPACK
   support for `PA_Req` and `PA_Rsp`.
4. Implement enough PairVerify/session pairing to derive the `main` stream PSK
   and the `ClientEncrypt-main`/`ServerEncrypt-main` ChaCha20-Poly1305 keys.
5. Decode or synthesize the OPACK-coded `P2PMessage` and `EventReport` payloads
   inside the protected stream.
6. Map decoded event reports onto Linux `uinput` keyboard, pointer, scroll, and
   vendor-key reports.

## Clean Pairing Bootstrap Constraints

A clean setup must allow an existing MacBook and the Linux peer to coexist with
the controller Mac. The Linux peer therefore should not clone or export the
MacBook's paired identity. It needs its own stable peer identity and its own
paired record on the controller Mac.

The relevant CoreUtils/Rapport object model is visible through Objective-C
runtime introspection:

- `CUPairingIdentity` contains `identifier`, `publicKey`, `secretKey`, and
  `altIRK`. It has `setRandomKeyPair`, `signData:error:`, and signature verify
  methods.
- `CUPairedPeer` contains `identifier`, `identifierStr`, `acl`, `altIRK`,
  `info`, `label`, `model`, `name`, and `publicKey`.
- `RPIdentity` can be initialized with `initWithPairedPeer:type:` and contains
  `edPKData`, `edSKData`, `deviceIRKData`, `btIRKData`, `btAddress`,
  `idsDeviceID`, account fields, and signing/verification methods.
- `CUPairingManager` exposes async read/write methods:
  `getPairingIdentityWithOptions:completion:`,
  `getPairedPeersWithOptions:completion:`,
  `findPairedPeer:options:completion:`,
  `savePairedPeer:options:completion:`, and
  `removePairedPeer:options:completion:`.
- `CUPairingDaemon` exposes the synchronous equivalents used behind the
  PairingManager XPC service, including `savePairedPeer:options:` and
  `copyPairedPeersWithOptions:error:`.

A normal unsigned command-line process can load these private frameworks and
inspect the classes, but `CUPairingManager` read calls return
`kMissingEntitlementErr`. Redacted keychain metadata queries also return no
accessible pairing items from the normal process context. This matches Apple
daemon entitlements:

- `rapportd` has `com.apple.PairingManager.Read`,
  `com.apple.PairingManager.Write`, `com.apple.CompanionLink`,
  `com.apple.rapport.Client`, private HomeKit pairing identity entitlements,
  and keychain access groups such as `com.apple.rapport`,
  `com.apple.pairing`, and `com.apple.sharing.appleidauthentication`.
- `sharingd` has the PairingManager read/write entitlements, private
  continuity/AppleID keychain groups, IDS continuity messaging entitlements,
  and `com.apple.rapport.RegenerateIdentity`.
- `UniversalControl` itself has display/HID/CompanionLink entitlements, but it
  does not appear to be the daemon that owns PairingManager writes.

Additional read-only probes on the current host:

- `SFAuthenticationManager` reports local support for authentication types 5
  (`MacApprovePhone`), 6 (`Registration`), and 7
  (`GuestModeUnlockPairing`). Candidate/eligible device enumeration for those
  types does not complete from an unsigned client, and `sharingd` logs that the
  client lacks the private authentication/unlock entitlement.
- `Rapport.RPPairingReceiverController` can be started by an ordinary process.
  `rapportd` logs `Start pairing receiver controller`, then stops it when the
  process exits. Setting `pairingValueUIVisible` to true does not produce a
  `RPPairingPINInfo` without an incoming pairing initiator.
- `RPRemoteDisplayServer startPairingServerWithCompletion:` can be called, but
  activation fails with `kMissingEntitlementErr` for the private
  `com.apple.RemoteDisplay` entitlement. No temporary Bonjour pairing service
  was observed from an unsigned client during bounded tests.
- Runtime protocol metadata shows the receiver XPC surface is intentionally
  small:

```text
Rapport.RPPairingDaemonXPCInterface:
  startPairingReceiverController:
  pairingValueUIVisibleUpdated:

Rapport.RPPairingReceiverControllerXPCClientInterface:
  pairingValueUpdated:
```

Rapport's string table exposes the likely network pairing bootstrap:

- request ID: `rppairing-bonjour-resolve`
- temporary service types: `_applicationServicePairing._tcp` and
  `_appSvcPrePair._tcp`
- response object: `RPPairingBonjourResolveResponse`, containing
  `serverPublicKey` and `bonjourServiceID`
- follow-on stream label: `RPPairingPairVerifyStream`

The current inference is that a Linux initiator must reproduce this
CompanionLink pairing request path, then complete a PairVerify-style exchange
against the temporary Bonjour service. Local macOS helper APIs are useful for
introspection, but they do not avoid the entitlement problem for creating a real
Universal Control trust record.

Live TCP bootstrap status:

- A raw TCP client can connect to the `_companion-link._tcp` listener, send
  `PA_Req` (`0x0a`) containing OPACK `{"_i":"1"}`, and receive `PA_Rsp`
  (`0x0b`) containing `{"_sv":"715.2"}`.
- A post-preauth `U_OPACK` or `P_OPACK` request for
  `rppairing-bonjour-resolve` is ignored while the connection is still in
  `SPairWait`; PairSetup/PairVerify must happen first.
- PairSetup/PairVerify payloads are OPACK dictionaries using the short key
  `_pd` for TLV8 data. Top-level OPACK data is rejected as a bad object type,
  and the long dictionary key `pairingInfo` is treated as missing pairing data.
- A `PairSetupStart` (`0x03`) request with `_pd = 00 01 00 06 01 01`,
  `_pwTy = 10`, and `_auTy = 8` reaches the QR/session-paired server path.
  `rapportd` logs `Requested password type: QRCode auth type: SessionPaired`
  and `Configuring for session pairing`.
- The corresponding PairSetup M2 is returned as `_pd` TLV8 data with
  `State=2`, a 16-byte salt, a 384-byte SRP public key, and an unknown
  `0x1b=08` TLV. If no M3 is sent, the server remains in `SPairWait` and later
  logs EOF. This gives a clean way to observe the SRP challenge without
  triggering wrong-code throttling.
- A parallel `RPPairingReceiverController` listener with
  `pairingValueUIVisible=true` saw no `RPPairingPINInfo` events during this
  raw CompanionLink PairSetup run. The receiver controller is therefore either
  not wired to this server path, or the raw listener does not install the
  server-side show handler that forwards pairing values to that XPC surface.
- Static disassembly of the PairSetup server path shows `RPConnection`
  installing `setShowPINHandlerEx:` and `setHidePINHandler:` before activating
  `CUPairingSession`. The next bootstrap target is to identify which
  CompanionLink or RemoteDisplay client path installs those handlers in a
  way an ordinary helper can trigger.
- A bounded `RPServer` helper probe can instantiate the framework object and
  set `showPasswordHandler`, `hidePasswordHandler`, `promptForPasswordHandler`,
  `passwordType=10`, and `serviceType=com.apple.universalcontrol`, but daemon
  activation fails with `kMissingEntitlementErr` for
  `com.apple.CompanionLink`. This means an unsigned helper cannot become the
  handler-owning CompanionLink server for Universal Control.
- Public `RPClient` device-mapping APIs are real and partly callable from an
  unsigned helper. Throwaway calls using
  `applicationService=com.apple.universalcontrol`, `deviceID=macolinux-device`,
  and endpoint/listener UUID `11111111-2222-3333-4444-555555555555` completed
  without error for `createEndpointToDeviceMapping:deviceID:endpointID:completion:`,
  `clientCreateDeviceMappingInternal:applicationService:deviceID:endpointID:completion:`,
  `createDeviceToListenerMapping:deviceID:completion:`, and
  `setAutoMapping:completion:`. The read-side
  `queryDeviceToListenerMapping:deviceID:completion:` failed with
  `kMissingEntitlementErr (Missing entitlement 'com.apple.rapport.Client' for
  createDeviceMapping)`. These APIs likely belong to the RPNW
  endpoint/listener routing layer and do not by themselves install an
  `RPIdentity` that PairVerify can resolve.
- Network.framework application-service discovery has an important scoping
  wrinkle. The public Swift `NWBrowser.Descriptor.applicationService`,
  `NWListener.Service(applicationService:)`, and
  `NWParameters.applicationService` APIs scope the request to the current
  process bundle/executable identity. The private C constructors
  `nw_browse_descriptor_create_application_service_with_bundle_id` and
  `nw_advertise_descriptor_create_application_service_with_bundle_id` let a
  helper set the bundle ID explicitly.
- An explicit-bundle `nw_listener` probe using
  `service=com.apple.universalcontrol` and
  `bundle=com.apple.universalcontrol` reaches `rapportd`'s RPNW listener path.
  Unified logs show an `RPNWAgentClient` upgraded to listener with
  `appSvc=com.apple.universalcontrol`, an advertise descriptor
  `com.apple.universalcontrol.com.apple.universalcontrol`, and creation of a
  listener framer. The server update then fails with `kAlreadyInUseErr
  (Service type already in use: 'com.apple.universalcontrol')`, which is
  expected on `endor` because the real Universal Control service is already
  registered. This is a stronger signal than the earlier raw `RPServer` probe:
  the Network.framework agent path can enter RPNW without the
  `com.apple.CompanionLink` entitlement.
- An explicit-bundle `nw_browser` probe for
  `service=com.apple.universalcontrol`, `bundle=com.apple.universalcontrol`
  starts and remains ready but has not yet returned endpoints on `endor`.
  Same-host loopback tests also do not report locally advertised application
  services, so lack of local browse results does not invalidate the listener
  path. The remaining pairing-specific Network.framework branch appears to use
  hidden Swift-only `NWListener.Service.PairingConfiguration`,
  `NWBrowser.Descriptor.PairingConfiguration`, `NWPairingType`, and
  `NWPairingValue` types. Those symbols are present in Network but omitted from
  the public Swift interface.
- The hidden Network pairing branch is now reproducible from an unsigned helper
  by setting private application-service `customService` bytes on the
  advertise descriptor. The private C setter shape is
  `nw_advertise_descriptor_set_custom_service(descriptor, bytes, length)`;
  passing a dispatch object is wrong and is interpreted as an oversized length.
  A JSON-encoded listener pairing configuration is accepted:

```json
{
  "pairingValue": { "pin": { "_0": "123456" } },
  "supportedPairingTypes": [{ "pin": {} }],
  "generatePairingValueImmediately": true,
  "_advertiseSensitiveInfo": true
}
```

  The repeatable probe command is:

```sh
target/research/continuity-inspect \
  nw-appsvc-listen-pairing \
  com.apple.universalcontrol com.apple.universalcontrol 123456 8
```

  `rapportd` recognizes the custom payload and enters the RPNW pairing server
  path:

```text
LISTEN: Setting pin on local endpoint for pairing listener.
LISTEN: Creating pairing server, advertise sensitive info: yes
LISTEN: Creating pairing listener framer
LISTEN: Successfully activated pairing server.
Starting advertising for pairing session with server identity: <private>
Starting advertising for pre-pairing session with server identity: <private>
```

  The normal Universal Control service still reports
  `kAlreadyInUseErr (Service type already in use: 'com.apple.universalcontrol')`
  on `endor`, but the pairing server and pre-pairing advertisements are created
  before the listener is cancelled. `fistel` did not see
  `_applicationServicePairing._tcp` or `_appSvcPrePair._tcp` with a standalone
  Python zeroconf WLAN browse during this window, so these advertisements are
  probably AWDL-scoped or internal to Network.framework/Rapport rather than
  ordinary LAN mDNS records.
- A JSON-encoded browser pairing configuration can be attached to a browse
  descriptor with `nw_browse_descriptor_set_custom_service`, and the descriptor
  logs as `custom:<len>`, but a plain `nw_browser` probe has not yet produced
  RPNW pairing-browse logs:

```json
{
  "pairingType": { "pin": {} },
  "preferredPairingTypes": [{ "pin": {} }]
}
```

  The current probe command is:

```sh
target/research/continuity-inspect \
  nw-appsvc-browse-pairing \
  com.apple.universalcontrol com.apple.universalcontrol 8
```

  Current inference: the listener-side hidden payload is enough to activate
  `RPNWNetworkAgentPairing`; the browse side may require an endpoint discovered
  through Network's application-service machinery, not just starting a local
  browser with a custom descriptor.
- A second Mac (`bespin`) can observe the temporary pairing services at the
  packet level on `awdl0` while `endor` runs `nw-appsvc-listen-pairing`. Normal
  `dns-sd -B` and `dns-sd -L` did not surface the records to user space on
  `bespin`, but `tcpdump -i awdl0 udp port 5353` captured the announcements.
  The AWDL mDNS shape is:

```text
endor._applicationServicePairing._tcp.local. TXT
  at=<12 hex chars>
  sid=<UUID>
  sn=com.apple.universalcontrol

endor._appSvcPrePair._tcp.local. TXT
  sn=com.apple.universalcontrol
  at=<same 12 hex chars>
  sid=<same UUID>
  dnm=endor

endor._applicationServicePairing._tcp.local. SRV
  <uuid-host>.local.:<pairing-port>

endor._appSvcPrePair._tcp.local. SRV
  <uuid-host>.local.:<prepair-port>

<uuid-host>.local. AAAA
  fe80::<endor-awdl-address>
```

  One concrete capture from `bespin`:

```text
TXT at=582dbb113b78
TXT sid=162B00AD-B278-4D39-B1D0-ED0E69A56D01
TXT sn=com.apple.universalcontrol
SRV endor._appSvcPrePair._tcp.local. -> 3905db08-...local.:59300
SRV endor._applicationServicePairing._tcp.local. -> 3905db08-...local.:59301
AAAA 3905db08-...local. -> fe80::405d:5dff:fe32:ba47
```

  A raw BSD socket connect from `bespin` to
  `fe80::405d:5dff:fe32:ba47%awdl0:59300` reached `endor`: `endor` captured
  the SYN and sent a SYN-ACK. `bespin` immediately sent a TCP RST, and later
  retries received RSTs from `endor`. This means the temporary pairing listener
  is reachable over AWDL at the TCP layer, but a plain socket probe is not a
  valid client. The next probe should connect through Network.framework
  (`NWConnection`) or reproduce the exact RPNW client framer setup before
  attempting the RPPairing stream.
- `NWConnection` to the temporary services by Bonjour service endpoint works
  from `bespin`, even though `dns-sd` does not surface the records:

```sh
/tmp/macolinux-dspext-research/application-service-probe \
  connect-service endor _appSvcPrePair._tcp local 10 receive-only

/tmp/macolinux-dspext-research/application-service-probe \
  connect-service endor _applicationServicePairing._tcp local 10 receive-only
```

  Both connections reached `ready`. In receive-only mode the server did not
  send any bytes before the client cancelled. `rapportd` accepted inbound
  connections on `awdl0` for both temporary services, one plain TCP and one TLS:

```text
Handling inbound connection ... local fe80::405d:5dff:fe32:ba47%awdl0.59313
Handling inbound connection ... local fe80::405d:5dff:fe32:ba47%awdl0.59312 tls
```

  When the client closed, Network.framework logged:

```text
Failed to retrieve actorID for incoming connection: <private>
```

  Using `NWParameters.applicationService` instead of plain TCP parameters did
  not change the result. Current inference: resolving and opening the AWDL
  socket is not enough. The valid peer path needs Network.framework's Swift
  distributed actor layer to associate an `NWActorID` with the connection.
- `RPNWFramer` static disassembly gives the first clear wire header for the
  RPNW framer. `+[RPNWFramer startConnection:token:]` sends control type `1`
  and logs `RPNW_CONTROL_HANDSHAKE`. The control frame is 16 bytes:

```text
01 00 00 00 13 13 13 13 00 00 00 00 00 00 00 00
```

  `+[RPNWFramer writeDataOnFramer:data:]` writes a 16-byte data header followed
  by the body. The data header is native little-endian:

```text
00 00 00 00 00 00 00 00 <uint64 body_length_le>
```

  Sending only the RPNW control handshake from `bespin`:

```sh
/tmp/macolinux-dspext-research/application-service-probe \
  connect-service endor _appSvcPrePair._tcp local 10 \
  hex:01000000131313130000000000000000 tcp
```

  produced a TLS alert on one temporary endpoint:

```text
15 03 01 00 02 02 46
```

  The other temporary endpoint closed without returning bytes. In both cases
  `rapportd` still logged `Failed to retrieve actorID for incoming connection`.
  This means hand-writing the first RPNW frame is insufficient; the missing
  piece is still the Network distributed actor association, not merely the
  RPNW magic value.
- Running the private pairing browser on `bespin` also starts cleanly but does
  not discover or connect to `endor`'s temporary pairing services:

```sh
/tmp/macolinux-dspext-research/continuity-inspect \
  nw-appsvc-browse-pairing \
  com.apple.universalcontrol com.apple.universalcontrol 20
```

  The descriptor includes the expected hidden browser pairing configuration:

```text
<nw_browse_descriptor application_service com.apple.universalcontrol
 bundle_id=com.apple.universalcontrol device_types=ffffffff
 device_scope=ffffffff custom:63>
```

  It reaches `browser state=ready` but returns no endpoints. Current inference:
  the hidden browser configuration is necessary but not sufficient; Apple's
  pairing client path likely creates or resolves an `NWActorID` through
  `NWActorSystem` and then opens the service connection with associated actor
  metadata.
- Network.framework contains a hidden Swift distributed actor transport used
  by the temporary pairing listeners:

```text
Network.NWActorSystem
Network.NWActorID
Network.NWActorDiscoveryMechanism
Network.NWActorSystemProtobuf_ActorID
Network.NWActorSystemProtobuf_RemoteCall
Network.NWActorSystemProtobuf_Reply
com.apple.network.MessageActorSystem
ActorSystemWireProtocol
NWActorSystemType
NWActorSystemOptions
```

  Runtime probing shows `NWActorSystem` stores
  `serverRolesByActorTypeName`, `discoveryMechanismByActorID`,
  `connectionsByActorID`, and `invalidationHandlersByActorID`. Its nested
  `ActorConnection` stores the underlying `nwConnection`, a
  `remoteCallHandler`, an `actorResolutionHandler`, `_associatedActorIDs`, and
  a `resolvedActorIDContinuation`.

  Static disassembly of the `com.apple.network.MessageActorSystem` framer shows
  the outbound actor-message header is 12 bytes:

```text
<uint32 wire_type_le> <uint32 options_le> <uint32 body_length_le> BODY...
```

  The public metadata values are logical actor message types. Apple's framer
  maps logical types `1..4` to raw wire types `5..8` on output, and maps raw
  wire types `5..8` back to logical types `1..4` on input. Values outside that
  range are treated as type `0` on input. This corrected an earlier false lead:
  sending raw values `5..8` as metadata to a custom pass-through framer does
  not exercise the real actor-message parser.

  A custom C `nw_framer` probe that emits the 12-byte header can now connect to
  the temporary pairing services. Plain TCP connections to
  `_applicationServicePairing._tcp` reach `Received connection` and remain open
  without the previous immediate `Failed to retrieve actorID` log. The TLS side
  is more diagnostic: connecting to `_appSvcPrePair._tcp` with
  `nw_parameters_create_secure_tcp`, a permissive verify block, and the custom
  actor framer completes TLS and logs:

```text
Output protocol connected (ActorSystemWireProtocol)
Handling message of type cancelRemoteCall length: 11 isCompressed: false
Failed to decode CancelRemoteCall: ...
```

  The body in that test was the minimal guessed protobuf
  `0a 09 6d 61 63 6f 6c 69 6e 75 78`, i.e. field 1 string `macolinux`, sent
  with logical actor message type `1`. This confirms the actor frame header and
  TLS transport are correct, but logical type `1` is `cancelRemoteCall`, not
  `ActorID`.
- A direct-host TLS sweep from `bespin` to the current AWDL listener ports
  confirms the actor logical type names:

```text
logical 1 -> cancelRemoteCall
logical 2 -> terminateProcess
logical 3 -> remoteCallProtobuf
logical 4 -> ReplyEnvelope
```

  The probe reaches the same parser when addressed as
  `fe80::405d:5dff:fe32:ba47%awdl0:<temporary-port>`, so stale Bonjour
  resolution can be avoided during tight experiments. The repeatable pattern is:

```sh
target/research/continuity-inspect \
  nw-appsvc-listen-pairing \
  com.apple.universalcontrol com.apple.universalcontrol 123456 45

ssh bespin '/tmp/macolinux-network-actor-framer-probe \
  connect-host "fe80::405d:5dff:fe32:ba47%awdl0" PORT 5 \
  3 0 "remote-call:00000000-0000-0000-0000-000000000001|macolinux|00000000-0000-0000-0000-000000000002|probe|0" \
  tls stack actor'
```

- `Network.framework` exposes the hidden actor runtime classes through runtime
  metadata even though the public Swift interface hides them. `NSClassFromString`
  can see `Network.NWActorSystem` and `Network.WireProtocol`; `dyld_info
  -exports` also exposes private Swift ABI symbols such as
  `NWActorSystem.remoteCall`, `NWActorSystem.resolve`, `NWActorSystem.publish`,
  `NWActorSystem.assignID`, and `NWActorID.encode(to:)`. However,
  `@_spi(Private) import Network` and related SPI imports still compile against
  the public `.swiftinterface`, so normal Swift source cannot name these types.
- Static string and reflection data give the protobuf/Codable field names:

```text
NWActorSystemProtobuf.ActorID:
  actorName
  identifier

NWActorSystemProtobuf.RemoteCall:
  callID
  recipient
  invocationTarget
  genericSubs
  arguments
  options

RemoteCallEnvelope:
  callID: UUID
  recipient: NWActorID
  invocationTarget: String
  genericSubs: [String]
  args: [Data]
  options: RemoteCallEnvelope.Options

NWActorID:
  typeName: String
  identifier: UUID

NWActorSystemProtobuf.Reply:
  value
  error
  metrics
  remoteExecutionTime

ReplyEnvelope:
  callID
  value
  error
  metrics
  archivedData
  mangledName
  encodedValue
```

  The important mismatches are that the Swift `RemoteCallEnvelope` uses
  `args`, while the protobuf message uses `arguments`, and that
  `NWActorID.identifier` is a UUID while `NWActorSystemProtobuf.ActorID` stores
  a string `identifier`.
- JSON and binary plist bodies using the corrected Swift `RemoteCallEnvelope`
  shape still fail at `RemoteCallEnvelope` decode. A raw protobuf
  `NWActorSystemProtobuf.RemoteCall` body succeeds when the field order matches
  the generated protobuf schema:

```text
RemoteCall protobuf:
  field 1: callID string
  field 2: recipient ActorID
  field 3: invocationTarget string
  field 4: repeated genericSubs string
  field 5: repeated arguments bytes
  field 6: options varint

ActorID protobuf:
  field 1: actorName string
  field 2: identifier string
```

  A minimal successful probe body was:

```text
0a2430303030303030302d303030302d303030302d303030302d303030303030303030303031
12410a096d61636f6c696e7578122430303030303030302d303030302d303030302d30303030
2d3030303030303030303030321a0570726f62653000
```

  Sent as logical actor type `3`, this no longer logs
  `Failed to decode RemoteCallEnvelope`. `rapportd` logs:

```text
Handling message of type remoteCallProtobuf length: 98 isCompressed: false
Performing remote call for call ID <private>
Failed to resolve actor with ID <private> for callID <private>
```

  The custom probe receives the server's actor reply as logical type `4`,
  options `15`, with a 40-byte body:

```text
62 76 78 6e 28 00 00 00 18 00 00 00 c8 01 0a 24
30 f3 68 05 2d fb 20 01 e3 31 1a 00 06 00 00 00
00 00 00 00 62 76 78 24
```

  The `62 76 78 6e` / `62 76 78 24` markers likely belong to Apple's private
  distributed actor value/reply codec. The request side is now past envelope
  decoding.

  A later sweep against a fresh temporary pairing listener resolved the actor
  name/identifier shape. The correct `ActorID.actorName` for this listener is:

```text
RPPairingDistributedActor
```

  The `ActorID.identifier` is the temporary service UUID printed by
  `nw-appsvc-listen-pairing`, for example:

```text
listener advertised add endpoint=app_svc: com.apple.universalcontrol,
  service_id: 676046C7-DF1F-4D4E-B706-5F895C5D73DF
```

  With actor name `RPPairingDistributedActor` and that UUID, `rapportd` no
  longer logs `Failed to resolve actor`; it reaches:

```text
Handling message of type remoteCallProtobuf length: 123 isCompressed: false
Performing remote call for call ID <private>
Failed to execute distributed target: <private> for callID <private>
```

  Wrong actor names still produce `Failed to resolve actor`, so the actor
  identity is now confirmed. The current Network.framework pairing blocker is
  the distributed-call target/argument encoding.
- Swift distributed actors use the mangled distributed thunk symbol as the
  `Distributed.RemoteCallTarget` identifier, not the human-readable method
  spelling. A local `swiftc -emit-silgen` control for:

```swift
distributed actor Demo {
    distributed func ping(data: Data) async throws -> Data { data }
    distributed func done() async throws {}
}
```

  shows generated `RemoteCallTarget` string literals:

```text
$s4main4DemoC4ping4data10Foundation4DataVAH_tYaKFTE
$s4main4DemoC4doneyyYaKFTE
```

  Therefore the relevant `rapportd` target strings are the exported distributed
  thunk symbols, for example:

```text
$s8rapportd25RPPairingDistributedActorC14resolveBonjour15clientPublicKeyAA0bF15ResolveResponseC10Foundation4DataV_tYaKFTE
$s8rapportd25RPPairingDistributedActorC23resolveBonjourCompletedyyYaKFTE
```

  `xcrun swift-demangle` maps the pairing thunks to:

```text
rapportd.RPPairingDistributedActor.resolveBonjour(clientPublicKey: Foundation.Data) async throws -> rapportd.RPPairingBonjourResolveResponse
rapportd.RPPairingDistributedActor.resolveBonjourCompleted() async throws -> ()
rapportd.RPPairingDistributedActor.startPairVerify(createEncryptionStream: Swift.Bool) async throws -> ()
rapportd.RPPairingDistributedActor.processPairVerifyData(Foundation.Data) async throws -> Foundation.Data?
```

  Live testing of the mangled target names was blocked by the current AWDL
  route from `bespin` to `endor`: `bespin` saw `endor` in
  `_companion-link._tcp`, but `ping6 -I awdl0 fe80::405d:5dff:fe32:ba47%awdl0`
  returned `No route to host`, and direct TLS probes stayed in
  `connection state=waiting`. The previous direct-host probes are still valid;
  a fresh live sweep should be repeated once Universal Control/AWDL routing is
  active again.
- Re-running with a working AWDL route confirmed the argument encoding used by
  `NWActorSystemInvocationEncoder`: each protobuf field-5 `arguments` entry is
  the Swift argument's `JSONEncoder` output. Concrete examples:

```text
Foundation.Data([0x00, ...]) -> JSON string containing base64 bytes:
  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

Swift.Bool -> true / false

Foundation.UUID -> JSON string:
  "50860139-FA7E-48B7-88C9-163682BBCD50"
```

  Negative controls are useful:

```text
raw 32-byte field-5 argument      -> JSON decoder error around byte 0x00
binary plist Data as field 5      -> JSON decoder error around byte 'b'
unquoted base64 text as field 5   -> JSON decoder error around byte 'A'
quoted base64 text as field 5     -> success
```

  A successful `resolveBonjour(clientPublicKey:)` call uses:

```text
actorName:         RPPairingDistributedActor
actorIdentifier:   <listener service_id UUID>
invocationTarget:  $s8rapportd25RPPairingDistributedActorC14resolveBonjour15clientPublicKeyAA0bF15ResolveResponseC10Foundation4DataV_tYaKFTE
argument[0]:       JSON-encoded Foundation.Data, e.g. "AAECAw..."
```

  The reply body is a `ReplyEnvelope` in the private `bvxn` container. For
  `resolveBonjour`, the value field contains JSON:

```json
{"bonjourServiceID":"A721553C-1084-43D6-886A-E5E67745792F","serverPublicKey":""}
```

  `serverPublicKey` remained empty for empty, low-order-looking, and random
  32-byte `clientPublicKey` values, so this method currently appears to be
  giving the follow-up Bonjour service identifier rather than an active key
  exchange.
- `startPairVerify(createEncryptionStream:)` accepts a JSON `Bool` argument and
  returns a void success envelope for both `false` and `true`:

```text
$s8rapportd25RPPairingDistributedActorC15startPairVerify22createEncryptionStreamySb_tYaKFTE
argument[0]: false / true
reply:      43-byte void success envelope
```

  `startPairVerifyWithSessionID(createEncryptionStream:)` also accepts a JSON
  `Bool` and returns a JSON-encoded UUID string:

```text
$s8rapportd25RPPairingDistributedActorC28startPairVerifyWithSessionID22createEncryptionStream10Foundation4UUIDVSb_tYaKFTE
argument[0]: false
reply value: "6E68147A-E0AA-44DE-8870-7E7728ECF2AC"

argument[0]: true
reply value: "50860139-FA7E-48B7-88C9-163682BBCD50"
```

  Calling
  `processPairVerifyDataWithSessionID(_:sessionID:)` on a later connection with
  JSON-encoded PairVerify M1 `Data` and a JSON-encoded returned UUID decodes the
  arguments, but returns an `RPError`:

```text
Internal error: PairVerify session <UUID prefix> not found
[RPPairingDistributedActor.swift:324]
```

  This points to PairVerify session state being connection-scoped or otherwise
  tied to the actor runtime connection that created it.
- The `network-actor-framer-probe` now has a research sequence mode for that
  connection-scoped path:

```text
pairverify-sequence:CALL_ID_START|CALL_ID_PROCESS|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|M1_HEX
```

  It sends `startPairVerifyWithSessionID(createEncryptionStream:)`, extracts the
  JSON UUID from the first reply, and then sends
  `processPairVerifyDataWithSessionID(_:sessionID:)` on the same `NWConnection`
  with:

```text
argument[0] = JSON-encoded PairVerify M1 Data
argument[1] = JSON-encoded UUID string returned by the first call
```

  This successfully reaches CoreUtils PairVerify and returns M2 over the actor
  reply path. Example run:

```text
pairverify-sequence: sessionID=F493ADB1-DCFA-436C-9208-82831CA59A08 processPayloadBytes=332
pairverify-sequence process send complete bytes=332
```

  `rapportd` logs for the second actor frame:

```text
Handling message of type remoteCallProtobuf length: 332 isCompressed: false
Performing remote call for call ID <private>
RPPairingDistributedActor-F493ADB1: PairStart, PairVerifyServer, 0x400004 < System HomeKit >
RPPairingDistributedActor-F493ADB1: PairVerify server M1 -- start request
RPPairingDistributedActor-F493ADB1: PairVerify server M2 -- start response
```

  The returned M2 `Data` was JSON-encoded as base64 in the reply. Decoded TLV:

```text
05 52 <82-byte encrypted data>
06 01 02
03 20 de ad eb 03 5b af f6 57 f2 d3 64 f3 32 04 e2 41
      52 ec eb b6 a4 1b 46 30 44 c4 d8 ac b5 93 b5 34
```

  This matches the direct CompanionLink PairVerify M2 shape: encrypted data,
  `State=2`, and server public key.

- The actor probe now has a three-call helper mode:

```text
pairverify-m3-sequence:CALL_ID_START|CALL_ID_M1|CALL_ID_M3|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|HELPER_PATH|IDENTITY_PATH
```

  `HELPER_PATH` points at the Rust `pairverify_actor_helper` binary. The probe
  invokes `helper m1`, sends `startPairVerifyWithSessionID`, extracts the
  returned JSON UUID, sends M1, extracts the JSON base64 M2 reply, invokes
  `helper m3 --secret-key-hex ... --m2-hex ... --identity ...`, and sends M3
  as another JSON-encoded `Data` argument on the same `NWConnection`.

  Example live run from `bespin` to `endor`:

```text
pairverify-m3-sequence: sessionID=7075B63F-C0A3-4527-872E-52436A40E1A0 m1PayloadBytes=332
pairverify-m3-sequence M1 send complete bytes=332
pairverify-m3-sequence: m2Bytes=121 m3PayloadBytes=405
pairverify-m3-sequence M3 send complete bytes=405
recv ... "BwEEBgED"
```

  The final base64 reply decodes to:

```text
07 01 04
06 01 03
```

  That is `Error=4` at `State=3`, matching the direct CompanionLink result.
  Server logs confirm the important boundary:

```text
RPPairingDistributedActor-7075B63F: PairVerify server M3 -- finish request
Resolve identity for signature failed: 0x4022 < SameAccountDevices FriendDevices >
Server PairVerify failed ... kNotFoundErr
PairVerify server M3 verify signature failed: -6727/0xFFFFE5B9 kNotFoundErr
```

  So the actor transport, JSON argument encoding, X25519/HKDF/ChaCha envelope,
  and M3 signature construction are correct enough for `rapportd` to decrypt M3
  and attempt identity resolution. The remaining blocker is registering or
  otherwise presenting the Linux peer identity so `rapportd` can resolve the
  M3 identifier as an allowed `RPIdentity`.

- `PairVerifyStart` (`0x05`) with only `_pd = 03 20 <32-byte X25519 public
  key>` reaches CoreUtils `PairVerifyServer`, but returns error 4 at state 0.
  The live TCP M1 shape that gets a real M2 is
  `06 01 01 03 20 <32-byte X25519 public key> 19 01 01`: state 1, public key,
  and app flags 1.
- The Rust probe now generates the PairVerify M1 X25519 keypair itself. For a
  normal M2 it derives the HKDF-SHA512 `Pair-Verify-Encrypt` key, decrypts
  `PV-Msg02`, optionally verifies the peer Ed25519 signature, and can build
  encrypted M3 (`PV-Msg03`) from a supplied Linux identity.
- `macolinux-ucd identity create` now persists a versioned Linux Ed25519
  identity JSON file. `pairing resolve --pairverify-client --identity PATH`
  consumes that file for M3 signing. The live `endor` listener now accepts M1,
  returns a decryptable M2, and receives our encrypted M3, then replies with
  `_pd = 07 01 04 06 01 03` (`Error=4`, `State=3`).
- A unified-log capture of that M3 failure shows the concrete server-side
  reason:
  `Resolve identity for signature failed` for
  `< SameAccountDevices FamilyDevices FriendDevices SharedTVUserDevices SessionPairedDevices >`,
  followed by `PairVerifyVerify failed: kNotFoundErr (Resolved identity not
  found)` and `PairVerify server M3 verify signature failed`. This means the
  remaining blocker is not the M3 encryption envelope; `rapportd` cannot resolve
  the Linux peer identifier as an allowed `RPIdentity`.
- Direct CoreUtils C API probing found `PairingSessionCreate`,
  `PairingSessionSavePeer`, and `PairingSessionFindPeer`. Calling
  `PairingSessionSavePeer` writes a peer that the same helper process can find,
  but `rapportd` still fails `RPIdentityDaemon` resolution. Testing
  `PairingSessionCreate` types 1 through 12 did not change the M3 result.
- Runtime probing maps `RPIdentity` type 13 to `SessionPaired`; type 15 is
  `AdHocPairedDevice`. `RPClient addOrUpdateIdentity:source:completion:` is the
  obvious daemon-facing API for installing this identity, but normal, root, and
  ad-hoc-signed helpers fail with missing or restricted
  `com.apple.rapport.Client` entitlement.
- The no-source `RPClient addOrUpdateIdentity:completion:` variant fails with
  the same `com.apple.rapport.Client` entitlement check. `RPClient
  diagnosticCommand:params:completion:` is also entitlement-gated, so
  diagnostic commands are not a shortcut for identity installation.
- The temporary Network.framework pairing listener has two advertised Bonjour
  legs on `awdl0`:

```text
endor._appSvcPrePair._tcp.local.              SRV <uuid-host>.local.:<pre-port>
endor._applicationServicePairing._tcp.local.  SRV <uuid-host>.local.:<pair-port>
```

  The `_appSvcPrePair` leg is the actor leg that accepts
  `RPPairingDistributedActor` calls when connected from `bespin` as TLS with
  actor type `3`. The `_applicationServicePairing` leg rejects a raw Rust
  PairSetup TCP client as a distributed actor connection with no actor ID, so
  raw Rapport PairSetup frames are the wrong protocol for this listener.
- A new `network-actor-framer-probe` `remote-call-sequence:` mode can send two
  distributed actor calls on one connection. Running
  `resolveBonjour(clientPublicKey:)` followed by `resolveBonjourCompleted()` on
  the same `_appSvcPrePair` connection succeeds:

```text
recv ... {"bonjourServiceID":"9A11D54F-AC1E-4242-A578-DC55B609C730","serverPublicKey":""}
remote-call-sequence second send complete ...
recv ... void success envelope
```

  `rapportd` logs the server-side state transition:

```text
RESOLVE: Bonjour resolve - calling browseResponse ... resolvedEndpoints:
  [0 - 9A11D54F-AC1E-4242-A578-DC55B609C730._asquic._udp.local.]
resolveBonjourCompleted
```

  It also logs why `serverPublicKey` is empty in our probe:

```text
Failed to find QUIC protocol options from parameters=tcp
RESOLVE: Failed to extract server public key
```

  This strongly suggests the clean temporary-pairing path is not raw TCP
  PairSetup. The client must create a Network.framework QUIC/asquic pairing
  connection so `rapportd` can extract the QUIC public key and bind the
  follow-up `_asquic._udp` endpoint. Reproducing that QUIC parameter shape is
  the next blocker before identity creation can be expected.
- The distributed actor `callID` must be UUID-shaped. Short test IDs such as
  `c1` make `rapportd` log `Failed to decode RemoteCallEnvelope` even though
  the actor wire type and protobuf field layout are otherwise correct. Reusing
  UUID strings for each call restores the working `resolveBonjour` path.
- The SDK exports public QUIC constructors and private application-service QUIC
  constructors:

```text
nw_parameters_create_quic(...)
nw_quic_copy_sec_protocol_options(...)
nw_quic_add_tls_application_protocol(...)
nw_parameters_create_application_service_quic()
nw_parameters_create_application_service_quic_using_identity(...)
NWParameters.applicationServiceQUIC(identity:)
```

  `network-actor-framer-probe` now has `quic[:ALPN,...]` and `appsvc-quic`
  transport modes, plus a `connect-appsvc` mode using the private
  `nw_endpoint_create_application_service` constructor. These are research-only
  paths; they keep the existing actor framer unchanged.
- A live run from `bespin` to a fresh listener on `endor` returned:

```json
{"serverPublicKey":"","bonjourServiceID":"58E0FD33-7351-45B7-BF09-890D79E3B6A1"}
```

  The listener printed:

```text
listener advertised add endpoint=58E0FD33-7351-45B7-BF09-890D79E3B6A1._asquic._udp.local.@utun0
listener advertised add endpoint=58E0FD33-7351-45B7-BF09-890D79E3B6A1._asquic._udp.local.
```

  `dns-sd -B _asquic._udp local.` on `bespin` did see the add/remove event for
  that instance while the listener was alive. However, direct mDNS queries for
  `58E0FD33-7351-45B7-BF09-890D79E3B6A1._asquic._udp.local.` received no
  SRV/TXT response from `endor`, and both generic QUIC and application-service
  QUIC probes stayed in `preparing`. Direct application-service endpoint probes
  with the full `_asquic._udp.local.` name and with only the UUID also stayed in
  `preparing`. That means the `_asquic` value in the actor reply should be
  treated as a Network/Rapport browse-response endpoint, not as ordinary
  Bonjour data that another process can resolve via mDNS.
- `network-actor-framer-probe` can now browse Bonjour services and then connect
  the exact `nw_browse_result_copy_endpoint(...)` object in-process. It can also
  require a specific interface with a final `INTERFACE|any` argument, using the
  private exported `nw_interface_create_with_name` plus the public
  `nw_parameters_require_interface`. A live run against a fresh
  `resolveBonjour` result showed:

```text
required interface=awdl0
browse-service ... interface=awdl0
browser result endpoint=141467A1-CE86-436F-BD0A-AF70203F2A72._asquic._udp.local.
browser result interface=awdl0
browser result endpoint=606087D2-4D47-447B-B0B0-3DEBE4DED128._asquic._udp.local.
browser result interface=awdl0
browse-service timeout
```

  The returned temporary endpoint from `resolveBonjour` did not appear when the
  browser was pinned to `awdl0`. Pinning the same browse to `en0` did find it,
  but the follow-up application-service QUIC connection still stayed in
  `preparing`:

```text
required interface=en0
browser result endpoint=48B693DC-A736-46EE-AE7B-15690023360C._asquic._udp.local.
browser result interface=en0
browse-service endpoint=48B693DC-A736-46EE-AE7B-15690023360C._asquic._udp.local. ... interface=en0
connection state=preparing
browse-service timeout
```

  Existing Apple Universal Control `_asquic` instances are visible on `awdl0`;
  the temporary endpoint produced by our TCP/TLS actor bootstrap is only visible
  on infrastructure Wi-Fi. This reinforces the earlier log finding that the
  missing piece is the real application-service QUIC/asquic client parameter
  shape, not a simple required-interface setting.
- The hidden Network Swift interface is not shipped as a private
  `.swiftinterface`, but the SDK export table does expose the relevant symbols:

```text
NWBrowser.Descriptor.init(name:pairingConfiguration:)
NWBrowser.Descriptor.customApplicationService(...)
NWBrowser.Descriptor.applicationServiceWithOptions(...)
NWBrowser.Descriptor.PairingConfiguration.init(pairingType:)
NWBrowser.Descriptor.PairingConfiguration.init(preferredPairingTypes:)
NWPairingType.pin
NWBrowser.Descriptor.Options.scope/deviceTypes/customService/applicationServiceEndpointsOnly
NWParameters.applicationServiceQUIC(identity:)
```

  The same Network binary also exports C setters that map directly to descriptor
  fields:

```text
nw_browse_descriptor_set_custom_service
nw_browse_descriptor_set_browse_scope
nw_browse_descriptor_set_device_types
nw_browse_descriptor_set_discover_application_service_endpoints_only
nw_browse_descriptor_set_invitation_scope
```

  `network-actor-framer-probe browse-appsvc` now exposes browse scope and device
  type masks, plus browser custom-service variants:

```text
... [endpoints-only|all] [INTERFACE|any]
    [BROWSE_SCOPE_HEX|default] [DEVICE_TYPES_HEX|default]
    [pin|both|pairing-only|preferred-only|empty|none|json:...|hex:...|b64:...]
```

  A live sweep from `bespin` against a fresh temporary listener on `endor`
  tested default scope, explicit `0xffffffff`, and bit masks `0x1`, `0x2`,
  `0x40`, and `0x100`, all with `device_types=0xffffffff`. All browsers
  reached `browser state=ready` and timed out with no results. A second sweep
  tested custom-service modes `pairing-only`, `preferred-only`, `both`, `empty`,
  and `none`; all also timed out. So the app-service browse failure is not
  explained by one of these visible C descriptor fields or by the obvious JSON
  variants for `PairingConfiguration`.
- Next QUIC/asquic work should focus on reproducing or capturing the
  `RPNWNetworkAgent` browse-result path that hands the endpoint object to the
  client. Useful directions are:
  `nw_browse_descriptor_set_discover_application_service_endpoints_only`,
  application-service browsing with QUIC parameters, and correlating
  `RPNWAgentClient` browse responses with the endpoint object returned by
  `resolveBonjour`.
- A bounded `RPCompanionLinkClient` browse probe confirms that the production
  CompanionLink client path is also entitlement-gated, not merely hidden API.
  From both the normal user account and `root@localhost`, activation with
  `serviceType=com.apple.universalcontrol` fails immediately with
  `kMissingEntitlementErr (Missing entitlement 'com.apple.CompanionLink')`.
  This removes the easy option of using Apple's client object as a local
  discovery oracle. The product implementation must either reproduce the
  Rapport/CompanionLink stream protocol itself, or trigger a supported pairing
  flow through an already-entitled Apple daemon.
- The actor probe now prints browse-result and endpoint TXT records through
  `nw_browse_result_copy_txt_record_object` and
  `nw_endpoint_copy_txt_record`, and prints
  `eopack_decrypt_psk_hex=<raw PairVerify shared secret>` after its M3 helper
  run. A live `endor` -> `bespin` check on macOS 26.3.1 found only
  `bespin._appSvcPrePair._tcp.local.` on `awdl0`; both TXT accessors returned
  `nil`, packet captures on `endor` and `bespin` saw only `endor`'s outgoing
  PTR queries, and using actor identifier `bespin` failed in `rapportd` with
  `Failed to decode RemoteCallEnvelope`. That is consistent with the actor
  identifier still needing the hidden UUID-shaped `sid`, not the service
  instance name.
- A controlled fresh listener run using `nw-appsvc-listen-pairing` on `endor`
  again confirms the full actor PairVerify path when the listener's printed
  `service_id` is used as `ActorID.identifier`:

```text
listener advertised add endpoint=app_svc: com.apple.universalcontrol,
  service_id: 3F2B43E7-4AD8-4B5A-B588-885A4AE8D024
```

  Running the actor client from `bespin`:

```sh
ssh bespin 'PAYLOAD="pairverify-m3-sequence:<uuid1>|<uuid2>|<uuid3>|RPPairingDistributedActor|3F2B43E7-4AD8-4B5A-B588-885A4AE8D024|true|/tmp/pairverify_actor_helper|/tmp/fistel.identity.json"; \
  /tmp/macolinux-network-actor-framer-probe \
  connect-service endor _appSvcPrePair._tcp local. 22 \
  3 0 "$PAYLOAD" tls stack actor awdl0'
```

  produced a session ID, decrypted M2, built and sent encrypted M3, and printed:

```text
pairverify-m3-sequence: eopack_decrypt_psk_hex=212255e52658cc4b3e62a680b70a1f5fdfbd12d34af6e97e71bce8ac249a2c10
pairverify-m3-sequence: pairverify_encryption_key_hex=dd2ad40a87d7b41521b3a84618002279d7f24727ad4120a07e2a7d0147ff5856
recv ... "BwEEBgED"
```

  `BwEEBgED` decodes to PairVerify TLV `Error=4, State=3`. `rapportd` logged:

```text
Starting PairVerify with session tracking (createEncryptionStream <private>)
PairVerify server M1 -- start request
PairVerify server M2 -- start response
PairVerify server M3 -- finish request
Resolve identity for signature failed: 0x4022 < SameAccountDevices FriendDevices >
PairVerify server M3 verify signature failed: kNotFoundErr
```

  Therefore the temporary listener, actor identity, Swift distributed call
  envelope, PairVerify crypto, and M3 signature construction are correct. The
  blocker before post-PairVerify `E_OPACK` remains macOS trust/identity
  resolution for the Linux peer identifier.
- The same controlled temporary listener also reaches the PIN/PAKE branch via
  the distributed actor method:

```text
rapportd.RPPairingDistributedActor.exchangePAKEIdentities(
  clientIdentity: String,
  deviceName: String,
  givenName: String?,
  familyName: String?
) async throws -> String
```

  A working call from `bespin` uses the same actor name and listener
  `service_id` UUID:

```sh
TARGET='$s8rapportd25RPPairingDistributedActorC22exchangePAKEIdentities14clientIdentity10deviceName05givenJ006familyJ0S2S_S2SSgAItYaKFTE'
PAYLOAD="remote-call:<uuid>|RPPairingDistributedActor|<service_id>|$TARGET|0|arg-json-string:fistel|arg-json-string:fistel|arg-json-string:fbettag|arg-json-string:linux"
/tmp/macolinux-network-actor-framer-probe \
  connect-service endor _appSvcPrePair._tcp local. 8 \
  3 0 "$PAYLOAD" tls stack actor awdl0
```

  The actor reply is a JSON string UUID, and `rapportd` logs a generated PIN
  dictionary such as:

```text
New pairing info generated
LISTEN: Updated PIN info: {"304296":["fbettag","linux","fistel"]}
RESOLVE: PINs Changed - calling browseResponse ... updatedEndpoint:
  [0 - app_svc: com.apple.universalcontrol, service_id: <service_id>]
```

  This confirms that we can trigger the visible PIN pairing state and endpoint
  update. However, `browse-appsvc com.apple.universalcontrol ... appsvc-quic`
  on `bespin` still returns no application-service results even after that
  update.
- The follow-up actor method
  `pairAndReceiveIdentity(pairingData: Foundation.Data) async throws ->
  RPPairingIdentity?` is reachable. Calling it with empty `Data` or with the
  ASCII bytes of the visible PIN returns JSON `null` and logs `Pairing FAIL`.
  Therefore `pairingData` is not the numeric PIN itself; it is the real
  SPAKE2+/Network pairing blob. Local symbols point at the next piece:

```text
SecOfferedPAKEIdentity
sec_identity_create_client_SPAKE2PLUSV1_identity
sec_identity_copy_SPAKE2PLUSV1_registration_record
sec_identity_copy_SPAKE2PLUSV1_client_identity
sec_protocol_options_set_pake_challenge_block
```

  The next implementation task is to generate or obtain this SPAKE2+
  `pairingData` blob on the client side, either by recovering the private
  Security function signatures or by making Network.framework's
  application-service PAKE connection path deliver it.
- The research probes now include two more inspection hooks for that task:
  `continuity-inspect sec-spake [CLIENT_ID] [SERVER_ID] [SCHEME]` prints the
  `SecOfferedPAKEIdentity` Objective-C shape and the relevant private Security
  symbol addresses, and `network-actor-framer-probe` installs
  `sec_protocol_options_set_pake_challenge_block` on TLS/QUIC options and logs
  any offered PAKE identities. On macOS 26.3.1,
  `SecOfferedPAKEIdentity` has:

```text
initWithClientIdentity::: @36@0:8@16@24S32
client_identity -> NSString
server_identity -> NSString
pake_scheme -> uint16_t
```

  A live run after `exchangePAKEIdentities` showed no PAKE challenge callback
  because the unsigned `browse-appsvc` and direct `connect-appsvc` probes still
  do not reach the application-service QUIC handshake. The listener logs still
  show the server-side endpoint update:

```text
LISTEN: Updated PIN info: {"788094":["fbettag","linux","fistel"]}
RESOLVE: PINs Changed - calling browseResponse ... updatedEndpoint:
  [0 - app_svc: com.apple.universalcontrol, service_id: ...]
```

  Bonjour browsing of `_appSvcPrePair._tcp` sees the endpoint but
  `nw_browse_result_copy_txt_record_object`, `nw_endpoint_copy_txt_record`, and
  `nw_endpoint_get_signature` all return nil. The pairing data is therefore
  not exposed through those public endpoint fields on the Bonjour side.
- The new offline decrypt loop for the post-PairVerify stream is:

```sh
cargo run -p macolinux-ucd --bin macolinux-ucd -- \
  eopack decrypt \
  --psk-hex "$EOPACK_DECRYPT_PSK_HEX" \
  --frame-hex "$RAPPORT_FRAME_HEX"
```

  `--body-hex` may be used instead of `--frame-hex` when the Rapport frame
  header has already been stripped. The default endpoint is `client`, matching
  the Linux/probe side receiving the server's first encrypted `E_OPACK`.

Current inference: root access alone is not enough for a clean bootstrap,
because macOS enforces this through code-signing entitlements and keychain
access groups. The clean product direction is a two-sided pairing flow:

1. Generate a fresh Linux `CUPairingIdentity`-compatible keypair and stable
   peer metadata for `fistel`.
2. Install or negotiate a new `CUPairedPeer`/`RPIdentity` record for that Linux
   peer on `endor`, without reusing the existing MacBook identity.
3. Keep the resulting Linux private key on Linux and use it for PairVerify.
4. Leave the MacBook's Universal Control identity untouched, allowing both
   devices to remain paired with `endor`.

The unresolved reverse-engineering question is how to create that macOS-side
paired record without Apple-only entitlements. The next clean experiments should
focus on an Apple-supported pairing request path in Sharing/Rapport, or on a
developer-controlled local helper strategy that installs only a new Linux peer
record and does not export existing device identities.

## Hidden Network pairing configuration ABI

`Network.framework` exports the hidden Swift-only types used by `rapportd`, even
though Xcode's public `Network.swiftinterface` does not expose them:

```text
Network.NWListener.Service.PairingConfiguration
Network.NWBrowser.Descriptor.PairingConfiguration
Network.NWPairingType
Network.NWPairingValue
```

The exported listener constructors and accessors include:

```text
NWListener.Service.PairingConfiguration.init(
  supportedPairingTypes: [NWPairingType],
  pairingData: Foundation.Data?
)

NWListener.Service.PairingConfiguration.init(
  supportedPairingTypes: [NWPairingType],
  pairingValue: NWPairingValue?,
  generatePairingValueImmediately: Bool
)

NWListener.Service.PairingConfiguration.pairingData.getter
NWListener.Service.PairingConfiguration.pairingValue.getter
```

`research/tools/network-pairing-config-probe.swift` calls those hidden symbols
by mangled name and records the current ABI shape on macOS 26.3.1:

```text
listener_pairing_configuration.size=49
listener_pairing_configuration.stride=56
pairing_type.size=0
pairing_type.stride=1
pairing_value.size=16
pairing_value.stride=16
```

For a listener PIN configuration:

```sh
swiftc research/tools/network-pairing-config-probe.swift \
  -o /tmp/network-pairing-config-probe
/tmp/network-pairing-config-probe listener-pin 123456
```

the hidden Network object has `pairingData == nil`; the PIN is stored as
`NWPairingValue.pin("123456")`. This matches the `rapportd` disassembly:
`+[RPPairingSession agentClientListenerGetPairingData:]` first asks the decoded
listener `PairingConfiguration` for `pairingData`; when it is nil, it asks for
`pairingValue`, extracts the `.pin(String)` payload, and converts that string
to UTF-8 `Data`.

That narrows the interpretation of the earlier actor failure: sending ASCII
PIN bytes to `pairAndReceiveIdentity(pairingData:)` is consistent with the
listener fallback path, but it still returns `null` when called out of context
through our direct actor probe. The remaining missing piece is therefore not
the hidden listener config encoding itself; it is the surrounding Network PAKE
session state or the exact client-side PAKE identity material that normally
accompanies the `pairAndReceiveIdentity` call.

A local same-host actor sanity check on `endor` reached
`exchangePAKEIdentities(...)` over `_appSvcPrePair._tcp` and returned a UUID
string, proving the actor transport and target symbol are still good when the
route is available. A subsequent direct same-host
`pairAndReceiveIdentity(pairingData:)` call with `313233343536` (`"123456"`)
still returned JSON `null`, so the missing context is inside the actual PAKE
session path rather than in Bonjour routing alone. During the same run, `bespin`
could browse `_appSvcPrePair._tcp` but did not reach `ready`, and `awdl0` there
reported inactive, so cross-device failures from that run should not be treated
as protocol evidence.

## rapportd SPAKE control-flow anchors

Static disassembly of `/usr/libexec/rapportd` is more useful than the stripped
`Rapport.framework` image for the pairing actor path. The relevant log sites in
the arm64e executable are:

```text
0x1000bbec4  "Starting SPAKE2+ resolve flow"
0x1000b9918  "No remote identity received from pairAndReceiveIdentity"
0x1000b799c  "Falling back to legacy SPAKE client identity"
0x1000d73c8  "Pairing FAIL"
0x1000d74c4  "Pairing SUCCESS, returning self identity"
0x1000e9d3c  "Pairing SUCCESS, returns temporary self identities"
```

`xcrun llvm-objdump --macho --arch=arm64e --disassemble /usr/libexec/rapportd`
shows these are real code references, not dead strings. The control-flow shape
matches the earlier live actor behavior:

- `0x1000bbec4` starts the SPAKE2+ resolve branch.
- A later branch logs
  `0x1000b9918 "No remote identity received from pairAndReceiveIdentity"`.
- That error path then reaches
  `0x1000b799c "Falling back to legacy SPAKE client identity"`.
- The terminal result logs are
  `0x1000d73c8 "Pairing FAIL"`,
  `0x1000d74c4 "Pairing SUCCESS, returning self identity"`, and
  `0x1000e9d3c "Pairing SUCCESS, returns temporary self identities"`.

This matters because the fallback is internal to the `rapportd` SPAKE flow. Our
direct actor call is not merely missing a numeric PIN conversion step; it is
failing before `rapportd` believes it has a usable remote identity and then
dropping into its legacy client-identity path.

The same disassembly also confirms two concrete Security.framework SPAKE client
identity builders inside `rapportd`:

```text
0x1000fef10  _sec_identity_create_client_SPAKE2PLUSV1_identity
0x1000fef44  _sec_identity_copy_SPAKE2PLUSV1_server_password_verifier
0x1000fef5c  _sec_identity_copy_SPAKE2PLUSV1_registration_record

0x1000ffa18  _sec_identity_create_client_SPAKE2PLUSV1_identity
```

The first path immediately extracts both the server password verifier and a
registration record from the created SPAKE identity object. The second path
creates a SPAKE client identity and returns it without that follow-up. That
strongly suggests there are at least two distinct helper flows in `rapportd`:

- a full SPAKE setup/registration path, and
- a lighter-weight identity construction path used by another pairing branch.

Current inference: `pairAndReceiveIdentity(pairingData:)` is downstream of one
of these richer helper paths, not a simple `PIN -> Data -> actor method`
translation. The next useful experiment is to recover the inputs that feed
`_sec_identity_create_client_SPAKE2PLUSV1_identity`, especially which values
map to:

- client identity string,
- server identity string,
- the `OS_dispatch_data` / `Data` argument at the call site, and
- the object that later yields the registration record.

The local Security probe in `research/tools/continuity-inspect.m` narrows that
signature further. Calling:

```sh
/tmp/continuity-inspect sec-spake-client '' fistel endor 123456
```

returns `nil`, but all of these succeed:

```sh
/tmp/continuity-inspect sec-spake-client hex:00 fistel endor 123456
/tmp/continuity-inspect sec-spake-client hex:01 fistel endor 123456
/tmp/continuity-inspect sec-spake-client hex:0001 fistel endor 123456
```

For the successful calls, the constructed `SecConcrete_sec_identity` preserves:

- the context bytes exactly as supplied,
- the client identity bytes,
- the server identity bytes,
- a 64-byte client password verifier,
- a 32-byte server password verifier, and
- a 65-byte registration record.

That means the hidden Security constructor does not accept a `nil` context, but
it also does not appear to require a strongly typed or fixed-width context blob
for basic operation. In other words, there is at least one layer above the raw
SPAKE constructor that is still missing from the actor path: `rapportd` is not
simply passing the visible PIN bytes directly into Security.

The matching server-side probe also round-trips successfully with those
derived values:

```sh
/tmp/continuity-inspect sec-spake-server \
  hex:00 fistel endor \
  64462534b2e6d0bd76c459fa6c1f412c487637080c6ad437d81c0adbfc43c9ef \
  0420df8c3bbef968cd1457cdaf0162d91c6b74d954d00dcbf03c81eb3e2e8c9634a130af1e90ae688c5911d0806e60403bec56fc04ca6037631f0d01ea61f4dad0
```

So the currently validated hidden Security tuple is:

```text
context: non-empty dispatch_data
client_identity: dispatch_data
server_identity: dispatch_data
password: dispatch_data
```

for the client constructor, and:

```text
context: dispatch_data
client_identity: dispatch_data
server_identity: dispatch_data
server_password_verifier: dispatch_data
registration_record: dispatch_data
```

for the server constructor.

Those richer SPAKE blobs still do not satisfy the actor by themselves. A fresh
same-host `_appSvcPrePair._tcp` listener on `endor` was used to call
`pairAndReceiveIdentity(pairingData:)` with:

- the 65-byte registration record, and
- the 32-byte server password verifier

derived from the working local Security probe above. Both calls returned actor
JSON `null`, just like the earlier raw PIN-byte attempt. That is strong
evidence that the actor method depends on additional in-memory session state
created by the real Network PAKE path, not only on the opaque bytes eventually
fed into Security.framework.

## Hidden application-service UUID endpoint probe

The next missing browse/result step is now partially bypassed. `Network`
exports a hidden Swift constructor:

```text
NWEndpoint.applicationService(_:uuid:)
```

and a hidden parameter factory:

```text
NWParameters.applicationServiceQUIC(identity:)
```

`research/tools/network-appsvc-uuid-probe.swift` calls both symbols directly
with `@_silgen_name`, then inspects the resulting parameter stack and installs
the private PAKE challenge callback on any protocol option that exposes
`securityProtocolOptions`.

For a temporary pairing listener such as:

```text
listener advertised add endpoint=app_svc: com.apple.universalcontrol,
  service_id: 722348E7-CF76-49FE-B143-1F0528821F9A
```

the new probe can target that exact endpoint by UUID:

```sh
swiftc research/tools/network-appsvc-uuid-probe.swift \
  -o /tmp/network-appsvc-uuid-probe

MACOLINUX_PAKE_MODE=respond \
MACOLINUX_PAKE_PASSWORD=123456 \
/tmp/network-appsvc-uuid-probe \
  connect com.apple.universalcontrol \
  722348E7-CF76-49FE-B143-1F0528821F9A 8
```

Current results on macOS 26.3.1:

- The hidden endpoint constructor is valid and prints as expected:

```text
endpoint=app_svc: com.apple.universalcontrol,
  service_id: 722348E7-CF76-49FE-B143-1F0528821F9A
endpoint.pairingData=nil
```

- The hidden `applicationServiceQUIC` parameter stack is not shaped like plain
  `NWParameters(quic:)`. It currently reports:

```text
stack.transport=Optional(Network.NWProtocolUDP.Options)
stack.application[0]=Network.NWProtocolQUIC.Options
stack.internet=Optional(Network.NWProtocolIP.Options)
```

  So the application-service QUIC path is layered as UDP transport plus QUIC in
  the application protocol stack, not as QUIC in `transportProtocol`.

- Installing the PAKE challenge block on that `NWProtocolQUIC.Options` object
  is successful, but neither same-host (`endor -> endor`) nor remote
  (`bespin -> endor`) exact-UUID connection attempts have produced a PAKE
  callback yet. Both runs remain:

```text
connection.state=preparing
timeout.cancel
connection.state=cancelled
```

This removes another guess:

- the hidden app-service endpoint UUID is not the missing piece,
- the hidden app-service QUIC parameter factory is not the missing piece, and
- the PAKE callback is still not reached even when the client targets the exact
  temporary `app_svc` endpoint instead of relying on `browse-appsvc`.

The remaining likely gap is below that layer: some additional application-
service routing or endpoint material that the production `RPNWNetworkAgent`
adds before the connection is allowed to advance past `preparing`.

Additional endpoint inspection from `research/tools/network-appsvc-uuid-probe.swift`
narrows the public/hidden `NWEndpoint` surface further:

- For exact hidden app-service endpoints created with
  `NWEndpoint.applicationService(_:uuid:)`, the currently safe getters still
  report:

```text
endpoint.txt=nil
endpoint.serviceID=nil
endpoint.pairingData=nil
```

- For Bonjour browse results on `_appSvcPrePair._tcp` and
  `_applicationServicePairing._tcp` from `bespin`, the safe hidden getters on
  the returned `NWEndpoint` objects also report no additional material for both
  the local and remote results:

```text
result.endpoint.txt=nil
result.endpoint.serviceID=nil
result.endpoint.pairingData=nil
result.endpoint.applicationService=nil
result.endpoint.applicationServiceName=nil
result.endpoint.deviceName=nil
result.endpoint.publicKeys=nil
result.metadata=<none>
result.interfaces=["awdl0"]
```

- The hidden `NWEndpoint.serviceIdentifier` getter is not safe to use on these
  Bonjour result endpoints in the current probe shape; it crashes the helper
  process while the safer getters above do not. So the useful conclusion is not
  the value of that property but the separation of object layers: the Bonjour
  browse result endpoint is still not the same rich application-service object
  that production code must be using to leave `preparing`.

That pushes the likely missing state one step lower again: not only is the
client missing app-service browse promotion, the ordinary Bonjour-visible
`NWEndpoint` object itself is also missing the extra agent/service material that
the production path carries.

Two more hidden-Network probes sharpen that further:

- `NWApplicationServiceGroup.for(_:id:)` is real, but it rejects plain Bonjour
  pairing endpoints as the wrong input kind. Feeding it the raw
  `_appSvcPrePair._tcp` `NWBrowser` results plus the known temporary
  `service_id` logs:

```text
-[NWConcrete_nw_group_descriptor initWithType:member:groupID:]
  Invalid endpoint type specified for group descriptor of type application_service
nw_group_descriptor_add_endpoint called with null descriptor
```

  So the raw Bonjour result endpoint is definitely not yet the promoted
  application-service endpoint type that the group API expects.

- A new hidden parameter knob also proved non-trivial:
  `_nw_parameters_set_attributed_bundle_identifier`. Applying
  `com.apple.universalcontrol` to the client browse parameters in
  `network-actor-framer-probe` does not promote results. Instead, both locally
  and from `bespin`, `browse-appsvc` now fails immediately with:

```text
parameters attributed_bundle_id=com.apple.universalcontrol
browser state=failed error=Invalid argument
```

  while `connect-appsvc` with the same attributed bundle ID still only reaches
  `timeout/cancel`. So this hidden parameter field is live and observable, but
  setting it directly is not the missing promotion step and may violate another
  internal precondition of the application-service browse path.

Current consequence: the next credible target is the internal promotion step
itself, most likely around
`BrowserProviderFactories.ApplicationService.makeEndpoint(from:)` or an
equivalent `RPNWNetworkAgent` handoff that transforms a Bonjour browse result
into an application-service endpoint before group creation or connection.

## C-level application-service endpoint dictionaries

`research/tools/network-endpoint-c-probe.c` now exercises the private C
Network endpoint constructors directly. This is more useful for the eventual
Rust/C implementation than the hidden Swift `NWEndpoint.nw` getter, because
compiled Swift does not call that resilient getter safely in our current probe.
The Swift interpreter can call it, but compiled helpers fault around Swift ARC
or optional-object handling, so the stable path is the C API.

Relevant C exports confirmed via `dyld_info`:

```text
_nw_endpoint_create_application_service
_nw_endpoint_create_application_service_with_alias
_nw_endpoint_create_bonjour_service
_nw_endpoint_copy_dictionary
_nw_endpoint_create_from_dictionary
_nw_endpoint_get_application_service_alias
_nw_endpoint_get_application_service_name
_nw_endpoint_get_device_id
_nw_endpoint_get_device_name
_nw_endpoint_set_device_id
_nw_endpoint_set_device_name
_nw_endpoint_set_service_identifier
_nw_parameters_create_application_service_quic
```

Confirmed ABI details:

- `nw_endpoint_create_application_service(const char *service, uuid_t id)`
  creates a type-6 application-service endpoint with a default alias string of
  `alias`.
- `nw_endpoint_create_application_service_with_alias(const char *service,
  const char *alias)` creates a type-6 application-service endpoint with the
  chosen alias, but generates its own service UUID.
- `nw_endpoint_set_service_identifier(endpoint, uuid_t id)` can then overwrite
  that generated UUID, so we can synthesize an endpoint with both the real
  temporary service UUID and a chosen alias.
- `nw_endpoint_set_device_name` and `nw_endpoint_set_device_id` add ordinary
  dictionary fields and their getters return the values.
- A normal Bonjour endpoint created with `nw_endpoint_create_bonjour_service`
  is type 3 and only serializes Bonjour name/type/domain fields.

Example synthetic application-service endpoint:

```text
endpoint.dictionary=<dictionary ... contents =
  "service_identifier" => 11111111-2222-3333-4444-555555555555
  "device_name" => "fistel"
  "application_service_alias" => "fistel"
  "device_color" => 0
  "application_service_name" => "com.apple.universalcontrol"
  "type" => 6
  "device_id" => "test-device-id"
}
endpoint.application_service_name=com.apple.universalcontrol
endpoint.application_service_alias=fistel
endpoint.device_name=fistel
endpoint.device_id=test-device-id
```

Example plain Bonjour endpoint:

```text
endpoint.dictionary=<dictionary ... contents =
  "bonjour_domain" => "local."
  "bonjour_type" => "_appSvcPrePair._tcp"
  "bonjour_name" => "endor"
  "type" => 3
}
endpoint.application_service_name=nil
endpoint.application_service_alias=nil
```

The C probe also has a `connect-appsvc-alias` mode. It creates a type-6
application-service endpoint with alias/device fields, uses
`nw_parameters_create_application_service_quic()`, enables peer-to-peer, and
starts a normal `nw_connection`. It also supports `require-interface NAME`,
implemented through `nw_interface_create_with_name` and
`nw_parameters_require_interface`.

Remote live test from `bespin` to a temporary `endor` pairing listener:

```text
listener advertised add endpoint=app_svc: com.apple.universalcontrol,
  service_id: 3042C1AE-A65D-4F4C-82C6-C3A1BBC70393

endpoint.dictionary=<dictionary ... contents =
  "service_identifier" => 3042C1AE-A65D-4F4C-82C6-C3A1BBC70393
  "device_name" => "endor"
  "application_service_alias" => "endor"
  "application_service_name" => "com.apple.universalcontrol"
  "type" => 6
  "device_id" => "endor-probe"
}
connection.state=preparing
timeout.cancel
connection.state=cancelled
```

Repeating the same live test from `bespin` with `require-interface awdl0` also
does not progress:

```text
listener advertised add endpoint=app_svc: com.apple.universalcontrol,
  service_id: 0DE8A2AF-0790-42FF-A3EA-CD681FF131A0

parameters.required_interface=awdl0
connection.state=preparing
timeout.cancel
connection.state=cancelled
```

This is a useful negative result. We can now synthesize the same visible
application-service endpoint dictionary fields that Network serializes for
type-6 endpoints, and even with a real temporary listener UUID and an explicit
AWDL interface requirement the connection does not progress beyond `preparing`.
The missing state is therefore not just `service_identifier`,
`application_service_alias`, `device_name`, `device_id`, or interface
selection. It is likely an agent/routing attachment or production promotion
step outside the endpoint dictionary, still probably in the
`RPNWNetworkAgent`/`BrowserProviderFactories.ApplicationService` path.

Unified logs from the same window support that split:

```text
network-endpoint-c-probe ... app_svc: com.apple.universalcontrol,
  service_id: 11111111-2222-3333-4444-555555555555 ...
  attribution: developer, local only, stricter path scoping,
  multipath service: interactive, use awdl, prohibit fallback
event: path:satisfied ... interface: en0
```

while the temporary listener path goes through rapportd's RPNW agent:

```text
RPNWAgentClient Updated ... (LSTNR):
  < appSvc=com.apple.universalcontrol PID:... entitled=0
    flowToken=[pid:...,id:...] browseToken=[pid:...,id:...]
    port=60667 (TCP) adesc=com.apple.universalcontrol.com.apple.universalcontrol
    scope:0 route:0 custom:147 >
LISTEN: Creating pairing listener framer
createListenerFramer calling assign with local endpoint=::.60667
Started inbox socket ... endpoint: ::.60688, interface: awdl0
Started inbox socket ... endpoint: ::.60713, interface: awdl0
```

So the client side is still missing a matching RPNW agent/client assignment,
token, group descriptor, or browse-promotion result. The next concrete probes
should target:

- C-level `nw_browse_descriptor_create_application_service_with_bundle_id` plus
  `nw_browse_descriptor_set_discover_application_service_endpoints_only`, then
  inspect whether browse results become type-6 endpoints rather than type-3
  Bonjour endpoints.
- `nw_parameters_set_required_netagent_*` or
  `nw_parameters_set_preferred_netagent_*` once we can learn the relevant RPNW
  agent UUID/token from a listener or browse path.
- C-level `nw_group_descriptor_create_application_service` and
  `nw_group_descriptor_add_endpoint` using the synthetic type-6 endpoints,
  to verify whether group creation accepts those endpoints outside Swift's
  `NWApplicationServiceGroup.for(_:id:)` wrapper.

Follow-up result for the first item: `network-endpoint-c-probe` now has
`browse-appsvc-bundle SERVICE BUNDLE SECONDS [endpoints-only 0|1]
[require-interface NAME]`, using the private explicit-bundle browse descriptor
and the private `discover_application_service_endpoints_only` flag.

Against a live temporary `endor` pairing listener from `bespin`:

```text
listener advertised add endpoint=app_svc: com.apple.universalcontrol,
  service_id: DBB3F746-9666-4199-93A9-0ED6AFB8807D

descriptor.service=com.apple.universalcontrol
descriptor.bundle=com.apple.universalcontrol
endpoints_only=true
parameters.required_interface=awdl0
browser.state=ready
browser.timeout
browser.state=cancelled
```

Repeating with `endpoints_only=false` also times out with no results. This
contrasts with ordinary Bonjour browsing, which sees the same listener as
`endor._appSvcPrePair._tcp.local.` on `awdl0`. So explicit-bundle
application-service browsing alone does not trigger the promotion path for an
unsigned helper.

Follow-up result for the group descriptor item: the C ABI is
`nw_group_descriptor_create_application_service(nw_endpoint_t member,
uuid_t id)`. Unlike the earlier Swift wrapper fed with raw Bonjour endpoints,
the C call accepts a synthetic type-6 application-service endpoint and
enumerates it back:

```text
endpoint.dictionary=<dictionary ... contents =
  "service_identifier" => 11111111-2222-3333-4444-555555555555
  "device_name" => "fistel"
  "application_service_alias" => "fistel"
  "application_service_name" => "com.apple.universalcontrol"
  "type" => 6
  "device_id" => "test-device-id"
}
group.member[0].dictionary=<dictionary ... contents =
  "service_identifier" => 11111111-2222-3333-4444-555555555555
  "device_name" => "fistel"
  "application_service_alias" => "fistel"
  "application_service_name" => "com.apple.universalcontrol"
  "type" => 6
  "device_id" => "test-device-id"
}
group.members.count=1
```

That means group descriptor construction itself is not the blocker once the
endpoint is already type 6. The blocker remains how a real browse/pairing flow
gets a client-side RPNW agent assignment or promoted endpoint connected to the
remote listener.

Follow-up on the RPNW agent side: `rapportd` creates three live Network agents
per daemon instance. On this boot the unified logs showed:

```text
Browse Agent UUID=d1c07537-0c3d-4b9f-a1a0-d3cdbbe7d30f
Network Agent UUID=0da5d94a-00be-403b-ada7-d0dca0ad80c4
DDUI Resolve Agent UUID=5d43a219-a950-42ec-919c-f71a2544afd2
```

`nw_network_agent_copy_dictionary_for_uuid` returns a 420-byte opaque data blob,
but its layout starts with UUID, domain, type, and description:

```text
d1c07537-...  com.apple.rapport.browse        RapportBrowseAgent       Rapport Browse Agent
0da5d94a-...  com.apple.rapport               RapportNetworkAgent      Rapport Network Agent
5d43a219-...  com.apple.rapport.dduiresolve   RapportDDUIResolveAgent  DDUI Resolve Agent
```

Static strings and `createBrowseAgent` disassembly agree with those class names.
`network-endpoint-c-probe` can now apply both UUID and class constraints:

```text
require-netagent d1c07537-0c3d-4b9f-a1a0-d3cdbbe7d30f
require-netagent-class com.apple.rapport.browse RapportBrowseAgent
```

The private class setter ABI is:

```c
nw_parameters_set_required_netagent_classes(parameters, xpc_domains, xpc_types)
```

where `xpc_domains` and `xpc_types` are parallel XPC string arrays. The copy
helpers confirm Network accepts the values:

```text
parameters.required_netagent_domains = [ "com.apple.rapport.browse" ]
parameters.required_netagent_types   = [ "RapportBrowseAgent" ]
```

However, requiring the live browse, network, or DDUI agent by UUID or by class
still leaves the browser in `ready` until timeout and produces no bounded-window
`rapportd` RPNW browse activity. Forcing browse parameters such as
`include_ble`, `include_screen_off_devices`, `use_p2p`, `use_awdl`, stricter
path scoping, effective/source bundle IDs, and app-service QUIC mode likewise
does not enter the RPNW browse handler from an unsigned helper.

The likely reason is now explicit in `rapportd`'s policy setup. Strings around
`-[RPNWNetworkAgent setupPolicyWithQueue:browseAgent:]` include:

```text
com.apple.private.application-service-browse
Failed to add entitlement allow policy for agent %@
```

`replicatord` and `chronod` both carry
`com.apple.private.application-service-browse`; `UniversalControl.app` does
not. An ad-hoc signed copy of the probe with that entitlement is rejected by
AMFI before `main`:

```text
Adhoc signed app with restricted entitlements detected
The file is adhoc signed but contains restricted entitlements
bailing out because of restricted entitlements
```

So the clean client-side app-service browse path is gated by a restricted Apple
entitlement, not merely by a hidden Network parameter. For a Linux client this
means the practical path is still to make Linux look like the paired remote
endpoint that Apple's own entitled clients discover and connect to, or to build
a Mac-side exporter/bridge that uses already-entitled system components. An
ordinary unsigned macOS helper cannot be promoted into the same browse policy
just by setting RPNW netagent UUIDs/classes.

## CompanionAuthentication pre-pair path

Follow-up probing on macOS 26.3.1 narrowed the `CompanionAuthentication` side
further:

- A local explicit-bundle listener on `endor`:

```sh
target/research/continuity-inspect \
  nw-appsvc-listen \
  com.apple.CompanionAuthentication \
  com.apple.CompanionAuthentication \
  10
```

  does enter `rapportd`'s RPNW listener path even without Apple entitlements.
  The bounded-window unified logs showed:

```text
ADVERTISE: Start advertise 'com.apple.CompanionAuthentication' request QUIC=NO isTCP=YES
Using appSvc only: 'com.apple.CompanionAuthentication'
Could not find registered listener for appSvc=com.apple.CompanionAuthentication
Updated RPNWAgentClient ... (LSTNR): < appSvc=com.apple.CompanionAuthentication ... >
Update server: RPServer: ST 'com.apple.CompanionAuthentication'
Activate: RPServer: ST 'com.apple.CompanionAuthentication', from rapportd:1036
```

  So `com.apple.CompanionAuthentication` is a real Rapport/Network application
  service type, not just an inert string. However, both same-host and
  cross-host unsigned `nw_browser` / `browse-appsvc-bundle` probes still timed
  out with no results, matching the earlier conclusion that plain unsigned
  app-service browsing does not see the promoted endpoint path.

- A remote pairing-style listener on `bespin`:

```sh
ssh bespin '
  /tmp/continuity-inspect-bespin \
    nw-appsvc-listen-pairing \
    com.apple.CompanionAuthentication \
    com.apple.CompanionAuthentication \
    123456 15'
```

  produced real AWDL mDNS advertisements captured on `endor` with:

```sh
ssh root@localhost 'tcpdump -i awdl0 -n -s0 -w /tmp/compauth-awdl.pcap udp port 5353'
```

  Decoding the capture shows `bespin` advertising both temporary pairing
  service types over `awdl0`:

```text
bespin (2)._appSvcPrePair._tcp.local.
bespin (2)._applicationServicePairing._tcp.local.
TXT "at=c61c49c512bd" "sid=2E49D8CA-D43E-4EFC-AD9D-1264F71E2D56"
    "sn=com.apple.CompanionAuthentication" "dnm=bespin"
SRV ...:65203
SRV ...:65202
```

  This is important because it proves a second real Mac can emit the same
  pairing/pre-pair transport shape for `CompanionAuthentication`, not just for
  `com.apple.universalcontrol` or AirDrop.

- Despite those AWDL advertisements being visible on `endor` at packet level,
  a bounded-window unified-log sweep on `endor` for `rapportd`, `sharingd`,
  `wifip2pd`, and related daemons showed no matching `CompanionAuthentication`,
  `_appSvcPrePair`, `_applicationServicePairing`, `Bonjour peer`, or
  `Bonjour unauth` activity. The only unrelated hit in that window was an
  `audioaccessoryd` nearby-audio update for `bespin`.

Current consequence: passive system state on `endor` is not reacting just
because valid `CompanionAuthentication` pre-pair traffic exists on AWDL. The
missing step is likely the launch-on-demand consumer that decides when to start
that discovery path, or an additional trust/UI gate above packet visibility.

## Add Display consumer gate

A later live check on `endor` confirmed that the macOS Displays "Add Display"
menu is the actual consumer path we need to satisfy. With the menu open,
`bespin` appears alongside Apple TVs, while `fistel` still does not.

The important bounded-window `rapportd` signal is not another Bonjour/TXT
difference. Instead, `RPIdentityDaemon` logs:

```text
Ignoring device with no DeviceAuthTag:
  CUBonjourDevice 14:AB:C5:55:F0:31, "fistel", TT 0x2 < WiFi >,
  TXT { "rpMac" : "0", "rpHN" : "fistel", "rpFl" : "0x20000", ... }
```

At the same time, same-account Apple peers shown in the menu resolve as:

```text
Resolved DeviceAuthTag: owner, CUBonjourDevice ..., "Wohnzimmer", ... ->
  RPIdentity, Type SameAccountDevice, ...
```

This moves the blocker one layer higher than raw CompanionLink TXT. A live
`dns-sd -L` comparison shows `bespin` and `fistel` currently advertise very
similar `_companion-link._tcp` TXT on the LAN:

```text
bespin: rpMac=0 rpHN=b35c03a9cc46 rpFl=0x20000 rpHA=b0996f4a7ec2
        rpVr=715.2 rpAD=6423ba43ce0e rpHI=695775143b45 rpBA=E5:60:8C:BB:8B:50

fistel: rpMac=0 rpHN=fistel         rpFl=0x20000 rpHA=14ABC555F031
        rpVr=715.2 rpAD=900045d546  rpHI=2204          rpBA=14:AB:C5:55:F0:31
```

So the current rejection is not explained by the obvious LAN TXT shape alone.
The binary strings in `rapportd` line up with that result and point to a
Bluetooth/auth-tag trust path:

```text
Ignoring device with no DeviceAuthTag
Resolved DeviceAuthTag: owner / family / friend / paired / SessionPaired / AdHocPaired
Using Bluetooth Identifier %@ and AuthTag %@ for AWDL Bonjour advertisement
resolveIdentityForTempAuthTagData:bluetoothAddressData:
bleAuthTag
nearbyInfoV2TempAuthTagData
```

Current consequence: the next productive target is no longer generic Bonjour
promotion. We need to understand or reproduce the `DeviceAuthTag` /
`bleAuthTag` trust input that lets `RPIdentityDaemon` map the peer to an
`RPIdentity`, or else rely on an Apple-side bridge that already has that trust.

## BLE payload correlation from `fistel`

The next pass moved below unified logs and captured raw BLE advertising blocks
from `fistel` with `btmon` while `btmgmt find -l` scanned nearby Apple devices.
This produced full Apple manufacturer payloads rather than just address churn.

Representative captures:

```text
Address 7F:9B:35:00:B8:F3 (Resolvable), ADV_IND
  Type 0x0f payload 90006fb0d9
  Type 0x10 payload 2404

Address 5A:AC:83:8C:FE:93 (Resolvable), ADV_IND
  Type 0x0f payload 9000a51860
  Type 0x10 payload 2f04

Address 6E:23:20:1A:EA:1B (Resolvable), ADV_IND
  Type 0x0f payload 9000330ae2
  Type 0x10 payload 2804

Address 67:9C:8E:80:8A:19 (Resolvable), ADV_IND
  Type 0x10 payload 2514da970e

Address 2E:8E:3F:58:76:9F (Non-Resolvable), ADV_NONCONN_IND
  Type 0x13 payload 4aebd6f7c1837c00
```

These are not synthetic artifacts. The same payloads already appear in
`endor`'s live `sharingd` logs as real Apple Continuity devices:

```text
BLE NearbyAction changed ... AdvD <9000330ae2> ... Paired yes, Cnx no, WiFiP2P
BLE NearbyInfo changed ... AdvD <2804> ... Paired yes, Cnx no, WiFiP2P

BLE NearbyInfo changed ... AdvD <2404> ... Paired yes, Cnx no, WiFiP2P
BLE NearbyInfo changed ... AdvD <2f04> ... Paired yes, Cnx no, WiFiP2P
BLE NearbyInfo changed ... AdvD <2514da970e> ... Paired yes, Cnx no, WiFiP2P
```

The important correlation is that the newer-looking five-byte `0x10` payload is
not noise. It is accepted by the same `sharingd` parser surface as the older
two-byte `0x10` values and stays tied to a paired WiFiP2P Apple peer.

A follow-up bounded capture plus local `sharingd` logs tightened this further:

- Some `0x0f` / `0x10` pairs are dynamic per device over time. For example, the
  same paired peer can rotate from `9000330ae2 + 2804` to `9000baaa64 + 2804`.
  So the `0x0f` payload is not a stable identity handle.
- Other peers rotate through `9000156f40 + 2504` and `9000412efd + 2904`, and
  those exact tuples also appear in `sharingd` as `Paired yes, Cnx no, WiFiP2P`
  devices.
- `sharingd`'s own `WirelessProximity` logs show macOS locally starting a type
  `16` advertisement with six bytes of data such as `421d2144a178`.
- Another six-byte `0x10` payload, `461dfba87a58`, appears on both a
  `Paired yes` device and a separate `Paired no` device at the same time.

Current inference: these newer six-byte `0x10` payloads are real and used by
Apple's stack, but they still do not look like the unique trust primitive that
explains `DeviceAuthTag` by themselves.

## Synchronized Add Display capture

To make the next rounds repeatable, there is now a bounded capture harness at:

```text
research/tools/capture-add-display-session.sh
```

It does three things in one run:

1. Opens the macOS Displays pane and programmatically clicks the Add Display
   menu.
2. Saves the visible menu items.
3. Collects bounded unified logs on `endor` plus a remote `btmon` capture on
   `fistel`, then parses Apple manufacturer TLVs with
   `research/tools/btmon-apple-continuity.py`.

A representative menu snapshot from this harness is:

```text
Tastatur und Maus verknüpfen mit:
  bespin

Spiegeln oder erweitern auf
  bespin
  Schlafzimmer
  Wohnzimmer
```

That matters because it proves the user-visible Add Display candidate set can be
captured without relying on manual timing.

One manual control experiment used the same harness window but restarted
`macolinux-uc.service` on `fistel` while the menu stayed open. In that bounded
window, `rapportd` still logged:

```text
Ignoring device with no DeviceAuthTag:
  CUBonjourDevice 14:AB:C5:55:F0:31, "fistel", ...
```

At the same time, the same menu snapshot still showed `bespin`,
`Schlafzimmer`, and `Wohnzimmer` as candidates. This is the cleanest same-session
confirmation so far that `fistel` is blocked at identity resolution while the
real Apple peers continue to occupy the Add Display UI path.

Another useful consequence of these bounded sessions: opening the Add Display
menu does not guarantee a fresh `Resolved DeviceAuthTag` log for already-known
peers such as `bespin`. The menu can render from cached candidate/identity
state. Fresh `RPIdentityDaemon` resolution logs appear when background
CompanionLink churn happens in the same window, not just because the menu was
opened.

In the same time windows, `rapportd` classifies nearby peers with matching
signal/range characteristics as real paired iCloud devices, but often still
rejects them for the Remote Display use case:

```text
Ignoring unsupported BLE device found: ... DF 0x228 < MyiCloud Ranging DeviceClose > ...
Ignoring unsupported BLE device found: ... DF 0x28 < MyiCloud Ranging > ...
```

This matters for the Linux implementation because it separates three layers:

1. Emitting Apple-like Continuity BLE TLVs is not enough by itself.
2. `sharingd` already recognizes these payload shapes as paired Apple devices.
3. `rapportd` still applies an additional product/use-case gate above that,
   and the Add Display path separately rejects `fistel` for missing
   `DeviceAuthTag`.

One more practical constraint showed up during this pass: unsigned local tools
can enumerate some authentication type names, but the useful pairing and
identity APIs remain entitlement-gated. `pairing-summary` fails with
`kMissingEntitlementErr`, and `rpclient-list-identities` fails with missing
`com.apple.rapport.Client`. So the next stage still needs static reversing or
log-level correlation rather than public/private API calls from an unsigned
helper.

## Static DeviceAuthTag path

`dyld_info -objc /usr/libexec/rapportd` turned out to be the cleanest static
view of the daemon code. It resolves the arm64 method entry points directly,
which avoids the misleading relative-method output from `otool -oV`.

The key arm64 entry points are:

```text
0x100063de8  -[RPIdentityDaemon resolveIdentityForTempAuthTagData:bluetoothAddressData:]
0x1000237dc  -[RPCompanionLinkDaemon _serverBonjourAuthTagStringWithData:]
0x100018834  -[RPCompanionLinkDaemon _serverNearbyInfoV2DeviceFound:deviceFlags:]
0x19bd3d604  -[RPIdentity authTagForData:type:error:]
0x19bd3d848  -[RPIdentity verifyAuthTag:data:type:error:]
0x19bd3d918  -[RPIdentity verifyAuthTagPtr:authTagLen:dataPtr:dataLen:type:error:]
```

The framework-side `RPIdentity` disassembly plus runtime IMP lookup now gives a
concrete auth-tag model:

- `authTagForData:type:error:` uses `self->_deviceIRKData` at ivar offset
  `0x58`, not the public key, account ID, or IDS device ID.
- It derives a six-byte intermediate tag from `deviceIRKData` and the caller's
  input bytes, then truncates it according to a small static table.
- `verifyAuthTag:data:type:error:` is just an `NSData` wrapper around
  `verifyAuthTagPtr:...`.
- `verifyAuthTagPtr:...` regenerates the same bytes and compares them with a
  constant-time XOR loop.

The current length table by auth-tag type is:

```text
type 1 -> 6 bytes
type 2 -> 3 bytes
type 3 -> 1 byte
type 4 -> 6 bytes
type 5 -> 3 bytes
type 6 -> 6 bytes
```

This is immediately useful for the daemon side because the BLE temp-auth path
does not use the six-byte Bonjour form.

### Temp auth resolution

`RPIdentityDaemon resolveIdentityForTempAuthTagData:bluetoothAddressData:`
does the following:

1. Calls `identitiesOfType:error:` with type `0x0f`.
2. Iterates those identities.
3. For each identity, calls
   `verifyAuthTag:data:type:error:(tempAuthTagData, bluetoothAddressData, 2)`.
4. Returns the first identity whose verification succeeds.

This lines up with earlier runtime probing: in `rapportd`, `RPIdentity` type
`15` is `AdHocPairedDevice`. So the temp-auth BLE gate is:

```text
AdHocPairedDevice identities
  + deviceIRKData
  + bluetoothAddressData
  -> verify 3-byte auth tag (type 2)
```

That is a much tighter explanation of the `DeviceAuthTag` rejection than the
earlier generic Bonjour/TXT hypotheses.

### BLE intake path

`RPCompanionLinkDaemon _serverNearbyInfoV2DeviceFound:deviceFlags:` now has a
named high-level flow:

1. Read `btAddressData` from the incoming `CBDevice`.
2. Read `nearbyInfoV2TempAuthTagData` from that same `CBDevice`.
3. Get `[RPIdentityDaemon sharedIdentityDaemon]`.
4. Call
   `resolveIdentityForTempAuthTagData:bluetoothAddressData:` with those exact
   two values.
5. If an identity resolves, use its `idsDeviceID` to find/update the tracked
   CompanionLink device state.

So the daemon-side bridge from BLE into identity resolution is no longer
speculative. The exact BLE fields are:

```text
CBDevice.btAddressData
CBDevice.nearbyInfoV2TempAuthTagData
```

and they flow directly into `RPIdentityDaemon`.

### Bonjour auth tag

`RPCompanionLinkDaemon _serverBonjourAuthTagStringWithData:` uses:

1. `[RPIdentityDaemon sharedIdentityDaemon]`
2. `identityOfSelfAndReturnError:nil`
3. `authTagForData:type:error:(data, 1, nil)`

and then formats the resulting bytes as a hex string for Bonjour publication.

So the normal Bonjour auth tag is the six-byte type-1 form on the daemon's
current self identity, while the BLE temp-auth resolution path uses the
three-byte type-2 form on `AdHocPairedDevice` identities.

The sibling method `_serverBonjourTempAuthTagStringWithData:` is the same
type-1 auth-tag generation path, but it swaps in
`identityOfTemporarySelfAndReturnError:nil` instead of the normal self
identity.

Current consequence:

- `rpHI` / Bonjour auth tags and BLE temp-auth tags are related, but they are
  not the same auth-tag type.
- The Universal Control admission blocker is specifically on the BLE
  `nearbyInfoV2TempAuthTagData` -> `AdHocPairedDevice` resolution path.
- A Linux implementation can only satisfy that path if it can advertise the
  correct three-byte type-2 auth tag for a device IRK that macOS already trusts
  as an `AdHocPairedDevice`, or if a small macOS bridge/exporter provides that
  trusted identity material on the Apple side.

## x86_64 pairing save path

The x86_64 slice of `/usr/libexec/rapportd` fills in the next layer above the
BLE admission gate: how pairing and identity-share results are turned into
persisted ad-hoc identities.

### Shared save dispatcher

`FUN_1000d1d60` is the path that logs:

```text
"Saving remote identity: %s"
"No remote identity received from pairAndReceiveIdentity"
```

When the remote identity is present, it does not persist it directly. It
tail-jumps to `FUN_100124280`, which is a generic save dispatcher.

That dispatcher is reused by at least one other path. A second caller at
`0x1000f115d` logs:

```text
"Pairing SUCCESS, returning self identity"
"Saving shared identity: %s"
```

and then tail-jumps into the same `FUN_100124280` save dispatcher. So the
downstream persistence path is shared between the "remote identity received"
branch and the "shared/self identity" branch.

### Persisted identity constructors

`FUN_100124280` schedules the single-record constructor
`FUN_100124340`. That constructor:

1. alloc/init's an `RPIdentity` object with type `0x0f`
2. sets `dateAdded`
3. sets `deviceIRKData`
4. sets `edPKData`
5. sets additional peer metadata such as identifier / name / model / type
6. calls `addOrUpdateAdHocPairedIdentity:`

The sibling function `FUN_100124990` performs the same kind of object build for
an indexed record layout, which matches the earlier `shareTemporaryIdentities`
hypothesis much better than the single-record path.

The important consequence is that `addOrUpdateAdHocPairedIdentity:` is not
deriving IRK state on its own. The `RPIdentity(type=15 / AdHocPairedDevice)`
object already carries `deviceIRKData` and `edPKData` before persistence.

### Correction: auth-tag match reads an existing identity IRK

The earlier assumption that `FUN_10010dc30` was reading `deviceIRKData` from a
freshly received remote pairing identity was too broad.

The actual x86_64 control flow is:

1. iterate candidate identities
2. call a `verifyAuthTag:data:type:error:`-shaped selector on each candidate
3. log either:
   - `AuthTag matches existing identity %@`
   - `AuthTag doesn't match identity %@ - %s needs identity share`
4. on the match path, call `deviceIRKData` on that matched existing identity

So the `0x10010e720` `deviceIRKData` read is from the already-known candidate
identity that passed auth-tag verification, not directly from the newly
received pairing result.

This fits the earlier daemon-side temp-auth model:

```text
existing AdHocPairedDevice identity
  + deviceIRKData
  + incoming auth-tag/data
  -> verify
  -> matched trusted peer
```

### Remaining unknown

The unresolved source is now narrower: where the incoming `RPPairingIdentity` /
`RPPairingTemporaryIdentity` first gets the `deviceIRKData` that later flows
through the shared save dispatcher into persisted `AdHocPairedDevice` state.

### Offline Swift field metadata

An offline parser over `__swift5_fieldmd` and `__swift5_reflstr` now gives us a
cleaner view of the pairing-side value layouts without relying on a working
headless decompiler.

The reusable helper is:

```text
research/tools/swift_fieldmd_dump.py
```

and the high-value `rapportd` hits are:

1. A class descriptor at `0x1001ad5cc` looks like the live distributed
   pairing-actor state object. Its stored properties include:
   - `pairingData`
   - `selfIdentity`
   - `pairVerifySessions`
   - `legacySessionID`
   - `pendingContinuation`
   - `encryptionStream`
   - `queue`
2. A higher-level controller class at `0x1001adb30` owns:
   - `pairingActorSystem`
   - `pairingActor`
   - `prePairingActorSystem`
   - `prePairingActor`
   - `pairingInfoMap`
   - `serverIdentity`
   - `client`
3. The `selfPairingIdentity` field in the pairing-browser object graph points
   at a four-field Swift struct at `0x1001adee4` with:
   - `deviceName`
   - `identifier`
   - `deviceIRKData`
   - `devicePublicKey`
4. A nearby nine-field Swift struct at `0x1001adf24` extends that same core
   identity with:
   - `contactIdentifier`
   - `contactImageData`
   - `dateAdded`
   - `givenName`
   - `familyName`
   - plus the same `deviceName` / `identifier` / `deviceIRKData` /
     `devicePublicKey`
5. Two nearby Objective-C class descriptors carry the remaining pairing-share
   material:
   - `0x1001adfa0`: `serverPublicKey`, `bonjourServiceID`
   - `0x1001adfc8`: `deviceName`, `givenName`, `familyName`, `pin`, `pake`,
     `createdAt`
6. The `pake` field above resolves to a seven-field Swift struct at
   `0x1001ad8dc`:

```text
context
clientIdentity
serverIdentity
password
contextData
clientIdentityData
serverIdentityData
```

That is important because it puts raw client/server identity blobs directly in
the PAKE-side pairing graph, rather than only in a late persistence step.

7. There are also two smaller pairing-side record types worth tracking:
   - `0x1001ad54c`: `identifier`, `found`, `hashData`, `authTagData`,
     `btAddressData`, `version`
   - `0x1001ad6c4`: `authTag`, `deviceName`, `serverIdentity`, `serviceName`

Those look like discovery / resolve-side records rather than persisted
identities.

Current consequence:

- We now have concrete pairing-side value layouts that carry
  `deviceIRKData` before `FUN_100124280` persists anything.
- The likely upstream source is no longer "some opaque pairing result"; it is
  more specifically the pairing identity structs above, plus the PAKE container
  that carries `clientIdentityData` / `serverIdentityData`.
- What still remains unresolved is the exact decode/translation path that turns
  those PAKE-side identity blobs into the four-field or nine-field identity
  structs and then feeds the shared save dispatcher.

One caution: this metadata work does not yet prove which exact top-level return
wrapper corresponds to `RPPairingIdentity` versus
`RPPairingTemporaryIdentity`, nor does it fully explain the 64-byte actor
return-value copies seen in the async paths. It does prove that the pairing-side
graph already has explicit `deviceIRKData`-carrying identity values upstream of
the ad-hoc persistence layer.

### Pairing return and temp-identity call graph

Headless string xrefs and direct caller xrefs now pin the main branches to a
small set of concrete functions:

- `FUN_1000d1d60`
  - logs `No remote identity received from pairAndReceiveIdentity`
  - logs `Saving remote identity: %s`
  - tail-jumps into the shared single-record save dispatcher
    `FUN_100124280`
- `FUN_1000efee0`
  - logs `Pairing SUCCESS, returning self identity`
  - stays on the self/shared-identity branch
- `FUN_1000f0f20`
  - logs `Saving shared identity: %s`
  - tail-jumps into the same shared single-record save dispatcher
    `FUN_100124280`
- `FUN_1000ffb40`
  - logs `Pairing SUCCESS, returns temporary self identities`
  - does **not** jump straight into `FUN_100124990`
  - instead tail-jumps into `FUN_10013b7b0`

The direct caller map for the shared save dispatcher is now explicit:

```text
FUN_1000d1d60 -> FUN_100124280
FUN_1000f0f20 -> FUN_100124280
```

and the temporary-identity success branch feeds:

```text
FUN_1000ffb40 -> FUN_10013b7b0
```

with two additional callers into `FUN_10013b7b0` at `FUN_1000d0990` and
`FUN_1000d11c0`.

The important consequence is that the temp-identity path is not "pairing
success -> add temporary identity" in one jump. There is an intermediate async
staging layer first.

### What the temp-identity staging layer does

On arm64e, the `FUN_1000ffb40` continuation stores the temporary return payload
in task state at `+0x208` and then resumes into the next async stage. That next
stage:

- checks whether the returned temporary-identity collection is empty
- moves it into task state at `+0x158`
- begins access on a peer-owned collection at `peer + 0x88`
- compares/filters against existing `identity share handles`
- logs `Needs identity share handles -  %s`

So the temp-identity success branch is first turned into a handle-selection /
share-preparation step before the add-or-update path runs.

The x86_64 string xref for that handle-selection log lands in
`FUN_10010a6b0`, which then continues deeper into the share-preparation flow
via `FUN_100134f60`.

One useful detail from the x86_64 disassembly is that the helper
`FUN_1001101a0` is not a direct persistence step either. It walks the
peer-owned collection passed in from `peer + 0x88`, iterates its hashed storage
bucket-by-bucket, and calls `FUN_10010f6f0` for each retained key/value pair.
So this helper is a set/dictionary transform over existing `identity share
handles`, not the `RPIdentity(type=15)` constructor path.

### The `FUN_100134f60` branch is a sync-session / monitor path

The next x86_64 continuations after `FUN_10010a6b0` are now clearer:

- `___lldb_unnamed_symbol5803` (`0x100135430`)
  - constructs a new record with a `Foundation.Date.init()`
  - zeroes additional fields
  - stores that record back through `___lldb_unnamed_symbol5796`
  - spawns a new async task rather than tail-jumping into
    `FUN_100124990`
- `___lldb_unnamed_symbol5804` (`0x1001356c0`)
  - logs `Activating RPIdentitySyncPathMonitor`
  - calls `Network.NWPathMonitor.start(queue:)`
  - stores the resulting task in monitor state at `+0x80`
- `___lldb_unnamed_symbol5810` (`0x100135e00`)
  - resumes from that monitor path
  - looks up an existing session in the monitor's `sessions` table
  - logs `Sending analytics event for %s`
  - computes additional per-session state via `FUN_100134860`
- `___lldb_unnamed_symbol5813` (`0x1001364b0`)
  - bridges a boolean under the key `reachable`
  - logs metrics under `"ServiceDiscovery"` via `CUMetricsLog`
  - writes the updated session back through `___lldb_unnamed_symbol5796`
- `___lldb_unnamed_symbol5814` (`0x100136720`)
  - when no sessions remain, calls `___lldb_unnamed_symbol5833`
- `___lldb_unnamed_symbol5833` (`0x100137ee0`)
  - logs `Invalidating RPIdentitySyncPathMonitor`
  - clears the monitor's `reachable` flag
  - cancels the `NWPathMonitor`
  - cancels/releases the outstanding monitor task

Direct caller xrefs line up with that structure:

```text
FUN_100135a30 -> FUN_100135e00
FUN_100135f10 -> FUN_100134860
FUN_100136720 -> FUN_100137ee0
```

Field metadata from the matching session/monitor classes also fits this branch:

- one class has fields:
  `sessions`, `sessionDuration`, `pathMonitor`, `identitySyncCache`
- a sibling monitor class has fields:
  `reachable`, `pathMonitor`, `pathUpdateTask`, `queue`

So the traced `FUN_10010a6b0 -> FUN_100134f60 -> ...` path is a sync-session
and path-monitor state machine. It updates per-session bookkeeping and metrics,
and it tears down the monitor when the session map empties.

The important correction is that this still does **not** give a direct call
chain into `FUN_100124990` or `FUN_10012a300`. The add/update constructor path
and the eventual sync-cache write path remain elsewhere in the async graph,
likely on a sibling continuation such as the path-update task or a separate
"add additions then store cache" stage.

### The cache object is now identified explicitly

Field metadata now identifies the `identitySyncCache` class itself. It is a
small actor-backed NSObject subclass with exactly two stored fields:

- `cachedInfo`
- `stagedVerifiedPeerIRKDataSet`

The x86_64 constructor `___lldb_unnamed_symbol5614` (`0x10012b700`) matches
that layout:

- it zero-initializes a 24-byte value at `+0x70 / +0x78 / +0x80`
- it initializes an empty bridged set at `+0x88`

The matching destroy path `___lldb_unnamed_symbol5616` (`0x10012b7d0`) releases
that same 24-byte `cachedInfo` triple via `FUN_10012ba20` and then releases the
bridged set at `+0x88`.

This means the core cache state is now concrete:

```text
identitySyncCache
  +0x70/+0x78/+0x80  cachedInfo
  +0x88              stagedVerifiedPeerIRKDataSet
```

The surrounding owner graph is also tighter. The larger actor-backed class with
fields:

- `sessionTelemetry`
- `identitySyncCache`

constructs both side objects during initialization:

- `FUN_10010e980` creates the telemetry/session side via `FUN_100138080`
- then creates the cache side via `FUN_10012b700`

### Temp sync cache persistence

The later temp-identity sync path is now clearer as well.

`FUN_10012a300` is the x86_64 function that logs:

- `Updating sync cache with %ld additions`
- `No staged changes, skipping cache store`
- `Storing sync cache to URL %s`
- `Failed to store sync cache %@`

The corresponding arm64e path we disassembled:

- checks for `Missing protected container`
- checks for `Missing cached sync info`
- logs `No staged changes, skipping cache store`
- builds a cache URL with `appendingPathComponent(...)`
- appends a `.plist` extension
- encodes the sync-cache object with `Foundation.PropertyListEncoder`
- writes it with `Foundation.Data.write(to:options:)`
- logs either:
  - `Storing sync cache to URL %s`
  - `Failed to store sync cache %@`

The x86_64 disassembly now lets us tighten that description further:

- `FUN_10012a300` begins by loading `identitySyncCache.cachedInfo` from
  `+0x70 / +0x78 / +0x80`
- if the final word is null, it logs `Missing cached sync info`
- later it begins access on `identitySyncCache.stagedVerifiedPeerIRKDataSet` at
  `+0x88`
- if that set is empty and no override flag is set, it logs
  `No staged changes, skipping cache store`
- otherwise it logs `Updating sync cache with %ld additions`, appends a cache
  path component, appends `.plist`, encodes with
  `Foundation.PropertyListEncoder`, and writes the result with
  `Foundation.Data.write(to:options:)`

So the broader temporary-identity flow is not just in-memory bookkeeping. It
does maintain an on-disk property-list sync cache after the protected-container
stage, and we now know that the staged input to that write is specifically the
`stagedVerifiedPeerIRKDataSet` on the `identitySyncCache` object. The
previously traced `FUN_10010a6b0 -> FUN_100134f60 -> ...` branch remains the
monitor/session side, not the direct cache-store call chain itself.

### The corresponding load, membership, and stage functions are now visible

The 24-byte `cachedInfo` payload is no longer opaque. Swift field metadata now
identifies it as a two-field struct:

- `selfDeviceIRKData`
- `verifiedPeerIRKDataSet`

There is also a sibling two-case enum/coding-key record with those same field
names. That matches the x86_64 decode tail in `FUN_100129180`:

- it first checks whether `identitySyncCache.cachedInfo` is already present
- if not, it runs through the same protected-container gate used by
  `FUN_10012a300`
- it constructs the same cache path and `.plist` extension
- it logs `Loading sync cache from URL %s`
- it reads the plist with `Foundation.Data.init(contentsOf:options:)`
- it constructs `Foundation.PropertyListDecoder`
- it resolves the witness table via `FUN_10012bcb0`
- it decodes that specific `Decodable` cached-info struct
- on success, it swaps the decoded 24-byte value into
  `identitySyncCache.cachedInfo` at `+0x70 / +0x78 / +0x80`, releases the old
  value via `FUN_10012ba20`, and schedules the follow-on continuation
  `FUN_1001298c0 -> FUN_100129920`

That continuation is also now visible. `FUN_100129920` logs
`Sync cache initialized` on its first-load branch after the decoded
`cachedInfo` value has been installed.

`FUN_100129b20` needed a correction. It is **not** the stage/update routine.
It is the membership test behind the identity-share decision:

- concrete caller: `FUN_10010db90 -> FUN_100129b20`
- `FUN_10010db90` passes the candidate peer IRK pair from its async frame at
  `+0x218 / +0x220`, stores the returned bool at `+0x5a`, and then chooses
  between:
  - `Identity was previously synced with peer %@ - no identity share needed`
  - `Identity not synced with peer %@ - needs identity share`
- inside `FUN_100129b20`, hidden `self` is the `identitySyncCache` object
- if no peer IRK is present, it logs `Missing peer IRK data`
- if `cachedInfo` is absent, it logs `Missing cached sync info`
- otherwise it loads:
  - `cachedInfo.selfDeviceIRKData` from `+0x70 / +0x78`
  - `cachedInfo.verifiedPeerIRKDataSet` from `+0x80`
  - the mutable `identitySyncCache.stagedVerifiedPeerIRKDataSet` from `+0x88`
- it then tests the candidate peer IRK against:
  - the staged set first
  - the persisted `verifiedPeerIRKDataSet` second
- it returns that membership result as the "already synced" bool

The actual staged-set mutator is the sibling `FUN_100129e60`:

- concrete caller: `FUN_100136e40 -> FUN_100129e60`
- it logs `Staging verified known peer IRK %s`
- it performs write access on `identitySyncCache.stagedVerifiedPeerIRKDataSet`
  at `+0x88`
- that is the real "add verified peer IRK into the staged set" path

The helper/xref pattern is now clearer:

- `FUN_100129180` and `FUN_10012a300` both call
  `FUN_10012ba50` and `FUN_1001053b0` before the protected-container check
- `FUN_100129180`, `FUN_100129b20`, and `FUN_10012a300` all use
  `FUN_10012ba20` for the shared cached-info release path

That gives a corrected sync-cache lifecycle:

```text
load plist into cachedInfo                      -> FUN_100129180
test whether peer IRK is already known/synced  -> FUN_100129b20
stage verified known peer IRK into staged set  -> FUN_100129e60
store staged additions back to plist           -> FUN_10012a300
```

So the verified-peer/auth-tag side is now split into two grounded branches:

```text
FUN_10010db90  -> FUN_100129b20   (membership test / share decision)
FUN_100136e40  -> FUN_100129e60   (stage verified known peer IRK)
```

### The staged-IRK path is owned by `sessionTelemetry`

The next structural link is now grounded by the x86_64 constructor
`FUN_100138080`, which matches the earlier field-metadata descriptor for the
`sessionTelemetry` class:

- `+0x70` = `sessions`
- `+0x78` = `sessionDuration`
- `+0x80` = `pathMonitor`
- `+0x88` = weak `identitySyncCache`

The constructor writes exactly that shape:

- `0x70` gets the empty sessions bridge object
- `0x78` gets `0x4024000000000000` (`10.0`) as the default session duration
- `0x80` gets a newly constructed monitor helper from `FUN_1001381f0`
- `0x88` is initialized with `swift_weakInit`

The helper object built by `FUN_1001381f0` also matches the earlier monitor
field metadata:

- `+0x70` = `reachable` (initialized to `0`)
- `+0x78` = `NWPathMonitor`
- `+0x80` = `pathUpdateTask` (initialized to `0`)
- `+0x88` = dispatch `queue`

That makes the staging call chain more concrete.

`FUN_100136b80` and `FUN_100136ea0` are both `sessionTelemetry`-owned async
continuations:

- both build a transformed bridge object from `sessionTelemetry.sessions`
  at `+0x70` via `FUN_10013a400`
- both iterate that transformed hashed collection
- both classify each entry through `FUN_1001371e0`

`FUN_100136b80` adds one important fast path:

- it only enters when a frame-local mode word equals `6`
- it attempts `swift_weakLoadStrong(sessionTelemetry + 0x88)`
- when that weak `identitySyncCache` resolves, it stores the strong reference
  in the async frame and tail-resumes into `FUN_100136e40`
- `FUN_100136e40` then calls `FUN_100129e60`, i.e. the actual
  `Staging verified known peer IRK %s` mutator

So the corrected ownership chain is:

```text
sessionTelemetry
  sessions (+0x70)
    -> FUN_10013a400
    -> FUN_1001371e0

sessionTelemetry
  weak identitySyncCache (+0x88)
    -> FUN_100136b80
    -> FUN_100136e40
    -> FUN_100129e60
```

This is useful because it narrows the producer-side story further. The
verified-known-peer IRK is not being staged from an isolated pairing callback.
It is being staged from the `sessionTelemetry` side, which owns both:

- the per-peer `sessions` state machine
- the weak link to `identitySyncCache`

Current inference: the missing upstream source is likely on the
`sessionTelemetry.sessions` / `FUN_1001371e0` branch, not in the raw cache
helpers anymore.

### The per-peer session record is now typed, and `FUN_1001371e0` is its updater

Offline Swift field metadata now identifies the concrete per-peer record that
`sessionTelemetry.sessions` is iterating. The matching descriptor is a
10-field struct with:

- `btAddressData`
- `handles`
- `sessionStart`
- `identityAdded`
- `firstIdentitySource`
- `firstIDSIdentityDate`
- `firstLocalIdentityDate`
- `idsIdentityCount`
- `localIdentityCount`
- `otherIdentityCount`

That makes the `FUN_1001371e0` branch substantially less opaque.

`FUN_1001371e0` does not mutate a few loose counters in place. It copies the
current record through `FUN_100139850`, updates that copied struct, then writes
the result back into the `sessionTelemetry.sessions` map through
`FUN_100134ae0`.

The x86_64 control flow now supports this concrete update model:

- force `identityAdded = true`
- if `firstIdentitySource == 0`, store the incoming source/state code
- if the incoming state is `2`, increment the local counter and populate the
  first-local date if it was still empty
- if the incoming state is `3`, increment the IDS counter and populate the
  first-IDS date if it was still empty
- otherwise, increment the `otherIdentityCount` branch only

The `2` vs `3` meaning is grounded by the paired date helpers used by the
stringifier:

- `FUN_1001345c0` computes the `firstLocalIdentityMS` value from the same date
  slot updated by the `state == 2` branch
- `FUN_100134710` computes the `firstIDSIdentityMS` value from the same date
  slot updated by the `state == 3` branch

So the updater logic is now:

```text
existing session record
  -> clone via FUN_100139850
  -> set identityAdded
  -> preserve firstIdentitySource once set
  -> state 2: local count/date
  -> state 3: IDS count/date
  -> else: other count
  -> store updated record via FUN_100134ae0
```

This matters because the staged verified-peer IRK path now has a much tighter
producer-side shape:

```text
sessionTelemetry.sessions
  -> FUN_1001371e0
     -> per-peer record with source + first-date + count state
  -> FUN_100136b80 / FUN_100136ea0
     -> mode 6 fast path
     -> FUN_100136e40
     -> FUN_100129e60
```

The next missing piece is upstream of this updater: what concrete event or
handle state produces source/state codes `2`, `3`, and the `other` branch in
the first place.

### The upstream entry is `logIdentityUpdateWithHandle:deviceIRKData:type:source:completionHandler:`

The next upstream semantic name is now grounded as well. Headless Ghidra xrefs
resolved `FUN_100137970` to:

```text
logIdentityUpdateWithHandle:deviceIRKData:type:source:completionHandler:
```

That fixes the meaning of the two integer lanes carried through the async
worker:

- `FUN_100136b00 + 0x68` is the update `type`
- `FUN_100136b00 + 0x6c` is the update `source`

This matters because the earlier `FUN_100136b80` fast-path check is therefore
*not* looking at the local/IDS source code. It is specifically checking
`type == 6` before entering the `identitySyncCache` staging branch.

The `source` lane is the one later forwarded into `FUN_1001371e0`, where it
becomes the now-grounded:

- `source == 2` -> local
- `source == 3` -> IDS
- otherwise -> other

The call/bridge chain is now:

```text
logIdentityUpdateWithHandle:deviceIRKData:type:source:completionHandler:
  -> FUN_100137970
  -> async worker FUN_100136b00
     -> type gate at +0x68
     -> source/state forwarded at +0x6c
     -> FUN_1001371e0
```

There is also an ObjC bridge thunk directly above that worker:

- `FUN_100137ae0` converts optional `NSString` / `NSData` inputs into Swift
  `String` / `Data`
- then tail-jumps into `FUN_100136b00` with the same `type` and `source`
  integer lanes intact

So the producer-side question is narrower now. We are no longer chasing a
generic anonymous counter path. This is specifically an identity-update path
parameterized by:

- a `handle`
- a `deviceIRKData`
- an update `type`
- an update `source`

Related string inventory around this path also contains:

- `Known type5 peer detected - starting sync cache session`
- `No more remaining known type5 peers - ending sync cache session`
- `Received friend identity update: from '%{mask}', IDS '%.8@'`
- `Received family identity update: from '%{mask}', IDS '%.8@'`

That does not yet prove the exact caller for `FUN_100137970`, but it does make
the surrounding subsystem much more specific: the sync-cache / staged-IRK path
is being driven by higher-level identity-update events, not just by a raw peer
transport observer.

### The type-6 identity-update path and the type5 peer-session path converge only at `identitySyncCache`

The x86_64 selector xref set is tighter now.

`_updateIdentityType:idsDeviceID:appleID:contactID:sendersKnownAlias:msg:source:`
still looks like the direct semantic producer for
`logIdentityUpdateWithHandle:deviceIRKData:type:source:completionHandler:`.
At `0x1000a8f54`, it sends that selector with:

- `handle` from `-0x58(%rbp)`
- `deviceIRKData` from the object returned into `r14`
- `type` from `-0x5c(%rbp)`
- `source` from the incoming `0x20(%rbp)` lane

In the current selector-xref pass, that is the only direct selector use that
showed up for `logIdentityUpdateWithHandle:deviceIRKData:type:source:completionHandler:`.
Combined with the earlier type decoding in `_updateIdentityType...`, the
fast-path check in `FUN_100136b80` is now consistent with a concrete semantic
reading:

- `type == 4` -> `Family`
- `type == 6` -> `Friend`
- only `type == 6` enters the `identitySyncCache` staging fast path

That is a useful correction to the mental model. The staged verified-peer IRK
path is not being entered by an anonymous "mode 6" from nowhere. It is reached
through a named identity-update API, and the known direct producer we have in
hand is the friend/family identity-update path.

The `Known type5 peer detected - starting sync cache session` branch is a
different producer path.

`FUN_10010bdb0` still starts from the "known device peer" set transition, but
the x86_64 bootstrap path is now clearer:

- it updates the known-peer set
- if the transition is from zero peers to non-zero peers, it logs
  `Known type5 peer detected - starting sync cache session`
- it reads an `NSData` from the peer-owned object at `0x80(%rbx)` via
  `objc_msgSend`
- it bridges that into `Foundation.Data`
- it stores that bridged peer IRK into the async task frame
- it tail-jumps into `FUN_100128e00`

`FUN_100128e70` is the first async stage of that bootstrap. It does not yet
stage the peer IRK. It first requires self IRK material:

- if self IRK is unavailable, it logs `Missing self IRK` and returns
- otherwise it continues into `FUN_100129060`

So the type5 peer-session start path is:

```text
known type5 peer add
  -> FUN_10010bdb0
  -> peer IRK bridged from peer-owned NSData
  -> FUN_100128e00
  -> FUN_100128e70
     -> require self IRK
     -> FUN_100129060
```

The removal / teardown side is now visible too.

`FUN_10012b0c0` is the mirrored async entry on the removal side:

- it also logs `Missing self IRK` if the self side cannot be loaded
- on success it tail-jumps into `FUN_10012b2f0`

`FUN_10012b2f0 -> FUN_10012b360` is the actual teardown worker. That branch:

- compares the current cached self identity state
- computes whether there was a self-identity change and whether the cache is empty
- logs
  `Clearing cached info - selfIdentityChange: %{bool}d cacheEmpty: %{bool}d force: %{bool}d`
- resets `identitySyncCache.cachedInfo` at `+0x80`
- resets `identitySyncCache.stagedVerifiedPeerIRKDataSet` at `+0x88`
- then tail-jumps into `FUN_10012a1c0`

That matters because it closes the symmetry around the cache object:

- `FUN_100129e60` stages a verified peer IRK into the set at `+0x88`
- `FUN_10012b360` clears both the cached info blob and that staged set again

So the current producer model is no longer one guessed linear chain. It is two
adjacent paths that converge on the same cache:

```text
friend / family identity updates
  -> _updateIdentityType...
  -> logIdentityUpdateWithHandle...
  -> sessionTelemetry
  -> type == 6 fast path
  -> FUN_100129e60

known type5 peer add / remove
  -> FUN_10010bdb0 / FUN_10012b0c0
  -> self IRK + peer IRK session bootstrap / teardown
  -> FUN_100129060 / FUN_10012b2f0
  -> identitySyncCache.cachedInfo / stagedVerifiedPeerIRKDataSet
```

The remaining open question is therefore narrower again. We no longer need to
ask whether the type5 session path and the friend-update path are the same
branch. They are not. The next useful target is where `FUN_100129060` stages or
shares identities after the self-IRK gate, and whether that path consumes the
same peer IRK values that later appear in `FUN_100129e60`.

## Pairing broker XPC shape

A new bounded probe against the pairing mach service tightened the unsigned
macOS bootstrap path again.

First, a raw XPC reachability check with a minimal message showed that the
broker names are real and not just string-table artifacts:

- `com.apple.rapport.RPPairing`
- `com.apple.PairingManager`
- `com.apple.CompanionLink`
- `com.apple.rapport`

all returned `XPC_ERROR_CONNECTION_INTERRUPTED`, while a bogus service name
returned `XPC_ERROR_CONNECTION_INVALID`. So those services are present and
reachable from an ordinary process, even though a nonsense payload is rejected.

An injected NSXPC tracer then recovered the exact Apple-side shape used by
`Rapport.RPPairingReceiverController.start`:

```text
NSXPCConnection initWithMachServiceName service=com.apple.rapport.RPPairing
NSXPCConnection setExportedInterface <NSXPCInterface ...>
NSXPCConnection setExportedObject <Rapport.RPPairingReceiverController ...>
NSXPCConnection setRemoteObjectInterface <NSXPCInterface ...>
proxy selector=startPairingReceiverController:
  arg0 = <Rapport.RPPairingReceiverController ...>
```

Two details matter:

- the service is the mach service `com.apple.rapport.RPPairing`
- the start call passes the real `Rapport.RPPairingReceiverController` instance
  itself, not a custom callback object, not `nil`, and not a block

The same trace did **not** show any extra:

- `NSXPCInterface setInterface:forSelector:argumentIndex:ofReply:`
- `NSXPCInterface setClasses:forSelector:argumentIndex:ofReply:`

for this controller path. Apple's helper keeps the wiring simple.

A matching unsigned probe confirmed the consequence:

- custom callback objects with extra `setInterface:` / `setClasses:` hints made
  `com.apple.rapport.RPPairing` interrupt the connection immediately
- mirroring Apple's exact shape kept the connection alive after
  `startPairingReceiverController:` and only invalidated when the probe itself
  called `invalidate`

So there is now a real unsigned broker path on macOS:

```text
ordinary process
  -> NSXPCConnection("com.apple.rapport.RPPairing")
  -> exportedObject = real RPPairingReceiverController
  -> remoteObjectProxy startPairingReceiverController(controller)
  -> broker stays up
```

This does not yet produce a pairing PIN or a trust record by itself. It still
needs an incoming initiator on the other side. But it moves the bootstrap
problem one level higher than “can an unsigned helper even talk to the pairing
broker?” The answer is now yes, if it mirrors the controller object shape
exactly.

## Pairing broker vs pairing listener

A same-host control run tightened the macOS bootstrap picture again.

The setup on `endor` was:

```sh
/tmp/rppairing-xpc-probe 60 controller visible

result/bin/macolinux-continuity-inspect \
  nw-appsvc-listen-pairing \
  com.apple.universalcontrol com.apple.universalcontrol 123456 60
```

The listener advertised a fresh temporary pairing actor:

```text
listener advertised add endpoint=app_svc: com.apple.universalcontrol,
  service_id: F3E37D13-37AE-433A-B7CD-F4801C16A293
```

Then a local actor call to `_appSvcPrePair._tcp` triggered the known pairing
method:

```sh
TARGET='$s8rapportd25RPPairingDistributedActorC22exchangePAKEIdentities14clientIdentity10deviceName05givenJ006familyJ0S2S_S2SSgAItYaKFTE'
PAYLOAD="remote-call:<uuid>|RPPairingDistributedActor|F3E37D13-37AE-433A-B7CD-F4801C16A293|$TARGET|0|arg-json-string:fistel|arg-json-string:fistel|arg-json-string:fbettag|arg-json-string:linux"

result/bin/macolinux-network-actor-framer-probe \
  connect-service endor _appSvcPrePair._tcp local. 12 \
  3 0 "$PAYLOAD" tls stack actor
```

That local call succeeded at the actor transport level:

```text
connection state=ready
send complete bytes=278
recv actorType=4 actorOptions=15
recv 90 bytes: ...
recv complete
```

`rapportd` simultaneously confirmed that this was a real pairing-side state
transition, not just a transport echo:

```text
Start pairing receiver controller from <private>
LISTEN: Setting pin on local endpoint for pairing listener.
LISTEN: Successfully activated pairing server.
Starting advertising for pairing session with server identity: <private>
Starting advertising for pre-pairing session with server identity: <private>
New pairing info generated: <private>
LISTEN: Updated PIN info: {"903096":["fbettag","linux","fistel"]}
RESOLVE: PINs Changed - calling browseResponse ... updatedEndpoint:
  [0 - app_svc: com.apple.universalcontrol,
   service_id: F3E37D13-37AE-433A-B7CD-F4801C16A293 ...]
```

However, the live `com.apple.rapport.RPPairing` controller probe still observed
no callback traffic:

- `rppairing-xpc-probe` printed no `controller callback pairingValueUpdated ...`
- the same run ended with `pairing events observed: 0`
- an `nsxpc-trace`-instrumented `rp-pairing-listen` helper showed only the
  startup `startPairingReceiverController:` call and no additional remote proxy
  selector traffic during the PIN update

So the useful correction is:

- `exchangePAKEIdentities(...)` over `_appSvcPrePair._tcp` really does generate
  PIN state in `rapportd`
- but that PIN update does **not** come back through the
  `RPPairingReceiverController` callback path we have probed so far

This means the unsigned `com.apple.rapport.RPPairing` controller connection is
real but is not, by itself, the consumer path for the temporary pairing PIN
updates triggered by the actor listener flow.

The cross-device leg is still weaker than the same-host control. A fresh remote
attempt from `bespin` with the full actor payload:

```text
/tmp/macolinux-network-actor-framer-probe \
  connect-service endor _appSvcPrePair._tcp local. 12 \
  3 0 'remote-call:...|RPPairingDistributedActor|E170EB71-...|...' \
  tls stack actor awdl0
```

kept the correct payload intact but stalled at:

```text
required interface=awdl0
connection state=preparing
timeout/cancel
```

So the current split is now clear:

- same-host actor initiation works and produces real PIN state
- the `RPPairing` broker does not expose that state through the controller path
  we mirrored
- the cross-device AWDL browse/connect leg is still not consistently promoted
  enough to reach `ready`

The next target should therefore move one layer away from
`RPPairingReceiverController` and toward the process actually owning the pairing
state machine and remote-device discovery path.

## PairingManager XPC shape

The next layer is now much less ambiguous.

First, the raw mach-service probe result from `com.apple.PairingManager` was
real and attributable, not just another string-table coincidence. A minimal
`xpc_connection_send_message_with_reply` probe produced `XPC_ERROR_CONNECTION_INTERRUPTED`,
and `rapportd` logged the incoming peer connection plus a Foundation XPC decode
error for that exact mach service:

```text
activating connection: ... name=com.apple.PairingManager.peer[...]
connection from pid ... on mach service named com.apple.PairingManager:
  received an undecodable message ...
```

So `com.apple.PairingManager` is handled by `rapportd`.

Runtime protocol enumeration and Objective-C introspection then recovered the
real PairingManager NSXPC surface:

- exported callback protocol: `CUPairingManagerXPCInterface`
- remote daemon protocol: `CUPairingDaemonXPCInterface`

`CUPairingDaemonXPCInterface` methods:

```text
deletePairingIdentityWithOptions:completion:
getPairedPeersWithOptions:completion:
showWithCompletion:
getPairingIdentityWithOptions:completion:
savePairedPeer:options:completion:
removePairedPeer:options:completion:
startMonitoringWithOptions:
findPairedPeer:options:completion:
```

`CUPairingManagerXPCInterface` callback methods:

```text
pairingIdentityCreated:options:
pairingIdentityDeletedWithOptions:
pairedPeerRemoved:options:
pairedPeerAdded:options:
pairedPeerChanged:options:
```

Tracing Apple's own `CUPairingManager` wrapper with `nsxpc-trace` confirmed the
exact connection shape:

```text
NSXPCConnection initWithMachServiceName service=com.apple.PairingManager
NSXPCConnection setExportedInterface <NSXPCInterface ...>
NSXPCConnection setExportedObject <CUPairingManager ...>
NSXPCInterface setClasses { NSArray, CUPairedPeer } for
  getPairedPeersWithOptions:completion: argumentIndex=0 ofReply=true
NSXPCConnection setRemoteObjectInterface <NSXPCInterface ...>
NSXPCConnection remoteObjectProxyWithErrorHandler
  -> __NSXPCInterfaceProxy_CUPairingDaemonXPCInterface
```

That was enough to build a direct unsigned probe at
`research/tools/pairingmanager-xpc-probe.m` that mirrors the wrapper setup
without going through `CUPairingManager` convenience methods.

The direct results matter:

- `getPairingIdentityWithOptions:` returns server-side
  `kMissingEntitlementErr`
- `getPairedPeersWithOptions:` returns server-side
  `kMissingEntitlementErr`
- `startMonitoringWithOptions:` is also server-side gated with
  `com.apple.PairingManager.Read`

`rapportd` now says this explicitly:

```text
### pairingmanager-xpc-probe:<pid> lacks 'com.apple.PairingManager.Read'
    entitlement to use GetPairingIdentity
### GetPairingIdentity failed: -71168/0xFFFEEA00 kMissingEntitlementErr
### pairingmanager-xpc-probe:<pid> lacks 'com.apple.PairingManager.Read'
    entitlement to use GetPairedPeers
### pairingmanager-xpc-probe:<pid> lacks 'com.apple.PairingManager.Read'
    entitlement to use StartMonitoring
```

So the important correction is that the PairingManager barrier is not a wrapper
artifact. Even a correctly shaped direct NSXPC client still hits the same
server-side entitlement gate.

One subpath remains interesting:

- malformed `showWithCompletion:` calls still trigger a `CUPairingDaemon State`
  dump inside `rapportd`
- the server reports our current reply-block signature as incompatible, so that
  method likely has a richer block shape than the naive probe used so far

Even without perfecting `showWithCompletion:`, the main conclusion is already
stronger: direct PairingManager XPC does not bypass the trust barrier, and the
`com.apple.PairingManager.Read` entitlement is enforced in `rapportd` itself.

## sharingd.nsxpc: unlock vs companion service

The `Sharing` authentication stack below `SFAuthenticationManager` is now
partially mapped from runtime rather than guessed from class names.

Using `research/tools/autounlock-probe.m` against `SFAutoUnlockManager` showed:

- `eligibleAutoUnlockDevicesWithCompletionHandler:` never replied within a
  bounded 6 second run
- `authPromptInfoWithCompletionHandler:` returned
  `SFAutoUnlockErrorDomain Code=111`
- `autoUnlockStateWithCompletionHandler:` returned the same Code 111
- `attemptAutoUnlock` produced no delegate callbacks in a bounded 8 second run

The daemon-side reason is explicit in `sharingd`:

```text
Client (...) does not have unlock manager entitlement
```

That matches a lower-level `nsxpc-trace` run. `SFAutoUnlockManager` creates an
`NSXPCConnection` to `com.apple.sharingd.nsxpc`, uses
`SFCompanionXPCManagerProtocol`, and reaches a returned unlock proxy described
by `SFUnlockProtocol`. The relevant protocol names are now grounded from live
`NSXPCInterface` descriptions:

- `SFCompanionXPCManagerProtocol`
- `SFUnlockProtocol`
- `SFUnlockClientProtocol`
- `SFAuthenticationStateChangesObserverProtocol`

The useful correction is that this branch is not blocked on unknown call shape
anymore. It is blocked on the server-side unlock-manager entitlement itself.

The sibling companion-service branch is more permissive.

`research/tools/companion-service-probe.m` can now describe and exercise the
interfaces exported by `SFCompanionXPCManager`:

- `SFCompanionServiceManagerProtocol`
  - `enableService:`
  - `disableService:`
- `SFCompanionServiceManagerClient`
  - `streamToService:withFileHandle:acceptReply:`

From an unsigned process, `serviceManagerProxyForIdentifier:client:withCompletionHandler:`
returns a live `_NSXPCDistantObject` for both:

- `com.apple.universalcontrol`
- `com.apple.CompanionAuthentication`

Calling `enableService:` with an `SFCompanionService` built from the same
identifier succeeds without an immediate entitlement error. While the probe is
alive, `sharingd` logs:

```text
Client '<private>' lacks device name entitlement
Added service to publisher <private> with identifier <private>
```

When the short-lived probe exits immediately, `sharingd` then removes stream
support and invalidates the client connection. Holding the probe open keeps the
publisher entry alive for the lifetime of the process.

One more local control check matters. While a held-open
`com.apple.CompanionAuthentication` publication was active through
`SFCompanionServiceManagerProtocol.enableService:`, both of these stayed empty:

- `result/bin/macolinux-continuity-inspect nw-appsvc-browse
  com.apple.CompanionAuthentication com.apple.universalcontrol 4`
- `result/bin/macolinux-network-endpoint-c-probe browse-appsvc-bundle
  com.apple.CompanionAuthentication com.apple.universalcontrol 4 ...`

Both browsers reached `ready` and then timed out or cancelled without surfacing
an endpoint. So the companion-service publisher path is real, but it is not
equivalent to a generic browseable `NWBrowser` application-service endpoint in
the current unsigned context.

This changes the boundary:

- the unlock/authentication branch is gated by unlock-manager entitlement
- the companion-service branch is reachable and can publish a service from an
  unsigned helper

That does **not** prove the published service is sufficient for Universal
Control bootstrap, but it is the first Apple-side `sharingd` broker we have
that accepts an unsigned service publication request instead of rejecting it
outright.

Pushing that branch further exposed a separate stream-request path that is not
the same as generic Network.framework application-service browsing.

`SFCompanionService.messageData` is a binary plist dictionary. For a bare
service it contains:

```text
message_version = 1
author_data = <binary plist>
```

The nested `author_data` plist contains at least:

```text
client_id = com.apple.CompanionAuthentication
unique_id = <SFCompanionService UUID>
```

When the probe also fills `managerID`, `deviceName`, `deviceID`, `ipAddress`,
and `nsxpcVersion`, `messageData` gains a top-level `bonjour_name`. Passing the
decoded dictionary, not the raw `NSData`, into
`SFCompanionXPCManager streamsForMessage:withCompletionHandler:` makes
`sharingd` resolve:

```text
<bonjour_name>._continuity._tcp.local
```

This was confirmed by `tcpdump` while running the loopback probe:

```text
PTR (QM)? _continuity._tcp.local.
SRV (QM)? <bonjour_name>._continuity._tcp.local.
TXT (QM)? <bonjour_name>._continuity._tcp.local.
```

Advertising a synthetic service on the controller Mac makes `sharingd` connect
to it:

```sh
dns-sd -R UCSTREAMTEST _continuity._tcp local 55678
UC_BONJOUR_NAME=UCSTREAMTEST \
  /tmp/companion-service-probe loopback \
  com.apple.CompanionAuthentication \
  com.apple.CompanionAuthentication 8
```

With a plain TCP listener on port `55678`, the listener receives a TLS
ClientHello from `sharingd`. With a temporary self-signed `openssl s_server`,
the TLS handshake completes and then `sharingd` rejects the certificate chain:

```text
SSL Handshake DONE
SecTrustEvaluateWithError failed with error errSecMissingRequiredExtension
Client cert chain not trusted. SFAppleIDVerifyCertificateChainSync failed
Failed to evaluate certificate
```

So this path is now mapped through Bonjour, TCP, and TLS. The current boundary
is the AppleID/Continuity certificate chain, not socket setup.

`research/tools/appleid-identity-probe.m` tries the obvious local identity
route through `SFAppleIDClient`. As an unsigned helper it returns:

```text
account.class=nil
account.error=Error Domain=NSOSStatusErrorDomain Code=-6768 "kSecurityRequiredErr"
```

`sharingd` has the relevant private account, AuthKit, system-keychain, and
Continuity keychain access-group entitlements. Signing the probe ad-hoc with a
matching extracted entitlement set does not help; AMFI rejects the executable
before `main`:

```text
The file is adhoc signed but contains restricted entitlements
Code has restricted entitlements, but the validation of its code signature failed.
```

That rules out a normal macOS helper directly exporting the host's AppleID
Continuity TLS identity.

The obvious "Apple broker bridge" experiment was also run with `bespin` as the
requesting Mac. `endor` held an `enable-full` publication open for 120 seconds,
printed the exact `messageData` plist for that same `SFCompanionService`
instance, and `bespin` called `connect-b64` with that plist. `bespin` accepted
the message and started `sharingd`'s stream opener:

```text
Streams are being requested from service = <private>
Streams are being requested for bonjour name = <private>
Creating network streams
resolver:start_bonjour
Started net service browser
```

After 30 seconds it failed with:

```text
Stream handler closed with error = Error Domain=NSPOSIXErrorDomain Code=60
Error getting streams = Error Domain=NSPOSIXErrorDomain Code=60
```

`endor` logged only `Added service to publisher`; it did not receive
`streamToService:withFileHandle:acceptReply:` during the remote request. A
parallel `dns-sd -L ENDORUCTEST2 _continuity._tcp local` from `bespin` also did
not resolve a normal Bonjour service. The companion-service publisher therefore
keeps state inside `sharingd`, but it does not by itself advertise a
remote-resolvable `_continuity._tcp` listener for another Mac to open.

The missing publication gate has now been identified. `SDServiceManager
enableService:` only forwards the service to the singleton `SDStreamManager`.
`SDStreamManager addService:` calls `publish` immediately only when
`SFActivityMonitor.sharedMonitor.alwaysSendPayload` is true. That value is read
from the boolean preference key `AlwaysSendPayload` in `com.apple.Sharing`
first, then `com.apple.NetworkBrowser`.

Temporary test recipe:

```sh
defaults write com.apple.Sharing AlwaysSendPayload -bool true
killall sharingd || true
```

Then hold the publisher open and make the exported message use the actual
published Bonjour instance name:

```sh
UC_BONJOUR_NAME=e3a0d17e48fc \
  /tmp/companion-service-probe enable-full \
  com.apple.CompanionAuthentication \
  com.apple.CompanionAuthentication 60
```

The daemon then logs:

```text
Added service to publisher <private> with identifier <private>
Restarting publish timer
Publishing net service
```

and Bonjour resolves:

```text
e3a0d17e48fc._continuity._tcp.local. can be reached at
dcd1fb59-b456-4fa6-b052-983af85feda9.local.:8771
```

With that `bonjour_name` in the plist, `bespin` successfully opened a stream to
`endor`:

```text
connect.stream.fileHandle.class=NSConcreteFileHandle
connect.stream.error=nil
```

and `endor` received the service callback:

```text
client.streamToService count=1
client.stream.service.value=SFCompanionService (serviceType =
E08592B5-A8AD-43A6-B91C-1BEB1440ED05, managerID =
com.apple.CompanionAuthentication, identifier =
E08592B5-A8AD-43A6-B91C-1BEB1440ED05)
client.stream.accept=true
```

The returned `NSFileHandle`s are bidirectional byte streams. With
`UC_STREAM_WRITE=bespin-ping` on the requester and
`UC_STREAM_REPLY=endor-reply` on the publisher:

```text
connect.stream.write.bytes=11
connect.stream.read.utf8=endor-reply
client.stream.write.bytes=11
client.stream.read.utf8=bespin-ping
```

Clean the temporary preference after the test:

```sh
defaults delete com.apple.Sharing AlwaysSendPayload 2>/dev/null || true
killall sharingd || true
```

Current implication: a macOS-side bridge can now produce a real Apple-accepted
Continuity stream between Macs without exporting the AppleID TLS identity. This
does not itself make Linux a Universal Control peer, but it gives us a working
broker path: Linux can speak a simpler local protocol to a macOS helper, and the
helper can terminate or relay the Apple stream through `sharingd`.

2026-05-02 packaged relay verification:

- `macolinux-ucd relay listen --bind 127.0.0.1:4717 --send-text
  endor-relay-ready --echo` accepted the TCP side of the helper relay.
- `macolinux-uc-bootstrap companion-stream publish --probe
  /tmp/companion-service-probe --bonjour-name e3a0d17e48fc --relay
  127.0.0.1:4717 --seconds 70` published the service through `sharingd`.
- `bespin` connected with `/tmp/companion-service-probe connect-b64
  <publish-plist-b64> 12` and `UC_STREAM_WRITE=bespin-via-apple`.

Observed on the publishing Mac:

```text
client.stream.relay.connected=127.0.0.1:4717
client.stream.relay_to_stream.relay.closed.bytes=33
client.stream.stream_to_relay.relay.closed.bytes=16
```

Observed in the Rust relay:

```text
relay sent: ... utf8="endor-relay-ready"
relay recv: ... utf8="bespin-via-apple"
relay echo: ... bytes=16
```

Observed on `bespin`:

```text
connect.stream.read.utf8=endor-relay-readybespin-via-apple
```

Important implementation detail: the ObjC relay must duplicate both read and
write descriptors for the Apple stream and the TCP socket, and must retain the
`NSFileHandle` for the lifetime of both async pump blocks. Without that, the
relay-to-stream direction can fail with `Bad file descriptor` after the callback
returns.
