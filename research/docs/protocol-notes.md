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

`_clientPreAuthStart` constructs an object, logs `Send PreAuthRequest`, and
sends it through `_sendFrameType:unencryptedObject:` with frame type `0x0a`.
That confirms `0x0a` is an unencrypted OPACK pre-auth request.

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

For the observed `main` stream, the stream AEAD keys are therefore derived from
the PairVerify PSK with `ClientEncrypt-main` and `ServerEncrypt-main`.

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
