# bt-classic design

Status: M0-M4 done on rootcanal; the stack runs on the ESP32 itself through unmodified esp-radio and works with a real phone, and connects profiles on the phone itself (see Milestones); the dongle firmware is next. Written 2026-11-25 as research and proposal.

## Goal

A `no_std`, async (embassy-style) Bluetooth Classic (BR/EDR) host stack. The first consumer is aa-dongle on an original ESP32, which needs exactly this from Bluetooth:

1. Be discoverable and connectable (Class of Device, local name, EIR, scan enable).
1. Pair with a phone using Secure Simple Pairing, store the link key, and reconnect bonded without re-pairing.
1. Publish SDP records: the wireless Android Auto RFCOMM service (UUID `4de17a00-52cb-11e6-bdf4-0800200c9a66`) and an HSP headset (HS, `0x1108`) record that gets the phone to connect. aa-dongle's BlueZ code (`src/linux/bluetooth.rs`) registers the AA profile on RFCOMM channel 8.
1. Accept one RFCOMM channel and carry the handshake bytes (`src/handshake.rs`) over it.

Everything else (inquiry, ERTM, SCO, A2DP, HFP) is out of scope until something needs it. Outgoing connections turned out to be needed (see M5): a phone does not reconnect a dongle on its own.

## Findings

### 1. bumble-rs: use as a reference, do not port

[chaitanyarahalkar/bumble-rs](https://github.com/chaitanyarahalkar/bumble-rs) (Apache-2.0) is a single-author port of Google Bumble: 220 commits between 2026-07-06 and 2026-07-16, about 100k lines across 26 crates. The volume, the "slice N of the incremental port" doc comments and the commit cadence say it was machine-generated against Python Bumble as an oracle. That is not damning by itself: the tests pin serializations to hex captured from upstream Bumble at a stated commit, and the design is sound.

What the protocol crates are:

| crate           | src lines | tests | notes                                                                                                                                                      |
| --------------- | --------- | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bumble-l2cap`  | 2,940     | 44    | classic signaling (connect, configure with MTU/FCS/RFC options, information request), basic mode and ERTM, plus LE credit-based                            |
| `bumble-sdp`    | 1,815     | 31    | data elements, PDUs, server and client with continuation state                                                                                             |
| `bumble-rfcomm` | 1,366     | 21    | frames, FCS, PN and MSC only (upstream Bumble also implements only those), credit-based flow control                                                       |
| `bumble-host`   | ~10,900   | 111   | one 10k-line `lib.rs` holding LE and classic host state, including the SSP event handling; depends on serde, serde_json, GATT, SMP and the soft controller |

Design: synchronous, sans-I/O state machines (`process_pdu`, `poll_outbound`, `tick`). That is the right shape for `no_std` and easy to drive from an async task. std use in the three protocol crates is light: `std::collections::{BTreeMap, VecDeque}`, `std::mem`, `std::error::Error`. Moving them to `no_std + alloc` is mechanical.

Why not port and upstream anyway:

1. **They allocate everywhere** (`Vec<u8>` per PDU, `VecDeque` queues, `BTreeMap` channels). The ESP32 shares about 300 KB of DRAM with Wi-Fi, the BT controller (64 KB reserved) and embassy-net; TrouBLE and the rest of the embassy ecosystem are allocation-free. Making bumble-rs allocation-free is a rewrite, not a port.
1. **Pairing lives in the host monolith.** The BR/EDR SSP logic we need is a few hundred lines buried in `bumble-host/src/lib.rs` next to LE, GATT and JSON key storage (`bumble/src/keys.rs` uses `std::fs`). There is nothing self-contained to port.
1. **Its HCI layer is its own** (`bumble-hci`, 15k lines, generated). We want to share bt-hci with TrouBLE (finding 2), so the HCI types would be thrown away.
1. **Upstreaming is unlikely to stick.** One author, one star, no commits since 2026-07-16; a `no_std` rework would be a fork in practice.
1. **The scope we need is small.** Basic-mode L2CAP with one dynamic channel, an SDP server with static records, an RFCOMM server and SSP Just Works are each a few hundred lines when written for a fixed, allocation-free footprint.

Evidence it works on real hardware: [niart120/swbt-bumble-backend](https://github.com/niart120/swbt-bumble-backend) extracted bumble-rs's HCI, classic L2CAP, SDP and pairing into a Classic HID backend for `swbt-rs`, a virtual Nintendo Switch controller running on a CSR USB dongle. Its `PROVENANCE.md` says it rewrote the classic host as classic-only state and the L2CAP channel state as sans-I/O logic, and its release fixes include ACL credit queuing and a legacy LE event mask for old controllers. So bumble-rs's classic L2CAP, SDP and SSP paths have interoperated with at least one real peer. RFCOMM has no such evidence.

**Recommendation: write fresh, allocation-free, with Python Bumble as the primary reference and bumble-rs and swbt-bumble-backend as secondary ones** (Apache-2.0: where we port logic closely, keep a NOTICE entry and a per-file attribution). Reuse their test vectors: the hex fixtures in bumble-rs's tests are directly useful as byte-level conformance tests for our encoders.

### 2. bt-hci: share it with TrouBLE

[embassy-rs/bt-hci](https://github.com/embassy-rs/bt-hci) 0.11.0 (2026-10-08; `main` is two ISO commits ahead) already has most of what we need:

- **Commands present:** Accept/Reject_Connection_Request, Create_Connection, Disconnect, Authentication_Requested, Set_Connection_Encryption, Link_Key_Request_Reply and Negative_Reply, PIN_Code_Request_Reply, IO_Capability_Request_Reply and Negative_Reply, User_Confirmation_Request_Reply and Negative_Reply, User_Passkey_Request_Reply and Negative_Reply, Remote_Name_Request, Inquiry, Read_BD_ADDR, Set_Event_Mask (all classic bits named) and Page 2, Host_Buffer_Size (ACL and sync).
- **Events:** every one we need, including Connection_Request, Connection_Complete, IO_Capability_Request/Response, User_Confirmation_Request, Link_Key_Request/Notification, Simple_Pairing_Complete, Authentication_Complete, Encryption_Change (v1 and v2), Number_Of_Completed_Packets. Unknown event codes parse to `Event::Unknown`, so nothing is rejected.
- **Missing:** Write_Scan_Enable, Write_Class_Of_Device, Write_Local_Name, Write_Extended_Inquiry_Response, Write_Simple_Pairing_Mode, Write_Secure_Connections_Host_Support, Write_Page_Timeout, Write_Page_Scan_Activity, PIN_Code_Request_Negative_Reply, and the non-LE Read_Buffer_Size (open issue #82). Each is about 10 lines with the crate's `cmd!` macro.
- **Design is not LE-specific:** `AclPacket` carries a 12-bit handle and the BR/EDR boundary and broadcast flags; `ExternalController` consumes only Command Complete and Command Status and passes every other event and ACL packet through.
- **Maintainer stance** (alexmoon on #82): the crate "has been focused on LE to date. If you would like to add the BR/EDR commands you need we'd be happy to add those." Earlier classic PRs (#47, #50, #53, #54) were merged. Issue #57 shows they care about code size from the big event enums, so new commands are welcome but anything that grows event parsing should stay cheap.

**Recommendation: depend on bt-hci.** Define the missing commands locally with `cmd!` from day one, and upstream them as one PR (closing #82) once they have been exercised against a real controller. This also keeps the door open to running TrouBLE and bt-classic on one dual-mode controller later; that needs a shared event dispatcher, which is a later design question, not a milestone-1 one.

Found while building M0:

- **`cmd!` is usable from outside, with a catch.** It is `#[doc(hidden)]` but exported, and `src/cmd.rs` defines Read_Buffer_Size with it. Its expansion names `::bt_hci_transport::PacketToController` by absolute path instead of through `$crate`, so any crate using it must depend on `bt-hci-transport` directly. Worth a one-line upstream fix.
- **`ExternalController` reads into a fixed 259-byte buffer** (`type Buffer<'a> = [u8; 259]`), sized for LE, while BR/EDR controllers deliver much larger ACL packets (rootcanal: 10 x 1023 bytes; DH5 carries up to 1021). M3 sent Host_Buffer_Size with 255 bytes, which the spec says the controller must split to (Core v5.4, Vol 4, Part E, 7.3.39), but M4 showed rootcanal ignores it without host flow control: a 300-byte RFCOMM frame failed the read with `BufferTooSmall` (M3's SDP packets were all small, so it went unnoticed). The fix that does not depend on the controller is `transport::SplitAcl`: it wraps any bt-hci transport, reads into its own 1028-byte buffer and hands oversized ACL packets up as 255-byte pieces with continuation flags, which L2CAP reassembles. Host_Buffer_Size stays as a hint, and bring-up carries on when a controller rejects it, as the ESP32's does (Unsupported Feature, 0x11). Upstream, a const-generic read buffer in `ExternalController` would make the adapter unnecessary.

### 3. Classic on the ESP32 through esp-radio

esp-radio 1.0.0-beta.1 (`src/ble/btdm.rs`, `src/ble/os_adapter_esp32.rs`) hard-codes BLE in three places: `create_ble_config` sets `mode: ESP_BT_MODE_BLE` and `bt_max_acl_conn: 0`, and `ble_init` calls `btdm_controller_enable(ESP_BT_MODE_BLE)`. The VHCI connector (`BleConnector`, a bt-hci `Transport`) forwards raw H4 frames, so classic traffic would pass through it unchanged once the controller is in BTDM mode.

Memory is already fine: esp-hal's ESP32 `memory.x` reserves the first 64 KB of DRAM (0x3FFB0000-0x3FFC0000) whenever Bluetooth is enabled, which covers the BR/EDR exchange memory (up to 0x3FFB6388) and the controller's BSS. `btdm_controller_mem_init` zeroes every region, classic ones included, and nothing calls `esp_bt_controller_mem_release`. No memory work is needed.

Comparing with ESP-IDF's `components/bt/controller/esp32/bt.c`, the changes are:

1. `mode: ESP_BT_MODE_BTDM` (or `CLASSIC_BT`) in the config, `bt_max_acl_conn` 1-2 (IDF default 2), `bt_max_sync_conn` 0, and the same mode passed to `btdm_controller_enable`. IDF requires the two to match.
1. `patch_apply` must also call `config_bt_funcs_reset()` (IDF does unless BLE-only).
1. IDF's enable path also calls `sdk_config_set_bt_pll_track_enable(true)` and `btdm_check_and_init_bb()`, and initializes the low-power clock (`btdm_lpclk_select_src`, `btdm_lpclk_set_div`); esp-radio does none of these. Plausibly irrelevant with modem sleep disabled, but they are the first suspects if links drop.

There is prior art and a warning: in esp-hal#3401, ljodal made changes 1 and 2 (branch `ljodal:bluetooth-dual-mode`) under BTstack. iOS saw the device, Connection_Complete succeeded, then the link died with reason 0x08 (connection timeout); a second try timed out in paging. Their BTstack also mishandled the connection as LE, so the cause is unclear, but it fits change 3 being needed. They gave up. esp-hal#6750 tracks "Bluetooth Classic (BR/EDR)" as missing for ESP32. This is a real but bounded upstream contribution: a `Config` option for the controller mode in esp-radio, ESP32 only.

What M5 found (2026-11-26): none of this is needed. esp-radio's ESP32 controller, configured BLE-only exactly as `main` (efc28aa2) ships it, answers BR/EDR inquiry, pages, pairs, encrypts and carries RFCOMM with an Android phone; the BLE-only mode and `bt_max_acl_conn: 0` are not enforced. A dual-mode patch with the BR/EDR patch functions and PLL tracking was written and tested, and made no difference. What broke links, exactly like #3401 (Connection_Complete, then reason 0x08), was interrupt latency: esp-log writes each line to the UART inside a critical section, about 10 ms per line at 115200 baud, and log lines while a link comes up starve the controller. With `ESP_LOG = "warn"` the link holds. Raising the Bluetooth interrupts from priority 1 to 3 only moved where it failed. ESP-IDF itself keeps the link at interrupt level 1 (HLI off), so high-level interrupts are not required either.

Wi-Fi coexistence: esp-radio's `coex` feature already wires the BTDM coexistence callbacks (`coex_schm_status_bit_set/clear`), and IDF supports Wi-Fi plus BR/EDR coexistence on this chip. Expect Wi-Fi throughput to drop while a BR/EDR link is active; aa-dongle only needs RFCOMM for the short handshake, so we can drop the ACL afterwards if coexistence hurts.

### 4. Testing without the ESP32

The host stack should run on a PC against any HCI controller over a byte transport, so most work does not need the board.

- **Virtual controller, first choice: rootcanal.** Android's virtual controller (Apache-2.0, shipped with the Android emulator as netsim) implements BR/EDR, SSP and the LMP side, and speaks HCI over TCP. The Android emulator itself attaches to it, so a real Android Bluetooth stack can discover, pair with and open RFCOMM to our stack with no radio at all. This is the closest thing to the real target.
- **Python Bumble as the peer.** Bumble has a full classic host (SDP client, RFCOMM client, SSP) and can connect to rootcanal or a USB dongle; its `rfcomm` and `pair` apps make good scripted test peers. Its in-process controller is mostly LE; treat its classic support as unverified.
- **Unit tests:** byte-level fixtures from the spec, Bumble and bumble-rs for every encoder and decoder; two in-process stacks wired back to back for L2CAP, SDP and RFCOMM state machines.
- **Real radio through WSL: not with the current adapter.** usbipd-win is installed and the MediaTek adapter (`2c7c:7009`) can be passed to the `podman-machine-default` distro, and that kernel has `CONFIG_BT_BREDR` and `btusb` as modules. But it is built without `CONFIG_BT_HCIBTUSB_MTK`, so btusb would not load the MediaTek firmware, and as far as I know Bumble's USB transport has no MediaTek driver either. Options: a custom WSL kernel, or (simpler) a cheap USB dongle with a CSR8510 or Realtek RTL8761B chip, which Linux (`btrtl` is enabled) and Bumble support. Passing a dongle to WSL also leaves Windows' own Bluetooth alone.
- **The real ESP32 controller from the PC.** ESP-IDF's `controller_hci_uart` example runs the ESP32 controller in BTDM mode over UART H4. Flashed on the DevKitC, it lets the host stack run on the PC against the exact target controller, which separates "does our host stack work" from "does the esp-radio patch work".

## Proposed layout

One crate to start, `bt-classic`, split into crates later only if a part becomes useful alone (SDP data elements, say):

```text
src/
  lib.rs
  hci/        bt-hci re-exports, the missing BR/EDR commands, Class of Device, EIR builder
  gap.rs      controller bring-up: reset, buffer sizes, event mask, name, CoD, EIR, SSP mode, scan enable
  link.rs     ACL connection table, accept policy, ACL fragmentation and reassembly, controller buffer credits
  security/   SSP state machine (IO capability, confirmation, link key request/notification), LinkKeyStore trait
  l2cap/      signaling channel, basic-mode dynamic channels, configuration (MTU), information responses
  sdp/        data element codec, static record table, server (search attribute, continuation)
  rfcomm/     multiplexer, DLC, PN/MSC/RPN responses, credit-based flow control, FCS
  runner.rs   the async task that owns the controller and drives the state machines
examples/
  host-h4.rs  PC example over TCP (rootcanal) or a serial H4 controller
```

Design rules:

- **No alloc.** Fixed capacities through const generics (connections, channels, DLCs, buffer sizes), `heapless` where needed, buffers provided by the caller like TrouBLE's `HostResources`.
- **Sans-I/O cores, one async runner.** Each protocol layer is a state machine fed bytes and polled for output, testable without a controller. The runner, generic over a bt-hci `Controller`, owns the event loop. Public API is async (`RfcommServer::accept().await`, `Channel::read/write`).
- **Policy is the caller's.** The application implements `LinkKeyStore` (flash on the ESP32, a file on the PC) and a pairing callback (accept Just Works, or show a number); the stack never decides security policy on its own.
- **`defmt` and `log` features**, like the rest of the embassy ecosystem.

## Milestones

1. **M0 Harness (done).** `examples/host-h4.rs` brings up rootcanal over TCP (reset, version, address, features, buffer sizes); `trace::Traced` prints every H4 packet and writes a btsnoop capture; `scripts/rootcanal.sh` runs rootcanal (in WSL on Windows); CI runs fmt, clippy, unit tests, a bare-metal `no_std` build and the bring-up against rootcanal.
1. **M1 Discoverable (done on rootcanal).** `gap::bring_up` and the missing bt-hci commands. The `discoverable` example is found by the `inquiry` example, which also reads its name with a Remote Name Request, and independently by Python Bumble 0.0.236, which decodes the same name, class 0x200404, HSP and Android Auto UUIDs from the EIR. CI runs the inquiry check. Still to see: a real Android phone, once there is a radio (the ESP32 or a USB dongle).
1. **M2 Pairing (done on rootcanal).** `security::Security` (no I/O) and `host::run`. The `discoverable` example accepts, pairs with Just Works SSP, encrypts, keeps keys in a file and reconnects bonded peers without pairing, also after a restart; the `pair` example plays the phone and CI runs it. With Secure Connections on, keys are P-256 (type 7). Python Bumble 0.0.236 as the phone, with its defaults (DisplayYesNo, MITM requested, like a phone), pairs and stores the same key and type, and reconnects on the bond. rootcanal hands out a fixed dummy key, so real key exchange is still to be seen with a phone.
1. **M3 L2CAP and SDP (done on rootcanal).** `l2cap::L2cap` (no I/O): signaling, peer-opened basic-mode channels, MTU configuration, information and echo requests, reassembly. `sdp::SdpServer` with static records (`rfcomm_service_record!`) and continuation. `host::run` now brings the controller up itself, sends ACL data on the controller's buffer credits, and serves SDP on PSM 1. The `discoverable` example serves the AA Wireless (RFCOMM 8) and HSP headset (RFCOMM 6) records; Python Bumble 0.0.236 reads them in CI (`tests/peer/sdp_check.py`), once with its default MTU and once with the 48-byte minimum, which splits the answers with continuation state.
1. **M4 RFCOMM (done on rootcanal).** `rfcomm::Rfcomm` (no I/O): the multiplexer, PN, credit-based flow control, MSC, and RPN, RLS and Test answered, NSC for the rest. `host::run` runs it on PSM 3 and gives the `Handler` RFCOMM callbacks with a sender, so an application can reply or speak first. The `discoverable` example echoes on channels 8 and 6. Python Bumble 0.0.236 plays the phone in CI (`tests/peer/rfcomm_check.py`): it pairs and encrypts, finds channel 8 via SDP, and gets 5, 300, 1000 and 5000-byte payloads echoed intact; channel 6 echoes and an unregistered channel is refused. The aa-dongle handshake runs on top in aa-dongle itself (it depends on aa-core, which this public crate should not), as the first step of M5.
1. **M5 ESP32.** First, the host stack on the PC against the real ESP32 controller (done 2026-11-26): ESP-IDF v6.1.1's `controller_hci_uart_esp32` on a DevKitC (ESP32-D0WD-V3), H4 over a 3.3 V FTDI cable at 921600 baud with RTS/CTS, `serial:PORT` in the examples. The controller reports Bluetooth 4.2 with BR/EDR, SSP and LE, 9 x 1021-byte ACL buffers, and refuses Host_Buffer_Size. An Android phone pairs with the `discoverable` example, encrypts, reads SDP and opens RFCOMM channels 6 and 8; aa-dongle's `bt-dongle` runs the full wireless AA handshake with it, and the phone then joins the S3's access point and opens TCP 5288 to its relay. Then the stack on the DevKitC itself (done 2026-11-26): `firmware/esp32` runs bt-classic over esp-radio's `BleConnector` with no esp-radio change, and the phone pairs, connects the headset profile and opens channel 8 (see finding 3 for the logging catch). Still to do: link keys in flash, and the aa-dongle firmware: the handshake on channel 8 and Wi-Fi coexistence.

   Reconnecting (2026-11-28): in a car the phone never reconnects to the dongle on its own. The Pi's aawgd avoids that by connecting to the bonded phone at start-up and calling BlueZ's `Device.ConnectProfile` on the phone's HSP Audio Gateway (0x1112) every 20 s until Android Auto opens its channel. Paging, authenticating with the stored key and encrypting already worked from application code (the `pair` example does it), but on the bench an encrypted link alone did not make the phone open channel 8. So bt-classic now connects profiles itself: `Requests::connect_profile(addr, uuid)` opens an L2CAP channel to the peer's SDP server, looks up the service's RFCOMM channel (`sdp::SdpClient`), opens RFCOMM as the initiator (or on the session the phone already started), and reports `Handler::profile_connected` or `profile_failed`. CI runs it against the `discoverable` example (`--profile 1108`) and against Bumble 0.0.236 playing the phone's gateway (`tests/peer/profile_check.py`, which also serves a decoy record). With a real phone (Samsung, Android 17) it works: after a reset the ESP32 pages the bonded phone, encrypts, connects HSP AG in the same second, and Android Auto opens channel 8 on its own about 26 s later and completes the handshake, with no tap on the phone. aa-dongle sends no `AT+CKPD`; the open channel is enough.
1. **M6 Upstream.** bt-hci PR with the BR/EDR commands (closes embassy-rs/bt-hci#82); possibly reach out to pulzar-net/bluetooth-host, which plans classic support.

## Open questions

- Whether Secure Connections (P-256) works through VHCI. It works with the same controller over UART: the phone's key is type 7 (unauthenticated P-256). Simple Pairing with P-192 stays the fallback.
- Publishing to crates.io: not yet; the crate stays `publish = false` until there is something to use.

Answered with one Android phone on the ESP32 controller (2026-11-26):

- IO capability: Just Works is enough. The phone offers DisplayYesNo and asks for MITM protection with dedicated bonding, but accepts the unauthenticated key that NoInputNoOutput produces.
- HSP: the phone opens a real RFCOMM connection on the headset channel (6) and keeps it open, before it opens Android Auto's channel (8).
- The handshake: Android Auto opens channel 8 right after pairing and waits for the dongle to speak. With an unreachable network it reports an 11-byte `WifiConnectStatus` and retries the whole handshake over and over; once it can join, the status is 2 bytes and it stops.
