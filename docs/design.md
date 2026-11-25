# bt-classic design

Status: research and proposal, written 2026-11-25. No stack code yet.

## Goal

A `no_std`, async (embassy-style) Bluetooth Classic (BR/EDR) host stack. The first consumer is aa-dongle on an original ESP32, which needs exactly this from Bluetooth:

1. Be discoverable and connectable (Class of Device, local name, EIR, scan enable).
1. Pair with a phone using Secure Simple Pairing, store the link key, and reconnect bonded without re-pairing.
1. Publish SDP records: the wireless Android Auto RFCOMM service (UUID `4de17a00-52cb-11e6-bdf4-0800200c9a66`) and an HSP headset (HS, `0x1108`) record that gets the phone to connect. aa-dongle's BlueZ code (`src/linux/bluetooth.rs`) registers the AA profile on RFCOMM channel 8.
1. Accept one RFCOMM channel and carry the handshake bytes (`src/handshake.rs`) over it.

Everything else (inquiry, outgoing connections, ERTM, SCO, A2DP, HFP) is out of scope until something needs it.

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

### 3. Classic on the ESP32 through esp-radio

esp-radio 1.0.0-beta.1 (`src/ble/btdm.rs`, `src/ble/os_adapter_esp32.rs`) hard-codes BLE in three places: `create_ble_config` sets `mode: ESP_BT_MODE_BLE` and `bt_max_acl_conn: 0`, and `ble_init` calls `btdm_controller_enable(ESP_BT_MODE_BLE)`. The VHCI connector (`BleConnector`, a bt-hci `Transport`) forwards raw H4 frames, so classic traffic would pass through it unchanged once the controller is in BTDM mode.

Memory is already fine: esp-hal's ESP32 `memory.x` reserves the first 64 KB of DRAM (0x3FFB0000-0x3FFC0000) whenever Bluetooth is enabled, which covers the BR/EDR exchange memory (up to 0x3FFB6388) and the controller's BSS. `btdm_controller_mem_init` zeroes every region, classic ones included, and nothing calls `esp_bt_controller_mem_release`. No memory work is needed.

Comparing with ESP-IDF's `components/bt/controller/esp32/bt.c`, the changes are:

1. `mode: ESP_BT_MODE_BTDM` (or `CLASSIC_BT`) in the config, `bt_max_acl_conn` 1-2 (IDF default 2), `bt_max_sync_conn` 0, and the same mode passed to `btdm_controller_enable`. IDF requires the two to match.
1. `patch_apply` must also call `config_bt_funcs_reset()` (IDF does unless BLE-only).
1. IDF's enable path also calls `sdk_config_set_bt_pll_track_enable(true)` and `btdm_check_and_init_bb()`, and initializes the low-power clock (`btdm_lpclk_select_src`, `btdm_lpclk_set_div`); esp-radio does none of these. Plausibly irrelevant with modem sleep disabled, but they are the first suspects if links drop.

There is prior art and a warning: in esp-hal#3401, ljodal made changes 1 and 2 (branch `ljodal:bluetooth-dual-mode`) under BTstack. iOS saw the device, Connection_Complete succeeded, then the link died with reason 0x08 (connection timeout); a second try timed out in paging. Their BTstack also mishandled the connection as LE, so the cause is unclear, but it fits change 3 being needed. They gave up. esp-hal#6750 tracks "Bluetooth Classic (BR/EDR)" as missing for ESP32. This is a real but bounded upstream contribution: a `Config` option for the controller mode in esp-radio, ESP32 only.

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

1. **M0 Harness.** PC example talking HCI over TCP to rootcanal; HCI tracing; CI running unit tests on the host.
1. **M1 Discoverable.** Bring-up sequence and the missing bt-hci commands; the device shows up on an Android phone (emulator first, then a real phone) with the right name and class.
1. **M2 Pairing.** Accept ACL, SSP with NoInputNoOutput (Just Works) and DisplayYesNo, link key storage, bonded reconnect, encryption on.
1. **M3 L2CAP and SDP.** Signaling, basic-mode channels, an SDP server holding the Android Auto and HSP HS records; verified with Bumble's SDP client and an Android phone.
1. **M4 RFCOMM.** A server channel (8) that an Android app or Bumble's RFCOMM client can open, with data echoed both ways; then the aa-dongle handshake running over it on the PC.
1. **M5 ESP32.** esp-radio patch for BTDM mode (local first, upstream PR to esp-rs/esp-hal after); the stack on the DevKitC, link keys in flash, aa-dongle integration with Wi-Fi coexistence.
1. **M6 Upstream.** bt-hci PR with the BR/EDR commands (closes embassy-rs/bt-hci#82); possibly reach out to pulzar-net/bluetooth-host, which plans classic support.

## Open questions

- Which IO capability does the AA handshake need? Commercial AA dongles pair Just Works; confirm the phone does not insist on numeric comparison.
- Whether the phone needs the HSP record only in SDP or an actual HSP RFCOMM connection to proceed. aa-dongle's BlueZ code accepts the HSP connection and does nothing with it.
- Whether Secure Connections (P-256) on the ESP32 controller works through VHCI; Simple Pairing with P-192 is the fallback.
- License and GitHub remote for this repo: not chosen yet.
