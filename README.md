# bt-classic

A Bluetooth Classic (BR/EDR) host stack for `no_std` Rust: L2CAP, SDP and RFCOMM over HCI.

Rust has BLE host stacks (TrouBLE), but nothing mature for classic Bluetooth, which phones still use for serial-port profiles such as wireless Android Auto's handshake. This crate aims to fill that gap, starting with what that handshake needs: an SDP record and one RFCOMM channel, on an ESP32's controller through `esp-radio`.

See [docs/design.md](docs/design.md) for the research behind it, the layout and the milestones.

## Status

Milestone 4: a controller comes up discoverable and connectable, accepts connections, pairs with Secure Simple Pairing (Just Works or numeric comparison), stores link keys, reconnects bonded devices without pairing again, answers SDP queries, and serves RFCOMM channels that a phone opens. Running it on an ESP32 comes next.

- `host`: the async runner (`host::run`) that brings the controller up, reads it, drives pairing, L2CAP and SDP, and sends their replies, with a `Handler` for progress and numeric-comparison prompts.
- `l2cap`: basic-mode L2CAP with no I/O: signaling, channels the peer opens, MTU configuration, reassembly.
- `sdp`: an SDP server for static service records, with continuation; `rfcomm_service_record!` builds the usual RFCOMM record.
- `rfcomm`: an RFCOMM server with no I/O: the multiplexer, parameter negotiation and credit-based flow control.
- `transport`: `SplitAcl`, which keeps incoming ACL packets within bt-hci's read buffer whatever the controller sends.
- `security`: the pairing state machine, with no I/O, and the `LinkKeyStore` trait (`MemoryKeyStore` keeps keys in RAM).
- `gap`: the bring-up sequence (`gap::bring_up`), Class of Device, the local name, and building and parsing EIR data.
- `cmd`: BR/EDR HCI commands that [bt-hci](https://github.com/embassy-rs/bt-hci) does not define yet: PIN code negative reply, name, scan enable and activity, Class of Device, inquiry mode, EIR, Simple Pairing mode, Secure Connections host support, buffer size.
- `trace`: wraps an H4 reader or writer, hands each HCI packet to a sink, and encodes btsnoop captures for Wireshark.

## Build

```sh
cargo build
cargo test
```

The library builds for any target, `no_std` included; tests and examples run on the host. `rust-toolchain.toml` pins the Rust version CI uses, and rustup installs it on the first build. Firmware for the ESP32 will need Espressif's Xtensa toolchain, so it will live in its own directory with its own toolchain file.

## Run against a virtual controller

[rootcanal](https://github.com/google/rootcanal), Android's virtual controller, implements BR/EDR and serves HCI over TCP port 6402. It ships for Linux x86-64 and macOS arm64; `scripts/rootcanal.sh` installs it into a Python venv on first run.

```sh
scripts/rootcanal.sh                    # Linux or macOS
wsl --cd ~ -- sh -s < scripts/rootcanal.sh   # Windows, in WSL; the port is forwarded to localhost
```

Each TCP connection to rootcanal gets its own controller on one shared virtual radio, so several examples can see each other. In other terminals:

```sh
cargo run --example host-h4                      # version, address, features, buffer sizes
cargo run --example discoverable -- --quiet --keys target/keys.txt   # pairs, serves SDP, echoes RFCOMM
cargo run --example inquiry -- --expect bt-classic   # finds it and reads its name
cargo run --example pair -- --expect bt-classic      # pairs, then reconnects on the bond
```

`tests/peer/sdp_check.py` and `tests/peer/rfcomm_check.py` check the `discoverable` example with Google's [Bumble](https://github.com/google/bumble) as an independent peer: its SDP records, and data echoed over RFCOMM after pairing (`pip install bumble==0.0.236`, then `python tests/peer/rfcomm_check.py`).

Every example prints the HCI packets it exchanges (`--quiet` turns that off) and takes `--btsnoop FILE` to write a capture that Wireshark decodes, and an optional `HOST:PORT` for a controller elsewhere.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
