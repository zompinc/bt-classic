# bt-classic

A Bluetooth Classic (BR/EDR) host stack for `no_std` Rust: L2CAP, SDP and RFCOMM over HCI.

Rust has BLE host stacks (TrouBLE), but nothing mature for classic Bluetooth, which phones still use for serial-port profiles such as wireless Android Auto's handshake. This crate aims to fill that gap, starting with what that handshake needs: an SDP record and one RFCOMM channel, on an ESP32's controller through `esp-radio`.

See [docs/design.md](docs/design.md) for the research behind it, the layout and the milestones.

## Status

Milestone 0: the test harness. The crate brings up an HCI controller and traces the traffic; no protocol layers yet.

- `cmd`: BR/EDR HCI commands that [bt-hci](https://github.com/embassy-rs/bt-hci) does not define yet (so far Read_Buffer_Size).
- `trace`: wraps an H4 reader or writer, hands each HCI packet to a sink, and encodes btsnoop captures for Wireshark.

## Build

```sh
cargo build
cargo test
```

The library builds for any target, `no_std` included; tests and examples run on the host.

## Run against a virtual controller

[rootcanal](https://github.com/google/rootcanal), Android's virtual controller, implements BR/EDR and serves HCI over TCP port 6402. It ships for Linux x86-64 and macOS arm64; `scripts/rootcanal.sh` installs it into a Python venv on first run.

```sh
scripts/rootcanal.sh                    # Linux or macOS
wsl --cd ~ -- sh -s < scripts/rootcanal.sh   # Windows, in WSL; the port is forwarded to localhost
```

Then, in another terminal:

```sh
cargo run --example host-h4 -- 127.0.0.1:6402 --btsnoop target/host-h4.btsnoop
```

It prints every packet, then the controller's version, address, features and buffer sizes. Open the `.btsnoop` file in Wireshark to decode the traffic.
