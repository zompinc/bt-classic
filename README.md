# bt-classic

A Bluetooth Classic (BR/EDR) host stack for `no_std` Rust: L2CAP, SDP and RFCOMM over HCI.

Rust has BLE host stacks (TrouBLE), but nothing mature for classic Bluetooth, which phones still use for serial-port profiles such as wireless Android Auto's handshake. This crate aims to fill that gap, starting with what that handshake needs: an SDP record and one RFCOMM channel, on an ESP32's controller through `esp-radio`.

## Status

Just started; nothing works yet.

## Build

```sh
cargo build
cargo test
```

The crate builds on any host; tests run there too. Hardware examples will live under `examples/`.
