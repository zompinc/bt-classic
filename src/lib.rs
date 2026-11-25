//! Bluetooth Classic (BR/EDR) host stack for `no_std` Rust.
//!
//! The host side of classic Bluetooth, on top of an HCI controller: L2CAP,
//! SDP and RFCOMM, enough to offer a serial port profile to a phone.
//!
//! The HCI layer is [`bt_hci`], shared with TrouBLE; [`cmd`] adds the BR/EDR
//! commands it does not define yet.

#![no_std]

pub mod cmd;
pub mod trace;
