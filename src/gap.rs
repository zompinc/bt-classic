//! Controller bring-up and discoverability (GAP, Core v5.4, Vol 3, Part C).
//!
//! [`bring_up`] resets a controller and configures it as a discoverable,
//! connectable BR/EDR device with Secure Simple Pairing on: event mask, name,
//! Class of Device, Extended Inquiry Response and scan enable.

use bt_hci::cmd::Error;
use bt_hci::cmd::controller_baseband::{Reset, SetEventMask};
use bt_hci::cmd::info::ReadBdAddr;
use bt_hci::controller::{Controller, ControllerCmdSync};
use bt_hci::param::{BdAddr, EventMask};

use crate::cmd::{
    ReadBufferSize, WriteClassOfDevice, WriteExtendedInquiryResponse, WriteLocalName,
    WriteScanEnable, WriteSimplePairingMode, scan_enable,
};

/// A Class of Device (Assigned Numbers, 2.8): service classes plus a major and
/// minor device class, as the 3 bytes HCI carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClassOfDevice(pub [u8; 3]);

impl ClassOfDevice {
    /// Builds one from service class bits ([`service`]), a major device class
    /// ([`major`]) and a 6-bit minor device class.
    pub const fn new(services: u32, major: u8, minor: u8) -> Self {
        let value =
            (services & 0x00ff_e000) | ((major as u32 & 0x1f) << 8) | ((minor as u32 & 0x3f) << 2);
        Self([value as u8, (value >> 8) as u8, (value >> 16) as u8])
    }

    /// The 24-bit value.
    pub const fn value(self) -> u32 {
        self.0[0] as u32 | (self.0[1] as u32) << 8 | (self.0[2] as u32) << 16
    }

    /// The major device class.
    pub const fn major(self) -> u8 {
        ((self.value() >> 8) & 0x1f) as u8
    }

    /// The minor device class.
    pub const fn minor(self) -> u8 {
        ((self.value() >> 2) & 0x3f) as u8
    }

    /// The service class bits, in place (bits 13-23).
    pub const fn services(self) -> u32 {
        self.value() & 0x00ff_e000
    }
}

/// Major service class bits of a [`ClassOfDevice`].
pub mod service {
    pub const LIMITED_DISCOVERABLE: u32 = 1 << 13;
    pub const LE_AUDIO: u32 = 1 << 14;
    pub const POSITIONING: u32 = 1 << 16;
    pub const NETWORKING: u32 = 1 << 17;
    pub const RENDERING: u32 = 1 << 18;
    pub const CAPTURING: u32 = 1 << 19;
    pub const OBJECT_TRANSFER: u32 = 1 << 20;
    pub const AUDIO: u32 = 1 << 21;
    pub const TELEPHONY: u32 = 1 << 22;
    pub const INFORMATION: u32 = 1 << 23;
}

/// Major device classes of a [`ClassOfDevice`].
pub mod major {
    pub const MISCELLANEOUS: u8 = 0x00;
    pub const COMPUTER: u8 = 0x01;
    pub const PHONE: u8 = 0x02;
    pub const NETWORKING: u8 = 0x03;
    pub const AUDIO_VIDEO: u8 = 0x04;
    pub const PERIPHERAL: u8 = 0x05;
    pub const IMAGING: u8 = 0x06;
    pub const WEARABLE: u8 = 0x07;
    pub const TOY: u8 = 0x08;
    pub const HEALTH: u8 = 0x09;
    pub const UNCATEGORIZED: u8 = 0x1f;
}

/// Minor device classes for [`major::AUDIO_VIDEO`].
pub mod audio_video {
    pub const WEARABLE_HEADSET: u8 = 0x01;
    pub const HANDS_FREE: u8 = 0x02;
    pub const LOUDSPEAKER: u8 = 0x05;
    pub const HEADPHONES: u8 = 0x06;
    pub const CAR_AUDIO: u8 = 0x08;
}

/// The Write_Local_Name parameter for `name`: UTF-8, NUL-padded to 248 bytes,
/// cut at a character boundary if longer.
pub fn local_name(name: &str) -> [u8; 248] {
    let mut out = [0u8; 248];
    let bytes = truncate_utf8(name, out.len());
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

/// The longest prefix of `s` that fits in `max` bytes without splitting a
/// character.
fn truncate_utf8(s: &str, max: usize) -> &[u8] {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s.as_bytes()[..end]
}

/// EIR data types (Assigned Numbers, 2.3).
pub mod eir_type {
    pub const UUID16_INCOMPLETE: u8 = 0x02;
    pub const UUID16_COMPLETE: u8 = 0x03;
    pub const UUID128_INCOMPLETE: u8 = 0x06;
    pub const UUID128_COMPLETE: u8 = 0x07;
    pub const NAME_SHORTENED: u8 = 0x08;
    pub const NAME_COMPLETE: u8 = 0x09;
    pub const TX_POWER_LEVEL: u8 = 0x0a;
}

/// The EIR buffer is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EirFull;

/// Builds Extended Inquiry Response data (Core v5.4, Vol 3, Part C, 8): a
/// sequence of `[length, type, data...]` structures in 240 bytes.
#[derive(Clone)]
pub struct Eir {
    buf: [u8; 240],
    len: usize,
}

impl Default for Eir {
    fn default() -> Self {
        Self::new()
    }
}

impl Eir {
    /// Empty EIR data.
    pub const fn new() -> Self {
        Self {
            buf: [0; 240],
            len: 0,
        }
    }

    /// Bytes still free, including each structure's 2 header bytes.
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.len
    }

    /// Appends one structure.
    pub fn push(&mut self, data_type: u8, data: &[u8]) -> Result<&mut Self, EirFull> {
        let needed = 2 + data.len();
        if needed > self.remaining() || data.len() > 254 {
            return Err(EirFull);
        }
        self.buf[self.len] = (data.len() + 1) as u8;
        self.buf[self.len + 1] = data_type;
        self.buf[self.len + 2..self.len + needed].copy_from_slice(data);
        self.len += needed;
        Ok(self)
    }

    /// Appends the device name: complete if it fits, otherwise shortened to
    /// the space left.
    pub fn name(&mut self, name: &str) -> Result<&mut Self, EirFull> {
        let room = self.remaining().checked_sub(2).ok_or(EirFull)?;
        if name.len() <= room {
            self.push(eir_type::NAME_COMPLETE, name.as_bytes())
        } else {
            self.push(eir_type::NAME_SHORTENED, truncate_utf8(name, room))
        }
    }

    /// Appends a complete list of 16-bit service UUIDs.
    pub fn uuid16(&mut self, uuids: &[u16]) -> Result<&mut Self, EirFull> {
        let mut data = [0u8; 238];
        let len = uuids.len() * 2;
        if len > data.len() {
            return Err(EirFull);
        }
        for (chunk, uuid) in data.as_chunks_mut::<2>().0.iter_mut().zip(uuids) {
            *chunk = uuid.to_le_bytes();
        }
        self.push(eir_type::UUID16_COMPLETE, &data[..len])
    }

    /// Appends a complete list of 128-bit service UUIDs, given as numbers
    /// (`0x4de17a00_52cb_11e6_bdf4_0800200c9a66`).
    pub fn uuid128(&mut self, uuids: &[u128]) -> Result<&mut Self, EirFull> {
        let mut data = [0u8; 224];
        let len = uuids.len() * 16;
        if len > data.len() {
            return Err(EirFull);
        }
        for (chunk, uuid) in data.as_chunks_mut::<16>().0.iter_mut().zip(uuids) {
            *chunk = uuid.to_le_bytes();
        }
        self.push(eir_type::UUID128_COMPLETE, &data[..len])
    }

    /// The structures written so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// The Write_Extended_Inquiry_Response parameter: the data, zero-padded.
    pub const fn to_array(&self) -> [u8; 240] {
        self.buf
    }
}

/// Iterates over the `(type, data)` structures of EIR or advertising data,
/// stopping at the first zero length or malformed structure.
pub fn eir_structures(data: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut rest = data;
    core::iter::from_fn(move || {
        let (&len, tail) = rest.split_first()?;
        let len = usize::from(len);
        if len == 0 || len > tail.len() {
            rest = &[];
            return None;
        }
        let (structure, next) = tail.split_at(len);
        rest = next;
        Some((structure[0], &structure[1..]))
    })
}

/// The name in EIR data, complete or shortened, if it has one.
pub fn eir_name(data: &[u8]) -> Option<&str> {
    eir_structures(data)
        .find(|&(t, _)| t == eir_type::NAME_COMPLETE || t == eir_type::NAME_SHORTENED)
        .and_then(|(_, name)| core::str::from_utf8(name).ok())
}

/// The events a classic device needs: connections, pairing (legacy and SSP),
/// encryption, inquiry and link changes. LE events are left off.
pub fn classic_event_mask() -> EventMask {
    EventMask::new()
        .enable_inquiry_complete(true)
        .enable_inquiry_result(true)
        .enable_inquiry_result_with_rssi(true)
        .enable_ext_inquiry_result(true)
        .enable_conn_complete(true)
        .enable_conn_request(true)
        .enable_disconnection_complete(true)
        .enable_authentication_complete(true)
        .enable_remote_name_request_complete(true)
        .enable_encryption_change_v1(true)
        .enable_encryption_key_refresh_complete(true)
        .enable_change_conn_link_key_complete(true)
        .enable_read_remote_supported_features_complete(true)
        .enable_read_remote_version_information_complete(true)
        .enable_read_remote_ext_features_complete(true)
        .enable_hardware_error(true)
        .enable_role_change(true)
        .enable_mode_change(true)
        .enable_pin_code_request(true)
        .enable_link_key_request(true)
        .enable_link_key_notification(true)
        .enable_data_buffer_overflow(true)
        .enable_max_slots_change(true)
        .enable_conn_packet_kind_changed(true)
        .enable_link_supervision_timeout_changed(true)
        .enable_io_capability_request(true)
        .enable_io_capability_response(true)
        .enable_user_confirmation_request(true)
        .enable_user_passkey_request(true)
        .enable_remote_oob_data_request(true)
        .enable_simple_pairing_complete(true)
        .enable_user_passkey_notification(true)
        .enable_keypress_notification(true)
        .enable_remote_host_supported_features_notification(true)
}

/// How [`bring_up`] presents the device.
#[derive(Clone, Copy, Debug)]
pub struct Config<'a> {
    /// The name peers see in inquiry results and remote name requests.
    pub name: &'a str,
    /// The Class of Device peers see.
    pub class_of_device: ClassOfDevice,
    /// 16-bit service UUIDs listed in the EIR.
    pub uuid16: &'a [u16],
    /// 128-bit service UUIDs listed in the EIR.
    pub uuid128: &'a [u128],
    /// Answer inquiries.
    pub discoverable: bool,
    /// Answer pages.
    pub connectable: bool,
}

/// What [`bring_up`] learned about the controller.
#[derive(Clone, Copy, Debug)]
pub struct ControllerInfo {
    /// The controller's public address.
    pub bd_addr: BdAddr,
    /// The longest ACL data packet the controller accepts.
    pub acl_data_packet_length: u16,
    /// How many ACL data packets the controller buffers.
    pub total_num_acl_data_packets: u16,
}

/// The commands [`bring_up`] sends. Implemented for every controller that
/// supports them, such as bt-hci's `ExternalController`.
pub trait ClassicController:
    Controller
    + ControllerCmdSync<Reset>
    + ControllerCmdSync<SetEventMask>
    + ControllerCmdSync<ReadBdAddr>
    + ControllerCmdSync<ReadBufferSize>
    + ControllerCmdSync<WriteSimplePairingMode>
    + ControllerCmdSync<WriteClassOfDevice>
    + ControllerCmdSync<WriteLocalName>
    + ControllerCmdSync<WriteExtendedInquiryResponse>
    + ControllerCmdSync<WriteScanEnable>
{
}

impl<C> ClassicController for C where
    C: Controller
        + ControllerCmdSync<Reset>
        + ControllerCmdSync<SetEventMask>
        + ControllerCmdSync<ReadBdAddr>
        + ControllerCmdSync<ReadBufferSize>
        + ControllerCmdSync<WriteSimplePairingMode>
        + ControllerCmdSync<WriteClassOfDevice>
        + ControllerCmdSync<WriteLocalName>
        + ControllerCmdSync<WriteExtendedInquiryResponse>
        + ControllerCmdSync<WriteScanEnable>
{
}

/// Resets the controller and configures it as `config` describes.
///
/// Like every command, this only completes while something polls
/// [`Controller::read`]; run it alongside the event loop.
pub async fn bring_up<C: ClassicController>(
    controller: &C,
    config: &Config<'_>,
) -> Result<ControllerInfo, Error<C::Error>> {
    controller.exec(&Reset::new()).await?;
    controller
        .exec(&SetEventMask::new(classic_event_mask()))
        .await?;

    let bd_addr = controller.exec(&ReadBdAddr::new()).await?;
    let buffers = controller.exec(&ReadBufferSize::new()).await?;

    controller.exec(&WriteSimplePairingMode::new(1)).await?;
    controller
        .exec(&WriteClassOfDevice::new(config.class_of_device.0))
        .await?;
    controller
        .exec(&WriteLocalName::new(local_name(config.name)))
        .await?;

    let mut eir = Eir::new();
    // A name too long for the EIR is shortened; UUIDs that no longer fit are
    // left out rather than failing bring-up. Peers still get them from SDP.
    let _ = eir.name(config.name);
    if !config.uuid16.is_empty() {
        let _ = eir.uuid16(config.uuid16);
    }
    if !config.uuid128.is_empty() {
        let _ = eir.uuid128(config.uuid128);
    }
    controller
        .exec(&WriteExtendedInquiryResponse::new(0, eir.to_array()))
        .await?;

    set_scan_enable(controller, config.discoverable, config.connectable).await?;

    Ok(ControllerInfo {
        bd_addr,
        acl_data_packet_length: buffers.acl_data_packet_length,
        total_num_acl_data_packets: buffers.total_num_acl_data_packets,
    })
}

/// Turns answering inquiries and pages on or off.
pub async fn set_scan_enable<C: ControllerCmdSync<WriteScanEnable>>(
    controller: &C,
    discoverable: bool,
    connectable: bool,
) -> Result<(), Error<C::Error>> {
    let mut value = scan_enable::NONE;
    if discoverable {
        value |= scan_enable::INQUIRY;
    }
    if connectable {
        value |= scan_enable::PAGE;
    }
    controller.exec(&WriteScanEnable::new(value)).await
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    #[test]
    fn class_of_device_headset() {
        // Audio service, Audio/Video major class, wearable headset: 0x200404.
        let cod = ClassOfDevice::new(
            service::AUDIO,
            major::AUDIO_VIDEO,
            audio_video::WEARABLE_HEADSET,
        );
        assert_eq!(cod.value(), 0x20_0404);
        assert_eq!(cod.0, [0x04, 0x04, 0x20]);
        assert_eq!(cod.major(), major::AUDIO_VIDEO);
        assert_eq!(cod.minor(), audio_video::WEARABLE_HEADSET);
        assert_eq!(cod.services(), service::AUDIO);
    }

    #[test]
    fn class_of_device_phone() {
        // A typical smartphone: 0x5a020c.
        let cod = ClassOfDevice([0x0c, 0x02, 0x5a]);
        assert_eq!(cod.major(), major::PHONE);
        assert_eq!(cod.minor(), 0x03);
        assert_eq!(
            cod.services(),
            service::TELEPHONY
                | service::OBJECT_TRANSFER
                | service::CAPTURING
                | service::NETWORKING
        );
    }

    #[test]
    fn local_name_pads_and_truncates() {
        let name = local_name("bt-classic");
        assert_eq!(&name[..10], b"bt-classic");
        assert!(name[10..].iter().all(|&b| b == 0));

        // 124 two-byte characters fill 248 bytes exactly; one more is dropped whole.
        let long: std::string::String = core::iter::repeat_n('é', 125).collect();
        let name = local_name(&long);
        assert_eq!(core::str::from_utf8(&name).unwrap().chars().count(), 124);
    }

    #[test]
    fn eir_name_and_uuids() {
        let mut eir = Eir::new();
        eir.name("bt").unwrap();
        eir.uuid16(&[0x1108, 0x1101]).unwrap();
        eir.uuid128(&[0x4de17a00_52cb_11e6_bdf4_0800200c9a66])
            .unwrap();

        let mut expected = std::vec![
            3, 0x09, b'b', b't', 5, 0x03, 0x08, 0x11, 0x01, 0x11, 17, 0x07
        ];
        // 128-bit UUIDs go little-endian on the air.
        expected.extend_from_slice(&[
            0x66, 0x9a, 0x0c, 0x20, 0x00, 0x08, 0xf4, 0xbd, 0xe6, 0x11, 0xcb, 0x52, 0x00, 0x7a,
            0xe1, 0x4d,
        ]);
        assert_eq!(eir.as_bytes(), &expected[..]);
        assert_eq!(eir.to_array()[expected.len()..], [0; 240][expected.len()..]);
    }

    #[test]
    fn eir_shortens_a_long_name() {
        let mut eir = Eir::new();
        eir.push(0xff, &[0; 228]).unwrap();
        // 10 bytes left: 2 of header, 8 of name.
        eir.name("a name longer than eight").unwrap();
        let (data_type, name) = eir_structures(eir.as_bytes()).nth(1).unwrap();
        assert_eq!(data_type, eir_type::NAME_SHORTENED);
        assert_eq!(name, b"a name l");
        assert_eq!(eir.remaining(), 0);
        assert_eq!(eir.push(0x0a, &[0]).err(), Some(EirFull));
    }

    #[test]
    fn eir_structures_stop_at_padding_and_garbage() {
        let data = [3, 0x09, b'h', b'i', 2, 0x0a, 0x04, 0, 0, 0];
        let found: Vec<_> = eir_structures(&data).collect();
        assert_eq!(found, [(0x09, &b"hi"[..]), (0x0a, &[0x04][..])]);
        assert_eq!(eir_name(&data), Some("hi"));

        // A length running past the end ends iteration.
        assert_eq!(eir_structures(&[9, 0x09, b'x']).count(), 0);
    }
}
