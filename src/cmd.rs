//! BR/EDR HCI commands that bt-hci 0.11 does not define yet.
//!
//! They use bt-hci's own `cmd!` macro, so they behave like its built-in
//! commands (`ReadBufferSize::new().exec(&controller)`). Each one is meant to
//! move upstream to bt-hci once it has run against a real controller; see
//! embassy-rs/bt-hci#82.
//!
//! Section numbers refer to Core v5.4, Vol 4, Part E.

/// `scan_enable` values for [`WriteScanEnable`] (7.3.18).
pub mod scan_enable {
    /// Neither discoverable nor connectable.
    pub const NONE: u8 = 0x00;
    /// Discoverable: answers inquiries.
    pub const INQUIRY: u8 = 0x01;
    /// Connectable: answers pages.
    pub const PAGE: u8 = 0x02;
    /// Discoverable and connectable.
    pub const BOTH: u8 = INQUIRY | PAGE;
}

/// `inquiry_mode` values for [`WriteInquiryMode`] (7.3.50).
pub mod inquiry_mode {
    /// Inquiry Result events only.
    pub const STANDARD: u8 = 0x00;
    /// Inquiry Result with RSSI events.
    pub const RSSI: u8 = 0x01;
    /// Extended Inquiry Result events, which carry the peer's EIR data.
    pub const EXTENDED: u8 = 0x02;
}

bt_hci::cmd! {
    /// Write Local Name command (7.3.11): the name peers see, UTF-8,
    /// NUL-padded to 248 bytes. Build it with [`crate::gap::local_name`].
    WriteLocalName(CONTROL_BASEBAND, 0x0013) {
        WriteLocalNameParams {
            local_name: [u8; 248],
        }
        Return = ();
    }
}

bt_hci::cmd! {
    /// Write Scan Enable command (7.3.18): whether the controller answers
    /// inquiries and pages. See [`scan_enable`].
    WriteScanEnable(CONTROL_BASEBAND, 0x001a) {
        WriteScanEnableParams {
            scan_enable: u8,
        }
        Return = ();
    }
}

bt_hci::cmd! {
    /// Write Page Scan Activity command (7.3.20), in 0.625 ms slots.
    WritePageScanActivity(CONTROL_BASEBAND, 0x001c) {
        WritePageScanActivityParams {
            page_scan_interval: u16,
            page_scan_window: u16,
        }
        Return = ();
    }
}

bt_hci::cmd! {
    /// Write Inquiry Scan Activity command (7.3.22), in 0.625 ms slots.
    WriteInquiryScanActivity(CONTROL_BASEBAND, 0x001e) {
        WriteInquiryScanActivityParams {
            inquiry_scan_interval: u16,
            inquiry_scan_window: u16,
        }
        Return = ();
    }
}

bt_hci::cmd! {
    /// Write Class of Device command (7.3.26). Build the value with
    /// [`crate::gap::ClassOfDevice`].
    WriteClassOfDevice(CONTROL_BASEBAND, 0x0024) {
        WriteClassOfDeviceParams {
            class_of_device: [u8; 3],
        }
        Return = ();
    }
}

bt_hci::cmd! {
    /// Write Inquiry Mode command (7.3.50). See [`inquiry_mode`].
    WriteInquiryMode(CONTROL_BASEBAND, 0x0045) {
        WriteInquiryModeParams {
            inquiry_mode: u8,
        }
        Return = ();
    }
}

bt_hci::cmd! {
    /// Write Extended Inquiry Response command (7.3.56): the EIR data sent
    /// with inquiry responses. Build it with [`crate::gap::Eir`].
    WriteExtendedInquiryResponse(CONTROL_BASEBAND, 0x0052) {
        WriteExtendedInquiryResponseParams {
            fec_required: u8,
            extended_inquiry_response: [u8; 240],
        }
        Return = ();
    }
}

bt_hci::cmd! {
    /// Write Simple Pairing Mode command (7.3.59): 1 enables Secure Simple
    /// Pairing. It cannot be turned off again without a reset.
    WriteSimplePairingMode(CONTROL_BASEBAND, 0x0056) {
        WriteSimplePairingModeParams {
            simple_pairing_mode: u8,
        }
        Return = ();
    }
}

bt_hci::cmd! {
    /// Write Secure Connections Host Support command (7.3.92): 1 lets SSP use
    /// P-256 when both sides support it.
    WriteSecureConnectionsHostSupport(CONTROL_BASEBAND, 0x007a) {
        WriteSecureConnectionsHostSupportParams {
            secure_connections_host_support: u8,
        }
        Return = ();
    }
}

bt_hci::cmd! {
    /// Read Buffer Size command (7.4.5): the controller's BR/EDR ACL and
    /// synchronous data buffers.
    ///
    /// The host must not send ACL packets longer than `acl_data_packet_length`
    /// or have more than `total_num_acl_data_packets` outstanding.
    ReadBufferSize(INFO_PARAMS, 0x0005) {
        Params = ();
        ReadBufferSizeReturn {
            acl_data_packet_length: u16,
            synchronous_data_packet_length: u8,
            total_num_acl_data_packets: u16,
            total_num_synchronous_data_packets: u16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bt_hci::cmd::{Cmd, OpcodeGroup};
    use bt_hci::{FromHciBytes, WriteHci};

    /// The command packet as sent, without the H4 indicator.
    fn encode<C: WriteHci>(cmd: &C) -> ([u8; 300], usize) {
        let mut buf = [0u8; 300];
        let len = cmd.size();
        cmd.write_hci(&mut buf[..]).unwrap();
        (buf, len)
    }

    #[test]
    fn opcodes() {
        let base = OpcodeGroup::CONTROL_BASEBAND;
        assert_eq!(WriteLocalName::OPCODE.group(), base);
        assert_eq!(WriteLocalName::OPCODE.to_raw(), 0x0c13);
        assert_eq!(WriteScanEnable::OPCODE.to_raw(), 0x0c1a);
        assert_eq!(WritePageScanActivity::OPCODE.to_raw(), 0x0c1c);
        assert_eq!(WriteInquiryScanActivity::OPCODE.to_raw(), 0x0c1e);
        assert_eq!(WriteClassOfDevice::OPCODE.to_raw(), 0x0c24);
        assert_eq!(WriteInquiryMode::OPCODE.to_raw(), 0x0c45);
        assert_eq!(WriteExtendedInquiryResponse::OPCODE.to_raw(), 0x0c52);
        assert_eq!(WriteSimplePairingMode::OPCODE.to_raw(), 0x0c56);
        assert_eq!(WriteSecureConnectionsHostSupport::OPCODE.to_raw(), 0x0c7a);
        assert_eq!(ReadBufferSize::OPCODE.group(), OpcodeGroup::INFO_PARAMS);
        assert_eq!(ReadBufferSize::OPCODE.to_raw(), 0x1005);
    }

    #[test]
    fn write_scan_enable_bytes() {
        let (buf, len) = encode(&WriteScanEnable::new(scan_enable::BOTH));
        assert_eq!(&buf[..len], &[0x1a, 0x0c, 0x01, 0x03]);
    }

    #[test]
    fn write_page_scan_activity_bytes() {
        let (buf, len) = encode(&WritePageScanActivity::new(0x0800, 0x0012));
        assert_eq!(&buf[..len], &[0x1c, 0x0c, 0x04, 0x00, 0x08, 0x12, 0x00]);
    }

    #[test]
    fn write_class_of_device_bytes() {
        let (buf, len) = encode(&WriteClassOfDevice::new([0x04, 0x04, 0x24]));
        assert_eq!(&buf[..len], &[0x24, 0x0c, 0x03, 0x04, 0x04, 0x24]);
    }

    #[test]
    fn write_local_name_is_248_bytes() {
        let mut name = [0u8; 248];
        name[..3].copy_from_slice(b"abc");
        let (buf, len) = encode(&WriteLocalName::new(name));
        assert_eq!(len, 3 + 248);
        assert_eq!(&buf[..7], &[0x13, 0x0c, 248, b'a', b'b', b'c', 0]);
    }

    #[test]
    fn write_extended_inquiry_response_is_241_bytes() {
        let (buf, len) = encode(&WriteExtendedInquiryResponse::new(1, [0xee; 240]));
        assert_eq!(len, 3 + 241);
        assert_eq!(&buf[..5], &[0x52, 0x0c, 241, 0x01, 0xee]);
    }

    #[test]
    fn read_buffer_size_return() {
        // 1021-byte ACL packets (DH5), 64-byte SCO, 8 ACL buffers, 1 SCO buffer.
        let bytes = [0xfd, 0x03, 0x40, 0x08, 0x00, 0x01, 0x00];
        let ret = ReadBufferSizeReturn::from_hci_bytes_complete(&bytes).unwrap();
        assert_eq!({ ret.acl_data_packet_length }, 1021);
        assert_eq!({ ret.synchronous_data_packet_length }, 64);
        assert_eq!({ ret.total_num_acl_data_packets }, 8);
        assert_eq!({ ret.total_num_synchronous_data_packets }, 1);
    }
}
