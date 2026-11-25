//! BR/EDR HCI commands that bt-hci 0.11 does not define yet.
//!
//! They use bt-hci's own `cmd!` macro, so they behave like its built-in
//! commands (`ReadBufferSize.exec(&controller)`). Each one is meant to move
//! upstream to bt-hci once it has run against a real controller; see
//! embassy-rs/bt-hci#82.

bt_hci::cmd! {
    /// Read Buffer Size command (Core v5.4, Vol 4, Part E, 7.4.5): the
    /// controller's BR/EDR ACL and synchronous data buffers.
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
    use bt_hci::FromHciBytes;
    use bt_hci::cmd::{Cmd, OpcodeGroup};

    #[test]
    fn read_buffer_size_opcode() {
        assert_eq!(ReadBufferSize::OPCODE.group(), OpcodeGroup::INFO_PARAMS);
        assert_eq!(ReadBufferSize::OPCODE.cmd(), 0x0005);
        assert_eq!(ReadBufferSize::OPCODE.to_raw(), 0x1005);
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
