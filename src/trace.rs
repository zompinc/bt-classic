//! HCI packet tracing for byte-stream (H4) transports.
//!
//! [`Traced`] wraps the reader or the writer of an H4 link (a UART, or TCP to
//! a virtual controller) and hands every complete HCI packet that passes
//! through it to a [`Sink`]. It sits below the transport, so it sees exactly
//! the bytes on the wire, whichever HCI layer is on top.
//!
//! [`btsnoop`] encodes those packets as a btsnoop capture that Wireshark
//! opens directly.

use embedded_io::ErrorType;

/// Which way a packet travelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Direction {
    /// Commands and outgoing data.
    HostToController,
    /// Events and incoming data.
    ControllerToHost,
}

/// Receives each traced packet.
pub trait Sink {
    /// Called once per complete H4 packet, indicator byte included.
    ///
    /// `packet` holds at most the framer's capacity; `original_len` is the
    /// packet's full length, larger than `packet.len()` when it was truncated.
    /// An unknown indicator byte arrives as a one-byte packet.
    fn packet(&self, direction: Direction, packet: &[u8], original_len: usize);
}

/// H4 packet indicators (Core v5.4, Vol 4, Part A, 2).
mod indicator {
    pub const COMMAND: u8 = 0x01;
    pub const ACL: u8 = 0x02;
    pub const SYNC: u8 = 0x03;
    pub const EVENT: u8 = 0x04;
    pub const ISO: u8 = 0x05;
}

/// The full length of the H4 packet starting `prefix`, once its header is in.
enum Length {
    NeedMore,
    Total(usize),
    Unknown,
}

fn packet_length(prefix: &[u8]) -> Length {
    let u8_at = |i: usize| prefix.get(i).map(|&b| usize::from(b));
    let u16_at = |i: usize| match (prefix.get(i), prefix.get(i + 1)) {
        (Some(&lo), Some(&hi)) => Some(usize::from(u16::from_le_bytes([lo, hi]))),
        _ => None,
    };
    let total = match prefix[0] {
        indicator::COMMAND => u8_at(3).map(|len| 4 + len),
        indicator::ACL => u16_at(3).map(|len| 5 + len),
        indicator::SYNC => u8_at(3).map(|len| 4 + len),
        indicator::EVENT => u8_at(2).map(|len| 3 + len),
        indicator::ISO => u16_at(3).map(|len| 5 + (len & 0x3fff)),
        _ => return Length::Unknown,
    };
    total.map_or(Length::NeedMore, Length::Total)
}

/// Splits an H4 byte stream into packets.
///
/// Holds up to `N` bytes of the current packet; longer packets are reported
/// truncated. `N` must be at least 5, the longest H4 header.
pub struct H4Framer<const N: usize> {
    buf: [u8; N],
    seen: usize,
    total: Option<usize>,
}

impl<const N: usize> Default for H4Framer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> H4Framer<N> {
    /// An empty framer.
    pub const fn new() -> Self {
        const { assert!(N >= 5, "H4Framer needs room for a 5-byte header") };
        Self {
            buf: [0; N],
            seen: 0,
            total: None,
        }
    }

    /// Feeds bytes from the stream, calling `emit(packet, original_len)` for
    /// every packet they complete.
    pub fn push(&mut self, bytes: &[u8], mut emit: impl FnMut(&[u8], usize)) {
        for &byte in bytes {
            if self.seen < N {
                self.buf[self.seen] = byte;
            }
            self.seen += 1;

            if self.total.is_none() {
                match packet_length(&self.buf[..self.seen.min(N)]) {
                    Length::NeedMore => continue,
                    Length::Total(total) => self.total = Some(total),
                    Length::Unknown => self.total = Some(1),
                }
            }

            if self.total == Some(self.seen) {
                emit(&self.buf[..self.seen.min(N)], self.seen);
                self.seen = 0;
                self.total = None;
            }
        }
    }
}

/// A reader or writer that reports the H4 packets passing through it.
///
/// Wrap the controller-to-host reader with [`Direction::ControllerToHost`]
/// and the writer with [`Direction::HostToController`]; one [`Sink`] can
/// serve both.
pub struct Traced<'s, T, S, const N: usize = 1100> {
    inner: T,
    direction: Direction,
    sink: &'s S,
    framer: H4Framer<N>,
}

impl<'s, T, S: Sink, const N: usize> Traced<'s, T, S, N> {
    /// Traces `inner`, a stream carrying packets in `direction`.
    pub const fn new(inner: T, direction: Direction, sink: &'s S) -> Self {
        Self {
            inner,
            direction,
            sink,
            framer: H4Framer::new(),
        }
    }

    /// The wrapped stream.
    pub fn into_inner(self) -> T {
        self.inner
    }

    fn observe(&mut self, bytes: &[u8]) {
        let (sink, direction) = (self.sink, self.direction);
        self.framer
            .push(bytes, |packet, len| sink.packet(direction, packet, len));
    }
}

impl<T: ErrorType, S, const N: usize> ErrorType for Traced<'_, T, S, N> {
    type Error = T::Error;
}

impl<T: embedded_io_async::Read, S: Sink, const N: usize> embedded_io_async::Read
    for Traced<'_, T, S, N>
{
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let n = self.inner.read(buf).await?;
        self.observe(&buf[..n]);
        Ok(n)
    }
}

impl<T: embedded_io_async::Write, S: Sink, const N: usize> embedded_io_async::Write
    for Traced<'_, T, S, N>
{
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let n = self.inner.write(buf).await?;
        self.observe(&buf[..n]);
        Ok(n)
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.inner.flush().await
    }
}

/// The btsnoop capture format, datalink type 1002 (H4).
///
/// A capture is [`FILE_HEADER`] followed, for each packet, by
/// [`record_header`] and the packet bytes, indicator included.
pub mod btsnoop {
    use super::{Direction, indicator};

    /// The 16-byte file header: magic, version 1, datalink 1002 (HCI UART).
    pub const FILE_HEADER: [u8; 16] = [
        b'b', b't', b's', b'n', b'o', b'o', b'p', 0, // magic
        0, 0, 0, 1, // version
        0, 0, 0x03, 0xea, // datalink 1002
    ];

    /// Length of a record header.
    pub const RECORD_HEADER_LEN: usize = 24;

    /// Microseconds from 0001-01-01 (btsnoop's epoch) to 1970-01-01.
    const UNIX_EPOCH_US: u64 = 0x00dc_ddb3_0f2f_8000;

    /// The record header for `packet`, which may be truncated from
    /// `original_len` bytes, captured `unix_time_us` microseconds after the
    /// Unix epoch.
    pub fn record_header(
        direction: Direction,
        packet: &[u8],
        original_len: usize,
        unix_time_us: u64,
    ) -> [u8; RECORD_HEADER_LEN] {
        let received = matches!(direction, Direction::ControllerToHost);
        let command_or_event = matches!(
            packet.first(),
            Some(&indicator::COMMAND) | Some(&indicator::EVENT)
        );
        let flags = u32::from(received) | (u32::from(command_or_event) << 1);

        let mut header = [0; RECORD_HEADER_LEN];
        header[0..4].copy_from_slice(&saturate(original_len).to_be_bytes());
        header[4..8].copy_from_slice(&saturate(packet.len()).to_be_bytes());
        header[8..12].copy_from_slice(&flags.to_be_bytes());
        // 12..16: cumulative drops, always 0.
        header[16..24].copy_from_slice(&(unix_time_us + UNIX_EPOCH_US).to_be_bytes());
        header
    }

    fn saturate(len: usize) -> u32 {
        u32::try_from(len).unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    fn frame<const N: usize>(chunks: &[&[u8]]) -> Vec<(Vec<u8>, usize)> {
        let mut framer = H4Framer::<N>::new();
        let mut packets = Vec::new();
        for chunk in chunks {
            framer.push(chunk, |packet, len| packets.push((packet.to_vec(), len)));
        }
        packets
    }

    const RESET: &[u8] = &[0x01, 0x03, 0x0c, 0x00];
    const RESET_COMPLETE: &[u8] = &[0x04, 0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00];

    #[test]
    fn command_without_parameters() {
        assert_eq!(frame::<16>(&[RESET]), [(RESET.to_vec(), 4)]);
    }

    #[test]
    fn packets_split_across_reads() {
        // How bt-hci-serial reads: indicator, header, then payload.
        let packets = frame::<16>(&[&[0x04], &[0x0e, 0x04], &[0x01, 0x03, 0x0c, 0x00]]);
        assert_eq!(packets, [(RESET_COMPLETE.to_vec(), 7)]);
    }

    #[test]
    fn several_packets_in_one_read() {
        let mut both = RESET.to_vec();
        both.extend_from_slice(RESET_COMPLETE);
        let packets = frame::<16>(&[&both]);
        assert_eq!(packets, [(RESET.to_vec(), 4), (RESET_COMPLETE.to_vec(), 7)]);
    }

    #[test]
    fn acl_length_is_16_bit() {
        let mut acl = std::vec![0x02, 0x01, 0x20, 0x00, 0x01];
        acl.extend(core::iter::repeat_n(0xaa, 256));
        let packets = frame::<300>(&[&acl]);
        assert_eq!(packets, [(acl.clone(), 261)]);
    }

    #[test]
    fn long_packet_is_truncated() {
        let mut acl = std::vec![0x02, 0x01, 0x20, 0x08, 0x00];
        acl.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let packets = frame::<8>(&[&acl, RESET]);
        assert_eq!(packets, [(acl[..8].to_vec(), 13), (RESET.to_vec(), 4)]);
    }

    #[test]
    fn unknown_indicator_resyncs() {
        let packets = frame::<16>(&[&[0xff], RESET]);
        assert_eq!(packets, [(std::vec![0xff], 1), (RESET.to_vec(), 4)]);
    }

    #[test]
    fn btsnoop_file_header() {
        assert_eq!(&btsnoop::FILE_HEADER[..8], b"btsnoop\0");
        assert_eq!(
            u32::from_be_bytes(btsnoop::FILE_HEADER[8..12].try_into().unwrap()),
            1
        );
        assert_eq!(
            u32::from_be_bytes(btsnoop::FILE_HEADER[12..16].try_into().unwrap()),
            1002
        );
    }

    #[test]
    fn btsnoop_record_header() {
        let header = btsnoop::record_header(Direction::ControllerToHost, RESET_COMPLETE, 7, 0);
        assert_eq!(&header[0..4], &7u32.to_be_bytes());
        assert_eq!(&header[4..8], &7u32.to_be_bytes());
        // Received, and an event.
        assert_eq!(&header[8..12], &3u32.to_be_bytes());
        assert_eq!(&header[12..16], &[0; 4]);
        assert_eq!(&header[16..24], &0x00dc_ddb3_0f2f_8000u64.to_be_bytes());

        let acl = [0x02, 0x01, 0x20, 0x00, 0x00];
        let header = btsnoop::record_header(Direction::HostToController, &acl, 5, 1);
        // Sent, and data.
        assert_eq!(&header[8..12], &0u32.to_be_bytes());
        assert_eq!(&header[16..24], &0x00dc_ddb3_0f2f_8001u64.to_be_bytes());
    }
}
