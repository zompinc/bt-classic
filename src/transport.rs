//! A transport adapter that keeps incoming ACL packets within bt-hci's read
//! buffer.
//!
//! bt-hci's `ExternalController` reads every packet into a 259-byte buffer,
//! enough for LE but not for BR/EDR, where controllers deliver ACL packets
//! of up to about 1021 bytes. Host_Buffer_Size should make the controller
//! split them (see [`crate::gap::HOST_ACL_DATA_PACKET_LENGTH`]), but not
//! every controller does without host flow control; rootcanal does not.
//!
//! [`SplitAcl`] wraps the transport, reads each packet into its own larger
//! buffer, and hands an oversized ACL packet up as several, the first with
//! the original packet boundary flag and the rest as continuations. L2CAP
//! reassembles them as it does any fragmented PDU.

use core::convert::Infallible;

use bt_hci::transport::{PacketKind, PacketToController, PacketToHost, Transport};
use bt_hci::{ReadHciError, data::AclPacketBoundary};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use embedded_io::ErrorType;
use embedded_io_async::Read;

use crate::gap::HOST_ACL_DATA_PACKET_LENGTH;

/// The largest ACL payload handed up in one piece.
const CHUNK: usize = HOST_ACL_DATA_PACKET_LENGTH as usize;

/// A packet's bytes without the H4 indicator: header and payload.
struct Raw<'a> {
    kind: PacketKind,
    len: usize,
    _bytes: &'a [u8],
}

impl<'a> PacketToHost<'a> for Raw<'a> {
    fn read_hci<R: embedded_io::Read>(
        kind: PacketKind,
        data: &mut R,
        buf: &'a mut [u8],
    ) -> Result<Self, ReadHciError<R::Error>> {
        let header = header_len(kind);
        let head = buf.get_mut(..header).ok_or(ReadHciError::BufferTooSmall)?;
        data.read_exact(head)?;
        let len = header + payload_len(kind, head);
        let rest = buf
            .get_mut(header..len)
            .ok_or(ReadHciError::BufferTooSmall)?;
        data.read_exact(rest)?;
        Ok(Self {
            kind,
            len,
            _bytes: &buf[..len],
        })
    }

    async fn read_hci_async<R: Read>(
        kind: PacketKind,
        data: &mut R,
        buf: &'a mut [u8],
    ) -> Result<Self, ReadHciError<R::Error>> {
        let header = header_len(kind);
        let head = buf.get_mut(..header).ok_or(ReadHciError::BufferTooSmall)?;
        data.read_exact(head).await?;
        let len = header + payload_len(kind, head);
        let rest = buf
            .get_mut(header..len)
            .ok_or(ReadHciError::BufferTooSmall)?;
        data.read_exact(rest).await?;
        Ok(Self {
            kind,
            len,
            _bytes: &buf[..len],
        })
    }
}

fn header_len(kind: PacketKind) -> usize {
    match kind {
        PacketKind::Event => 2,
        PacketKind::Cmd | PacketKind::SyncData => 3,
        PacketKind::AclData | PacketKind::IsoData => 4,
    }
}

fn payload_len(kind: PacketKind, header: &[u8]) -> usize {
    match kind {
        PacketKind::Event => usize::from(header[1]),
        PacketKind::Cmd | PacketKind::SyncData => usize::from(header[2]),
        PacketKind::AclData => usize::from(u16::from_le_bytes([header[2], header[3]])),
        PacketKind::IsoData => usize::from(u16::from_le_bytes([header[2], header[3]]) & 0x3fff),
    }
}

/// The packet being handed up in pieces, and the buffer it was read into.
struct State<const MAX: usize> {
    buf: [u8; MAX],
    /// Handle and broadcast flag of the split packet, boundary flag cleared.
    handle_bits: u16,
    /// Next payload byte to hand up, and where the payload ends.
    next: usize,
    end: usize,
}

/// See the [module docs](self). `MAX` is the largest packet read from the
/// controller, header included; the default fits 1021-byte DH5 payloads.
pub struct SplitAcl<T, const MAX: usize = 1028> {
    inner: T,
    state: Mutex<NoopRawMutex, State<MAX>>,
}

impl<T, const MAX: usize> SplitAcl<T, MAX> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            state: Mutex::new(State {
                buf: [0; MAX],
                handle_bits: 0,
                next: 0,
                end: 0,
            }),
        }
    }
}

impl<T: ErrorType, const MAX: usize> ErrorType for SplitAcl<T, MAX> {
    type Error = T::Error;
}

impl<T, const MAX: usize> Transport for SplitAcl<T, MAX>
where
    T: Transport,
    T::Error: From<ReadHciError<Infallible>>,
{
    async fn read<'a, P: PacketToHost<'a>>(&self, rx: &'a mut [u8]) -> Result<P, Self::Error> {
        let mut state = self.state.lock().await;

        if state.next < state.end {
            return Ok(next_chunk(&mut state, AclPacketBoundary::Continuing, rx).await?);
        }

        let raw: Raw<'_> = self.inner.read(&mut state.buf).await?;
        let (kind, len) = (raw.kind, raw.len);
        if kind == PacketKind::AclData && len - 4 > CHUNK {
            let handle = u16::from_le_bytes([state.buf[0], state.buf[1]]);
            let boundary = match (handle >> 12) & 0x3 {
                0x00 => AclPacketBoundary::FirstNonFlushable,
                0x01 => AclPacketBoundary::Continuing,
                0x02 => AclPacketBoundary::FirstFlushable,
                _ => AclPacketBoundary::Complete,
            };
            state.handle_bits = handle & !(0x3 << 12);
            state.next = 4;
            state.end = len;
            return Ok(next_chunk(&mut state, boundary, rx).await?);
        }

        let mut bytes = &state.buf[..len];
        Ok(P::read_hci_async(kind, &mut bytes, rx).await?)
    }

    async fn write<P: PacketToController>(&self, tx: &P) -> Result<(), Self::Error> {
        self.inner.write(tx).await
    }
}

/// Hands up the next piece of the split ACL packet with `boundary`.
async fn next_chunk<'a, P: PacketToHost<'a>, const MAX: usize>(
    state: &mut State<MAX>,
    boundary: AclPacketBoundary,
    rx: &'a mut [u8],
) -> Result<P, ReadHciError<Infallible>> {
    let n = (state.end - state.next).min(CHUNK);
    let mut packet = [0u8; 4 + CHUNK];
    let handle = state.handle_bits | ((boundary as u16) << 12);
    packet[0..2].copy_from_slice(&handle.to_le_bytes());
    packet[2..4].copy_from_slice(&(n as u16).to_le_bytes());
    packet[4..4 + n].copy_from_slice(&state.buf[state.next..state.next + n]);
    state.next += n;
    if state.next >= state.end {
        state.next = 0;
        state.end = 0;
    }
    let mut bytes = &packet[..4 + n];
    P::read_hci_async(PacketKind::AclData, &mut bytes, rx).await
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use bt_hci::ControllerToHostPacket;
    use bt_hci_serial::SerialTransport;
    use std::vec::Vec;

    /// A writer that discards everything, with the slice reader's error type.
    struct Discard;

    impl embedded_io::ErrorType for Discard {
        type Error = Infallible;
    }

    impl embedded_io_async::Write for Discard {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Infallible> {
            Ok(buf.len())
        }

        async fn flush(&mut self) -> Result<(), Infallible> {
            Ok(())
        }
    }

    /// Reads every packet from `stream` through `SplitAcl` into 259-byte
    /// buffers, as ExternalController does.
    fn read_all(stream: &[u8], count: usize) -> Vec<(u8, Vec<u8>)> {
        let serial: SerialTransport<NoopRawMutex, _, _> = SerialTransport::new(stream, Discard);
        let split: SplitAcl<_> = SplitAcl::new(serial);
        embassy_futures::block_on(async {
            let mut out = Vec::new();
            for _ in 0..count {
                let mut buf = [0u8; 259];
                match split
                    .read::<ControllerToHostPacket<'_>>(&mut buf)
                    .await
                    .unwrap()
                {
                    ControllerToHostPacket::Acl(acl) => {
                        out.push((acl.boundary_flag() as u8, acl.data().to_vec()));
                    }
                    ControllerToHostPacket::Event(event) => out.push((0xee, event.data.to_vec())),
                    _ => panic!("unexpected packet"),
                }
            }
            out
        })
    }

    fn acl(boundary: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = std::vec![0x02];
        let handle = 0x0001u16 | (u16::from(boundary) << 12);
        out.extend_from_slice(&handle.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn splits_an_oversized_acl_packet() {
        let payload: Vec<u8> = (0..600u16).map(|i| i as u8).collect();
        let mut stream = acl(0x02, &payload);
        stream.extend_from_slice(&[0x04, 0x0e, 0x01, 0x05]); // an event after it
        let out = read_all(&stream, 4);
        assert_eq!(out[0], (0x02, payload[..255].to_vec()));
        assert_eq!(out[1], (0x01, payload[255..510].to_vec()));
        assert_eq!(out[2], (0x01, payload[510..].to_vec()));
        assert_eq!(out[3], (0xee, std::vec![0x05]));
    }

    #[test]
    fn passes_small_packets_through() {
        let mut stream = acl(0x02, b"small");
        stream.extend_from_slice(&acl(0x01, &[7u8; 255]));
        let out = read_all(&stream, 2);
        assert_eq!(out[0], (0x02, b"small".to_vec()));
        assert_eq!(out[1], (0x01, std::vec![7u8; 255]));
    }
}
