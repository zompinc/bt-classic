//! RFCOMM as the responding side (Bluetooth RFCOMM 1.2 over 3GPP TS 07.10):
//! serial-port channels that a peer opens over an L2CAP channel on PSM 3.
//!
//! Like the other protocol layers it does no I/O. The runner tells it when
//! an RFCOMM L2CAP channel opens or closes and hands it each SDU; it returns
//! data that arrived on a channel and builds the frames to send, which
//! [`Rfcomm::pop_outbound`] produces one at a time: control frames first,
//! then data from each channel's transmit buffer as credits allow.
//!
//! Supported: the multiplexer on DLCI 0, PN (parameter negotiation),
//! credit-based flow control, MSC, RPN, RLS and Test answered, NSC for the
//! rest. Not supported: opening a session or channel ourselves, and
//! aggregate flow control (FCon/FCoff are acknowledged but ignored).

/// RFCOMM's L2CAP PSM.
pub const PSM: u16 = crate::l2cap::psm::RFCOMM;

/// How many RFCOMM sessions (one per L2CAP channel) can exist at once.
pub const MAX_SESSIONS: usize = 2;
/// How many data channels can be open across all sessions.
pub const MAX_DLCS: usize = 4;
/// How many server channels can be registered.
pub const MAX_SERVERS: usize = 4;
/// Bytes each channel can buffer for sending.
pub const TX_BUFFER: usize = 1024;
/// The largest information field we accept: what fits in one L2CAP SDU of
/// our MTU after the frame header and FCS.
pub const MAX_FRAME: usize = crate::l2cap::MTU as usize - 6;
/// The frame size assumed when PN does not negotiate one.
pub const DEFAULT_FRAME: u16 = 127;
/// Credits we keep the peer topped up to. Each credit lets it send one frame
/// before we have handled it, so this bounds what can queue up in the
/// runner.
pub const RX_CREDITS: u8 = 4;

/// Frame types (TS 07.10, 5.2.1.3), P/F bit clear.
mod control {
    pub const SABM: u8 = 0x2f;
    pub const UA: u8 = 0x63;
    pub const DM: u8 = 0x0f;
    pub const DISC: u8 = 0x43;
    pub const UIH: u8 = 0xef;
    pub const PF: u8 = 0x10;
}

/// Multiplexer control message types (TS 07.10, 5.4.6.3).
mod mcc {
    pub const PN: u8 = 0x20;
    pub const TEST: u8 = 0x08;
    pub const FCON: u8 = 0x28;
    pub const FCOFF: u8 = 0x18;
    pub const MSC: u8 = 0x38;
    pub const NSC: u8 = 0x04;
    pub const RPN: u8 = 0x24;
    pub const RLS: u8 = 0x14;
}

/// The TS 07.10 FCS table: CRC-8, x^8 + x^2 + x + 1, reflected.
const CRC_TABLE: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u8;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xe0
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// The frame check sequence over `bytes`.
pub fn fcs(bytes: &[u8]) -> u8 {
    0xff - bytes
        .iter()
        .fold(0xff, |crc, &b| CRC_TABLE[usize::from(crc ^ b)])
}

/// A data channel: the L2CAP channel its session runs on and its DLCI
/// (server channel times two, plus the direction bit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Dlc {
    pub l2cap_cid: u16,
    pub dlci: u8,
}

impl Dlc {
    /// The server channel, 1 to 30.
    pub fn channel(&self) -> u8 {
        self.dlci >> 1
    }
}

/// A channel opening or closing, from [`Rfcomm::pop_event`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RfcommEvent {
    Opened(Dlc),
    Closed(Dlc),
}

/// Data that arrived on an open channel.
#[derive(Debug, PartialEq, Eq)]
pub struct Received<'a> {
    pub dlc: Dlc,
    pub data: &'a [u8],
}

/// A frame to send on an L2CAP channel.
pub struct Frame {
    pub l2cap_cid: u16,
    len: usize,
    bytes: [u8; MAX_FRAME + 6],
}

impl Frame {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Why [`Rfcomm::send`] did not take the data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SendError {
    /// No open channel.
    NotOpen,
    /// The transmit buffer has less room than the data needs; `room` bytes
    /// would fit.
    Full { room: usize },
}

struct Session {
    l2cap_cid: u16,
    /// The largest RFCOMM frame the L2CAP channel carries.
    l2cap_mtu: u16,
    open: bool,
}

struct DlcState {
    dlc: Dlc,
    open: bool,
    /// Negotiated with PN; [`DEFAULT_FRAME`] otherwise.
    frame_size: u16,
    credit_flow: bool,
    /// Frames we may still send.
    tx_credits: u16,
    /// Frames the peer may still send.
    rx_credits: u8,
    tx: [u8; TX_BUFFER],
    tx_start: usize,
    tx_len: usize,
}

/// A small control frame waiting to go out.
#[derive(Clone, Copy)]
struct Control {
    l2cap_cid: u16,
    len: usize,
    bytes: [u8; 16],
}

/// The RFCOMM layer. See the [module docs](self).
pub struct Rfcomm {
    servers: [Option<u8>; MAX_SERVERS],
    sessions: [Option<Session>; MAX_SESSIONS],
    dlcs: [Option<DlcState>; MAX_DLCS],
    control: [Option<Control>; 8],
    events: [Option<RfcommEvent>; 4],
    /// Round-robin start for data frames.
    next_dlc: usize,
}

impl Default for Rfcomm {
    fn default() -> Self {
        Self::new()
    }
}

impl Rfcomm {
    pub const fn new() -> Self {
        Self {
            servers: [None; MAX_SERVERS],
            sessions: [const { None }; MAX_SESSIONS],
            dlcs: [const { None }; MAX_DLCS],
            control: [None; 8],
            events: [None; 4],
            next_dlc: 0,
        }
    }

    /// Accepts connections to server `channel` (1 to 30). Returns false if
    /// the table is full or the channel is out of range.
    pub fn register(&mut self, channel: u8) -> bool {
        if !(1..=30).contains(&channel) {
            return false;
        }
        if self.servers.contains(&Some(channel)) {
            return true;
        }
        match self.servers.iter_mut().find(|s| s.is_none()) {
            Some(slot) => {
                *slot = Some(channel);
                true
            }
            None => false,
        }
    }

    /// An RFCOMM L2CAP channel opened; `l2cap_mtu` is the largest SDU the
    /// peer accepts on it.
    pub fn l2cap_opened(&mut self, l2cap_cid: u16, l2cap_mtu: u16) {
        self.l2cap_closed(l2cap_cid);
        if let Some(slot) = self.sessions.iter_mut().find(|s| s.is_none()) {
            *slot = Some(Session {
                l2cap_cid,
                l2cap_mtu,
                open: false,
            });
        }
    }

    /// An RFCOMM L2CAP channel closed: its channels close too.
    pub fn l2cap_closed(&mut self, l2cap_cid: u16) {
        for session in &mut self.sessions {
            if session.as_ref().is_some_and(|s| s.l2cap_cid == l2cap_cid) {
                *session = None;
            }
        }
        for i in 0..MAX_DLCS {
            if let Some(state) = &self.dlcs[i]
                && state.dlc.l2cap_cid == l2cap_cid
            {
                let (dlc, was_open) = (state.dlc, state.open);
                self.dlcs[i] = None;
                if was_open {
                    self.push_event(RfcommEvent::Closed(dlc));
                }
            }
        }
    }

    /// Whether `dlc` is open.
    pub fn is_open(&self, dlc: Dlc) -> bool {
        self.state(dlc).is_some_and(|s| s.open)
    }

    /// Bytes `dlc` can still buffer for sending.
    pub fn room(&self, dlc: Dlc) -> usize {
        self.state(dlc).map_or(0, |s| TX_BUFFER - s.tx_len)
    }

    /// Queues `data` for `dlc`, all or nothing. It goes out in frames as
    /// credits allow.
    pub fn send(&mut self, dlc: Dlc, data: &[u8]) -> Result<(), SendError> {
        let state = self
            .state_mut(dlc)
            .filter(|s| s.open)
            .ok_or(SendError::NotOpen)?;
        let room = TX_BUFFER - state.tx_len;
        if data.len() > room {
            return Err(SendError::Full { room });
        }
        for &b in data {
            state.tx[(state.tx_start + state.tx_len) % TX_BUFFER] = b;
            state.tx_len += 1;
        }
        Ok(())
    }

    /// The next channel event.
    pub fn pop_event(&mut self) -> Option<RfcommEvent> {
        let first = self.events.iter().position(Option::is_some)?;
        let event = self.events[first].take();
        self.events[first..].rotate_left(1);
        event
    }

    /// Handles one SDU from RFCOMM L2CAP channel `l2cap_cid`. Returns the
    /// data it carries for an open channel, if any.
    pub fn on_data<'f>(&mut self, l2cap_cid: u16, frame: &'f [u8]) -> Option<Received<'f>> {
        let (&address, rest) = frame.split_first()?;
        let (&ctrl, rest) = rest.split_first()?;
        let dlci = address >> 2;
        let (len, header_len, rest) = match rest.split_first()? {
            (&b, rest) if b & 1 == 1 => (usize::from(b >> 1), 3, rest),
            (&b, rest) => {
                let (&hi, rest) = rest.split_first()?;
                (usize::from(b >> 1) | usize::from(hi) << 7, 4, rest)
            }
        };
        let kind = ctrl & !control::PF;
        let pf = ctrl & control::PF != 0;
        let has_credits = kind == control::UIH && pf && dlci != 0;
        let info_start = usize::from(has_credits);
        if rest.len() < info_start + len + 1 {
            return None;
        }
        let checked = if kind == control::UIH { 2 } else { header_len };
        if fcs(&frame[..checked]) != rest[info_start + len] {
            return None;
        }
        let credits = if has_credits { rest[0] } else { 0 };
        let info_range =
            (frame.len() - rest.len() + info_start)..(frame.len() - rest.len() + info_start + len);

        match kind {
            control::SABM if dlci == 0 => {
                if let Some(session) = self.session_mut(l2cap_cid) {
                    session.open = true;
                    self.queue_frame(l2cap_cid, 0, control::UA | control::PF, true, &[]);
                }
                None
            }
            control::SABM => {
                self.on_open_dlc(l2cap_cid, dlci);
                None
            }
            control::DISC if dlci == 0 => {
                self.queue_frame(l2cap_cid, 0, control::UA | control::PF, true, &[]);
                // The peer closes the L2CAP channel next; close channels now.
                let cid = l2cap_cid;
                self.l2cap_closed(cid);
                if let Some(slot) = self.sessions.iter_mut().find(|s| s.is_none()) {
                    *slot = Some(Session {
                        l2cap_cid: cid,
                        l2cap_mtu: crate::l2cap::MIN_MTU,
                        open: false,
                    });
                }
                None
            }
            control::DISC => {
                let dlc = Dlc { l2cap_cid, dlci };
                let response = if self.state(dlc).is_some() {
                    control::UA
                } else {
                    control::DM
                };
                self.queue_frame(l2cap_cid, dlci, response | control::PF, true, &[]);
                self.close(dlc);
                None
            }
            control::UA | control::DM => None, // we send no commands that expect these
            control::UIH if dlci == 0 => {
                let mut message = [0u8; 64];
                let n = len.min(message.len());
                message[..n].copy_from_slice(&frame[info_range][..n]);
                self.on_mcc(l2cap_cid, &message[..n]);
                None
            }
            control::UIH => {
                let dlc = Dlc { l2cap_cid, dlci };
                let state = self.state_mut(dlc).filter(|s| s.open)?;
                if state.credit_flow {
                    state.tx_credits = state.tx_credits.saturating_add(u16::from(credits));
                    if len > 0 {
                        state.rx_credits = state.rx_credits.saturating_sub(1);
                    }
                }
                if len == 0 {
                    return None;
                }
                Some(Received {
                    dlc,
                    data: &frame[info_range],
                })
            }
            _ => None,
        }
    }

    /// The next frame to send: control frames first, then credit grants
    /// and data, round-robin over channels.
    pub fn pop_outbound(&mut self) -> Option<Frame> {
        if let Some(first) = self.control.iter().position(Option::is_some) {
            let control = self.control[first].take()?;
            self.control[first..].rotate_left(1);
            let mut frame = Frame {
                l2cap_cid: control.l2cap_cid,
                len: control.len,
                bytes: [0; MAX_FRAME + 6],
            };
            frame.bytes[..control.len].copy_from_slice(&control.bytes[..control.len]);
            return Some(frame);
        }

        for step in 0..MAX_DLCS {
            let i = (self.next_dlc + step) % MAX_DLCS;
            let Some(state) = self.dlcs[i].as_mut().filter(|s| s.open) else {
                continue;
            };
            let grant = if state.credit_flow && state.rx_credits <= RX_CREDITS / 2 {
                RX_CREDITS - state.rx_credits
            } else {
                0
            };
            let can_send = state.tx_len > 0 && (!state.credit_flow || state.tx_credits > 0);
            if grant == 0 && !can_send {
                continue;
            }
            let l2cap_mtu = self
                .sessions
                .iter()
                .flatten()
                .find(|s| s.l2cap_cid == state.dlc.l2cap_cid)
                .map_or(crate::l2cap::MIN_MTU, |s| s.l2cap_mtu);
            // Header (up to 4), credit byte, FCS.
            let fits = usize::from(l2cap_mtu).saturating_sub(6);
            let size = usize::from(state.frame_size).min(fits).min(MAX_FRAME);
            let n = if can_send { state.tx_len.min(size) } else { 0 };

            let mut frame = Frame {
                l2cap_cid: state.dlc.l2cap_cid,
                len: 0,
                bytes: [0; MAX_FRAME + 6],
            };
            let ctrl = if grant > 0 {
                control::UIH | control::PF
            } else {
                control::UIH
            };
            let mut at = header(&mut frame.bytes, state.dlc.dlci, ctrl, false, n);
            if grant > 0 {
                frame.bytes[at] = grant;
                at += 1;
                state.rx_credits += grant;
            }
            for k in 0..n {
                frame.bytes[at + k] = state.tx[(state.tx_start + k) % TX_BUFFER];
            }
            at += n;
            state.tx_start = (state.tx_start + n) % TX_BUFFER;
            state.tx_len -= n;
            if n > 0 && state.credit_flow {
                state.tx_credits -= 1;
            }
            frame.bytes[at] = fcs(&frame.bytes[..2]);
            frame.len = at + 1;
            self.next_dlc = (i + 1) % MAX_DLCS;
            return Some(frame);
        }
        None
    }

    fn on_open_dlc(&mut self, l2cap_cid: u16, dlci: u8) {
        let session_open = self.session(l2cap_cid).is_some_and(|s| s.open);
        let served = self.servers.contains(&Some(dlci >> 1));
        let dlc = Dlc { l2cap_cid, dlci };
        if !session_open || !served {
            self.close(dlc);
            return self.queue_frame(l2cap_cid, dlci, control::DM | control::PF, true, &[]);
        }
        // PN may have created the state already; otherwise defaults.
        if self.state(dlc).is_none() && !self.new_dlc(dlc, DEFAULT_FRAME, false, 0) {
            return self.queue_frame(l2cap_cid, dlci, control::DM | control::PF, true, &[]);
        }
        self.queue_frame(l2cap_cid, dlci, control::UA | control::PF, true, &[]);
        if let Some(state) = self.state_mut(dlc) {
            let first = !state.open;
            state.open = true;
            if first {
                self.push_event(RfcommEvent::Opened(dlc));
                // Our modem status: RTC, RTR and DV on, flow not stopped.
                self.queue_mcc(l2cap_cid, mcc::MSC, true, &[(dlci << 2) | 0x03, 0x8d]);
            }
        }
    }

    fn new_dlc(&mut self, dlc: Dlc, frame_size: u16, credit_flow: bool, tx_credits: u16) -> bool {
        let Some(slot) = self.dlcs.iter_mut().find(|d| d.is_none()) else {
            return false;
        };
        *slot = Some(DlcState {
            dlc,
            open: false,
            frame_size,
            credit_flow,
            tx_credits,
            rx_credits: if credit_flow { RX_CREDITS } else { 0 },
            tx: [0; TX_BUFFER],
            tx_start: 0,
            tx_len: 0,
        });
        true
    }

    fn close(&mut self, dlc: Dlc) {
        for slot in &mut self.dlcs {
            if let Some(state) = slot
                && state.dlc == dlc
            {
                let was_open = state.open;
                *slot = None;
                if was_open {
                    self.push_event(RfcommEvent::Closed(dlc));
                }
                return;
            }
        }
    }

    fn on_mcc(&mut self, l2cap_cid: u16, message: &[u8]) {
        let Some((&type_byte, rest)) = message.split_first() else {
            return;
        };
        let Some((&len_byte, value)) = rest.split_first() else {
            return;
        };
        // Two-byte lengths never occur for the messages we answer.
        if len_byte & 1 == 0 {
            return;
        }
        let len = usize::from(len_byte >> 1).min(value.len());
        let value = &value[..len];
        let command = type_byte & 0x02 != 0;
        let kind = type_byte >> 2;
        if !command {
            return; // responses to our MSC
        }
        match kind {
            mcc::PN if value.len() >= 8 => self.on_pn(l2cap_cid, value),
            mcc::MSC if !value.is_empty() => {
                self.queue_mcc(l2cap_cid, mcc::MSC, false, value);
            }
            // Port settings and line status: accept what the peer says.
            mcc::RPN | mcc::RLS | mcc::TEST | mcc::FCON | mcc::FCOFF => {
                self.queue_mcc(l2cap_cid, kind, false, value);
            }
            _ => self.queue_mcc(l2cap_cid, mcc::NSC, false, &[type_byte]),
        }
    }

    /// Parameter negotiation for a channel about to open (TS 07.10, 5.4.6.3.1
    /// and RFCOMM 5.5.3).
    fn on_pn(&mut self, l2cap_cid: u16, value: &[u8]) {
        let dlci = value[0] & 0x3f;
        let credit_flow = value[1] & 0xf0 == 0xf0;
        let priority = value[2];
        let wanted = u16::from_le_bytes([value[4], value[5]]);
        let peer_credits = u16::from(value[7] & 0x07);
        let l2cap_mtu = self
            .session(l2cap_cid)
            .map_or(crate::l2cap::MIN_MTU, |s| s.l2cap_mtu);
        let frame_size = wanted
            .min(MAX_FRAME as u16)
            .min(l2cap_mtu.saturating_sub(6))
            .max(1);

        let dlc = Dlc { l2cap_cid, dlci };
        let served = self.servers.contains(&Some(dlci >> 1));
        if !served {
            return self.queue_frame(l2cap_cid, dlci, control::DM | control::PF, true, &[]);
        }
        match self.state_mut(dlc) {
            Some(state) if !state.open => {
                state.frame_size = frame_size;
                state.credit_flow = credit_flow;
                state.tx_credits = peer_credits;
                state.rx_credits = if credit_flow { RX_CREDITS } else { 0 };
            }
            Some(_) => {}
            None => {
                if !self.new_dlc(dlc, frame_size, credit_flow, peer_credits) {
                    return self.queue_frame(l2cap_cid, dlci, control::DM | control::PF, true, &[]);
                }
            }
        }
        let size = frame_size.to_le_bytes();
        let (cl, k) = if credit_flow {
            (0xe0, RX_CREDITS)
        } else {
            (0x00, 0)
        };
        self.queue_mcc(
            l2cap_cid,
            mcc::PN,
            false,
            &[dlci, cl, priority, 0, size[0], size[1], 0, k],
        );
    }

    /// Queues a multiplexer control message on DLCI 0.
    fn queue_mcc(&mut self, l2cap_cid: u16, kind: u8, command: bool, value: &[u8]) {
        let mut message = [0u8; 12];
        message[0] = (kind << 2) | (u8::from(command) << 1) | 1;
        message[1] = ((value.len() as u8) << 1) | 1;
        let n = value.len().min(message.len() - 2);
        message[2..2 + n].copy_from_slice(&value[..n]);
        self.queue_frame(l2cap_cid, 0, control::UIH, false, &message[..2 + n]);
    }

    /// Queues a frame we build: `response` sets C/R as a responder's
    /// response, UIH frames use the command C/R.
    fn queue_frame(&mut self, l2cap_cid: u16, dlci: u8, ctrl: u8, response: bool, info: &[u8]) {
        let Some(slot) = self.control.iter_mut().find(|c| c.is_none()) else {
            return;
        };
        let mut bytes = [0u8; 16];
        let at = header(&mut bytes, dlci, ctrl, response, info.len());
        bytes[at..at + info.len()].copy_from_slice(info);
        let checked = if ctrl & !control::PF == control::UIH {
            2
        } else {
            at
        };
        bytes[at + info.len()] = fcs(&bytes[..checked]);
        *slot = Some(Control {
            l2cap_cid,
            len: at + info.len() + 1,
            bytes,
        });
    }

    fn push_event(&mut self, event: RfcommEvent) {
        if let Some(slot) = self.events.iter_mut().find(|e| e.is_none()) {
            *slot = Some(event);
        }
    }

    fn session(&self, l2cap_cid: u16) -> Option<&Session> {
        self.sessions
            .iter()
            .flatten()
            .find(|s| s.l2cap_cid == l2cap_cid)
    }

    fn session_mut(&mut self, l2cap_cid: u16) -> Option<&mut Session> {
        self.sessions
            .iter_mut()
            .flatten()
            .find(|s| s.l2cap_cid == l2cap_cid)
    }

    fn state(&self, dlc: Dlc) -> Option<&DlcState> {
        self.dlcs.iter().flatten().find(|s| s.dlc == dlc)
    }

    fn state_mut(&mut self, dlc: Dlc) -> Option<&mut DlcState> {
        self.dlcs.iter_mut().flatten().find(|s| s.dlc == dlc)
    }
}

/// Writes address, control and length into `out`; returns where the
/// information field starts. We are the responder: our commands and UIH
/// frames carry C/R 0, our responses C/R 1.
fn header(out: &mut [u8], dlci: u8, ctrl: u8, response: bool, len: usize) -> usize {
    out[0] = (dlci << 2) | (u8::from(response) << 1) | 1;
    out[1] = ctrl;
    if len <= 127 {
        out[2] = ((len as u8) << 1) | 1;
        3
    } else {
        out[2] = ((len & 0x7f) as u8) << 1;
        out[3] = (len >> 7) as u8;
        4
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    const CID: u16 = 0x0041;

    #[test]
    fn fcs_matches_known_frames() {
        // SABM on DLCI 0 from an initiator, and the UA answering it.
        assert_eq!(fcs(&[0x03, 0x3f, 0x01]), 0x1c);
        assert_eq!(fcs(&[0x03, 0x73, 0x01]), 0xd7);
        // DISC on DLCI 0.
        assert_eq!(fcs(&[0x03, 0x53, 0x01]), 0xfd);
    }

    /// A frame from the initiator (C/R 1 on commands and UIH).
    fn from_peer(dlci: u8, ctrl: u8, info: &[u8]) -> Vec<u8> {
        let mut f = std::vec![(dlci << 2) | 0x03, ctrl];
        if info.len() <= 127 {
            f.push(((info.len() as u8) << 1) | 1);
        } else {
            f.push(((info.len() & 0x7f) as u8) << 1);
            f.push((info.len() >> 7) as u8);
        }
        let checked = if ctrl & !control::PF == control::UIH {
            2
        } else {
            f.len()
        };
        f.extend_from_slice(info);
        f.push(fcs(&f[..checked]));
        f
    }

    /// A UIH data frame from the peer granting `credits`.
    fn data_from_peer(dlci: u8, credits: Option<u8>, data: &[u8]) -> Vec<u8> {
        let ctrl = if credits.is_some() {
            control::UIH | control::PF
        } else {
            control::UIH
        };
        let mut f = std::vec![(dlci << 2) | 0x03, ctrl];
        f.push(((data.len() as u8) << 1) | 1);
        if let Some(c) = credits {
            f.push(c);
        }
        f.extend_from_slice(data);
        f.push(fcs(&f[..2]));
        f
    }

    fn outbound(rfcomm: &mut Rfcomm) -> Vec<Vec<u8>> {
        core::iter::from_fn(|| rfcomm.pop_outbound().map(|f| f.as_bytes().to_vec())).collect()
    }

    fn rfcomm() -> Rfcomm {
        let mut rfcomm = Rfcomm::new();
        assert!(rfcomm.register(8));
        rfcomm.l2cap_opened(CID, 672);
        rfcomm
    }

    /// Opens the session and channel 8 (DLCI 17) with PN asking for credit
    /// flow, frame size 1000 and 7 initial credits for us.
    fn open(rfcomm: &mut Rfcomm) -> Dlc {
        assert!(rfcomm.on_data(CID, &from_peer(0, 0x3f, &[])).is_none());
        assert_eq!(outbound(rfcomm), [std::vec![0x03, 0x73, 0x01, 0xd7]]);

        // PN command: DLCI 17, CL 0xF, priority 7, frame 1000, k 7.
        let pn = [0x83, 0x11, 17, 0xf0, 7, 0, 0xe8, 0x03, 0, 7];
        rfcomm.on_data(CID, &from_peer(0, control::UIH, &pn));
        // PN response: CL 0xE, frame size capped to what one L2CAP SDU of 672 holds, k 4.
        let size = (672u16 - 6).to_le_bytes();
        let mut response = std::vec![
            0x01,
            control::UIH,
            (10 << 1) | 1,
            0x81,
            0x11,
            17,
            0xe0,
            7,
            0,
            size[0],
            size[1],
            0,
            4
        ];
        response.push(fcs(&response[..2]));
        assert_eq!(outbound(rfcomm), [response]);

        rfcomm.on_data(CID, &from_peer(17, 0x3f, &[]));
        let out = outbound(rfcomm);
        // UA on DLCI 17, our MSC command, then a credit grant? No: we granted 4 in PN.
        assert_eq!(out[0], {
            let mut ua = std::vec![(17 << 2) | 0x03, 0x73, 0x01];
            ua.push(fcs(&ua));
            ua
        });
        assert_eq!(&out[1][3..7], &[0xe3, 0x05, (17 << 2) | 0x03, 0x8d]);
        assert_eq!(out.len(), 2);
        let dlc = Dlc {
            l2cap_cid: CID,
            dlci: 17,
        };
        assert_eq!(rfcomm.pop_event(), Some(RfcommEvent::Opened(dlc)));
        dlc
    }

    #[test]
    fn opens_a_channel_with_credit_flow() {
        let mut rfcomm = rfcomm();
        let dlc = open(&mut rfcomm);
        assert_eq!(dlc.channel(), 8);

        // The peer's MSC command is answered with a response.
        let msc = [0xe3, 0x05, (17 << 2) | 0x03, 0x8d];
        rfcomm.on_data(CID, &from_peer(0, control::UIH, &msc));
        let out = outbound(&mut rfcomm);
        assert_eq!(&out[0][3..7], &[0xe1, 0x05, (17 << 2) | 0x03, 0x8d]);
    }

    #[test]
    fn data_spends_and_replenishes_credits() {
        let mut rfcomm = rfcomm();
        let dlc = open(&mut rfcomm);

        // Peer data arrives; after two frames the peer is down to half, so
        // the next outbound frame carries a grant.
        let hello = data_from_peer(17, None, b"hello");
        let got = rfcomm.on_data(CID, &hello).unwrap();
        assert_eq!(got.data, b"hello");
        assert!(outbound(&mut rfcomm).is_empty());
        rfcomm.on_data(CID, &data_from_peer(17, None, b"again"));
        let out = outbound(&mut rfcomm);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0][1], control::UIH | control::PF);
        assert_eq!(out[0][2], 0x01); // no data
        assert_eq!(out[0][3], 2); // two credits back

        // We have 7 credits from PN: 7 frames go out, then we wait.
        for _ in 0..8 {
            rfcomm.send(dlc, b"x").unwrap();
            let _ = outbound(&mut rfcomm);
        }
        rfcomm.send(dlc, b"y").unwrap();
        assert!(outbound(&mut rfcomm).is_empty(), "out of credits");
        rfcomm.on_data(CID, &data_from_peer(17, Some(3), &[]));
        let out = outbound(&mut rfcomm);
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0][3..out[0].len() - 1], b"xy");
    }

    #[test]
    fn long_data_is_split_by_frame_size() {
        let mut rfcomm = rfcomm();
        let dlc = open(&mut rfcomm);
        let data: Vec<u8> = (0..1000u16).map(|i| i as u8).collect();
        rfcomm.send(dlc, &data).unwrap();
        let out = outbound(&mut rfcomm);
        let mut sent = Vec::new();
        for frame in &out {
            assert!(frame.len() <= 672);
            let (len, start) = if frame[2] & 1 == 1 {
                (usize::from(frame[2] >> 1), 3)
            } else {
                (usize::from(frame[2] >> 1) | usize::from(frame[3]) << 7, 4)
            };
            sent.extend_from_slice(&frame[start..start + len]);
            assert_eq!(*frame.last().unwrap(), fcs(&frame[..2]));
        }
        assert_eq!(out.len(), 2);
        assert_eq!(sent, data);
    }

    #[test]
    fn without_pn_there_is_no_credit_flow() {
        let mut rfcomm = rfcomm();
        rfcomm.on_data(CID, &from_peer(0, 0x3f, &[]));
        rfcomm.on_data(CID, &from_peer(17, 0x3f, &[]));
        let _ = outbound(&mut rfcomm);
        let dlc = Dlc {
            l2cap_cid: CID,
            dlci: 17,
        };
        rfcomm.send(dlc, &[1u8; 300]).unwrap();
        let out = outbound(&mut rfcomm);
        // The default frame size, 127 bytes, and no credit bytes.
        assert_eq!(out.len(), 3);
        assert_eq!(out[0][1], control::UIH);
        assert_eq!(out[0][2], (127 << 1) | 1);
    }

    #[test]
    fn unknown_channel_gets_dm() {
        let mut rfcomm = rfcomm();
        rfcomm.on_data(CID, &from_peer(0, 0x3f, &[]));
        let _ = outbound(&mut rfcomm);
        rfcomm.on_data(CID, &from_peer(9, 0x3f, &[])); // channel 4
        let out = outbound(&mut rfcomm);
        assert_eq!(out[0][..2], [(9 << 2) | 0x03, 0x1f]);
        assert_eq!(rfcomm.pop_event(), None);
    }

    #[test]
    fn disc_closes_the_channel() {
        let mut rfcomm = rfcomm();
        let dlc = open(&mut rfcomm);
        rfcomm.on_data(CID, &from_peer(17, 0x53, &[]));
        let out = outbound(&mut rfcomm);
        assert_eq!(out[0][..2], [(17 << 2) | 0x03, 0x73]);
        assert_eq!(rfcomm.pop_event(), Some(RfcommEvent::Closed(dlc)));
        assert_eq!(rfcomm.send(dlc, b"x"), Err(SendError::NotOpen));
    }

    #[test]
    fn unknown_mcc_gets_nsc_and_test_echoes() {
        let mut rfcomm = rfcomm();
        rfcomm.on_data(CID, &from_peer(0, 0x3f, &[]));
        let _ = outbound(&mut rfcomm);
        rfcomm.on_data(CID, &from_peer(0, control::UIH, &[0x7f, 0x01]));
        rfcomm.on_data(CID, &from_peer(0, control::UIH, &[0x23, 0x05, 0xaa, 0xbb]));
        let out = outbound(&mut rfcomm);
        assert_eq!(&out[0][3..6], &[0x11, 0x03, 0x7f]);
        assert_eq!(&out[1][3..7], &[0x21, 0x05, 0xaa, 0xbb]);
    }

    #[test]
    fn bad_fcs_is_ignored() {
        let mut rfcomm = rfcomm();
        let mut sabm = from_peer(0, 0x3f, &[]);
        *sabm.last_mut().unwrap() ^= 0xff;
        rfcomm.on_data(CID, &sabm);
        assert!(outbound(&mut rfcomm).is_empty());
    }

    #[test]
    fn l2cap_close_closes_channels() {
        let mut rfcomm = rfcomm();
        let dlc = open(&mut rfcomm);
        rfcomm.l2cap_closed(CID);
        assert_eq!(rfcomm.pop_event(), Some(RfcommEvent::Closed(dlc)));
        assert!(!rfcomm.is_open(dlc));
    }
}
