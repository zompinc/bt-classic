//! L2CAP for BR/EDR in basic mode (Core v5.4, Vol 3, Part A): the
//! signaling channel, dynamic channels opened by either side, and
//! reassembly of ACL fragments.
//!
//! Like [`crate::security`], it does no I/O. Feed it ACL packets with
//! [`L2cap::on_acl`]; it hands back data that arrived on open channels and
//! queues what it wants to send, which [`L2cap::pop_outbound`] drains as
//! complete L2CAP PDUs. Splitting those into controller-sized ACL packets is
//! the runner's job, since it knows the controller's buffers.
//!
//! Not supported: ERTM and streaming modes,
//! connectionless data, and per-PSM security requirements.

use bt_hci::data::AclPacketBoundary;
use bt_hci::param::ConnHandle;

/// The signaling channel on an ACL-U link.
pub const SIGNALING_CID: u16 = 0x0001;
/// The first dynamically allocated channel ID.
pub const FIRST_DYNAMIC_CID: u16 = 0x0040;
/// The MTU every BR/EDR L2CAP implementation must accept.
pub const MIN_MTU: u16 = 48;
/// The MTU assumed when the peer does not say: also what we receive.
pub const MTU: u16 = 672;
/// The largest PDU we reassemble or send: basic header plus [`MTU`].
pub const MAX_PDU: usize = 4 + MTU as usize;

/// Protocol/Service Multiplexer values.
pub mod psm {
    pub const SDP: u16 = 0x0001;
    pub const RFCOMM: u16 = 0x0003;
}

/// How many ACL links L2CAP tracks.
pub const MAX_CONNECTIONS: usize = 2;
/// How many dynamic channels can be open across all links.
pub const MAX_CHANNELS: usize = 6;
/// How many PDUs can wait to be sent.
pub const OUTBOX: usize = 4;
/// How many PSMs can be registered.
pub const MAX_PSMS: usize = 4;

mod code {
    pub const COMMAND_REJECT: u8 = 0x01;
    pub const CONNECTION_REQUEST: u8 = 0x02;
    pub const CONNECTION_RESPONSE: u8 = 0x03;
    pub const CONFIGURATION_REQUEST: u8 = 0x04;
    pub const CONFIGURATION_RESPONSE: u8 = 0x05;
    pub const DISCONNECTION_REQUEST: u8 = 0x06;
    pub const DISCONNECTION_RESPONSE: u8 = 0x07;
    pub const ECHO_REQUEST: u8 = 0x08;
    pub const ECHO_RESPONSE: u8 = 0x09;
    pub const INFORMATION_REQUEST: u8 = 0x0a;
    pub const INFORMATION_RESPONSE: u8 = 0x0b;
}

mod reject {
    pub const NOT_UNDERSTOOD: u16 = 0x0000;
    pub const INVALID_CID: u16 = 0x0002;
}

mod connection {
    pub const SUCCESS: u16 = 0x0000;
    pub const PENDING: u16 = 0x0001;
    pub const PSM_NOT_SUPPORTED: u16 = 0x0002;
    pub const NO_RESOURCES: u16 = 0x0004;
}

mod config {
    pub const SUCCESS: u16 = 0x0000;
    pub const UNACCEPTABLE: u16 = 0x0001;
    pub const UNKNOWN_OPTIONS: u16 = 0x0003;
    pub const CONTINUATION: u16 = 0x0001;

    pub const MTU: u8 = 0x01;
    pub const FLUSH_TIMEOUT: u8 = 0x02;
    pub const QOS: u8 = 0x03;
    pub const RETRANSMISSION: u8 = 0x04;
    pub const FCS: u8 = 0x05;
    pub const HINT: u8 = 0x80;
}

mod info {
    pub const CONNECTIONLESS_MTU: u16 = 0x0001;
    pub const EXTENDED_FEATURES: u16 = 0x0002;
    pub const FIXED_CHANNELS: u16 = 0x0003;
    pub const SUCCESS: u16 = 0x0000;
    pub const NOT_SUPPORTED: u16 = 0x0001;
    /// Extended features: fixed channels supported (bit 7), nothing else.
    pub const FEATURES: u32 = 1 << 7;
    /// Fixed channels: the signaling channel (bit 1).
    pub const CHANNELS: u64 = 1 << 1;
}

/// A dynamic channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Channel {
    pub handle: ConnHandle,
    pub psm: u16,
    /// Our channel ID: where the peer sends.
    pub local_cid: u16,
    /// The peer's channel ID: where we send.
    pub remote_cid: u16,
    /// The largest SDU the peer accepts.
    pub remote_mtu: u16,
    /// We opened it with [`L2cap::connect`].
    pub outgoing: bool,
    /// Our configuration request was accepted.
    ours_done: bool,
    /// We accepted the peer's configuration request.
    theirs_done: bool,
    /// Identifier of our outstanding connection request while `remote_cid`
    /// is 0, then of our outstanding configuration request.
    config_ident: u8,
}

impl Channel {
    /// Both sides are configured: data may flow.
    pub fn is_open(&self) -> bool {
        self.ours_done && self.theirs_done
    }
}

/// A channel opening or closing, from [`L2cap::pop_event`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ChannelEvent {
    Opened(Channel),
    Closed(Channel),
    /// A channel we asked for with [`L2cap::connect`] was refused.
    Failed(Channel),
}

/// Data that arrived on an open channel.
#[derive(Debug, PartialEq, Eq)]
pub struct Received<'a> {
    pub channel: Channel,
    pub data: &'a [u8],
}

/// A PDU to send: basic header included.
#[derive(Clone)]
pub struct Outbound {
    pub handle: ConnHandle,
    len: usize,
    bytes: [u8; MAX_PDU],
}

impl Outbound {
    /// The PDU bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Why [`L2cap::send`] did not queue the data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SendError {
    /// No open channel with that ID.
    NoChannel,
    /// Longer than the peer's MTU.
    TooLong,
    /// The outbox is full; drain it first.
    Busy,
}

/// Reassembly state for one ACL link.
struct Link {
    handle: ConnHandle,
    buf: [u8; MAX_PDU],
    len: usize,
    /// Set when the PDU in progress does not fit; the rest is dropped.
    overflow: bool,
}

/// The L2CAP layer. See the [module docs](self).
pub struct L2cap {
    psms: [Option<u16>; MAX_PSMS],
    links: [Option<Link>; MAX_CONNECTIONS],
    channels: [Option<Channel>; MAX_CHANNELS],
    outbox: [Option<Outbound>; OUTBOX],
    events: [Option<ChannelEvent>; 4],
    next_ident: u8,
    next_cid: u16,
    dropped: u32,
}

impl Default for L2cap {
    fn default() -> Self {
        Self::new()
    }
}

impl L2cap {
    /// An L2CAP layer with no PSMs registered.
    pub const fn new() -> Self {
        Self {
            psms: [None; MAX_PSMS],
            links: [const { None }; MAX_CONNECTIONS],
            channels: [None; MAX_CHANNELS],
            outbox: [const { None }; OUTBOX],
            events: [None; 4],
            next_ident: 1,
            next_cid: FIRST_DYNAMIC_CID,
            dropped: 0,
        }
    }

    /// Accepts connections to `psm`. Returns false if the table is full.
    pub fn register(&mut self, psm: u16) -> bool {
        if self.psms.contains(&Some(psm)) {
            return true;
        }
        match self.psms.iter_mut().find(|p| p.is_none()) {
            Some(slot) => {
                *slot = Some(psm);
                true
            }
            None => false,
        }
    }

    /// An ACL link came up.
    pub fn connected(&mut self, handle: ConnHandle) {
        self.disconnected(handle);
        if let Some(slot) = self.links.iter_mut().find(|l| l.is_none()) {
            *slot = Some(Link {
                handle,
                buf: [0; MAX_PDU],
                len: 0,
                overflow: false,
            });
        }
    }

    /// An ACL link went down: its channels close.
    pub fn disconnected(&mut self, handle: ConnHandle) {
        for link in &mut self.links {
            if link.as_ref().is_some_and(|l| l.handle == handle) {
                *link = None;
            }
        }
        for i in 0..MAX_CHANNELS {
            if let Some(channel) = self.channels[i]
                && channel.handle == handle
            {
                self.channels[i] = None;
                self.push_event(ChannelEvent::Closed(channel));
            }
        }
    }

    /// The channel with our ID `local_cid`.
    pub fn channel(&self, local_cid: u16) -> Option<&Channel> {
        self.channels
            .iter()
            .flatten()
            .find(|c| c.local_cid == local_cid)
    }

    /// An open channel to `psm` on the link `handle`, if any.
    pub fn find(&self, handle: ConnHandle, psm: u16) -> Option<&Channel> {
        self.channels
            .iter()
            .flatten()
            .find(|c| c.handle == handle && c.psm == psm && c.is_open())
    }

    /// How many more PDUs the outbox takes.
    pub fn outbox_room(&self) -> usize {
        self.outbox.iter().filter(|o| o.is_none()).count()
    }

    /// PDUs dropped because the outbox was full.
    pub fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Handles one ACL packet. Returns the SDU it completes on an open
    /// channel, if any; signaling is answered internally.
    pub fn on_acl(
        &mut self,
        handle: ConnHandle,
        boundary: AclPacketBoundary,
        data: &[u8],
    ) -> Option<Received<'_>> {
        let index = self
            .links
            .iter()
            .position(|l| l.as_ref().is_some_and(|l| l.handle == handle))?;
        let link = self.links[index].as_mut()?;

        match boundary {
            AclPacketBoundary::Continuing => {
                if link.len == 0 && !link.overflow {
                    return None; // a continuation without a start
                }
            }
            _ => {
                link.len = 0;
                link.overflow = false;
            }
        }
        if link.overflow {
            return None;
        }
        if link.len + data.len() > link.buf.len() {
            link.overflow = true;
            link.len = 0;
            return None;
        }
        link.buf[link.len..link.len + data.len()].copy_from_slice(data);
        link.len += data.len();

        if link.len < 4 {
            return None;
        }
        let pdu_len = usize::from(u16::from_le_bytes([link.buf[0], link.buf[1]]));
        let total = 4 + pdu_len;
        if total > link.buf.len() {
            link.overflow = true;
            link.len = 0;
            return None;
        }
        if link.len < total {
            return None;
        }
        // Complete. Anything past `total` is malformed and ignored.
        link.len = 0;
        let cid = u16::from_le_bytes([link.buf[2], link.buf[3]]);

        if cid == SIGNALING_CID {
            let mut signal = [0u8; MAX_PDU];
            signal[..pdu_len].copy_from_slice(&link.buf[4..total]);
            self.on_signaling(handle, &signal[..pdu_len]);
            return None;
        }

        let channel = *self
            .channels
            .iter()
            .flatten()
            .find(|c| c.handle == handle && c.local_cid == cid && c.is_open())?;
        let link = self.links[index].as_ref()?;
        Some(Received {
            channel,
            data: &link.buf[4..total],
        })
    }

    /// Queues `data` as one SDU on the open channel `local_cid`.
    pub fn send(&mut self, local_cid: u16, data: &[u8]) -> Result<(), SendError> {
        let channel = *self
            .channels
            .iter()
            .flatten()
            .find(|c| c.local_cid == local_cid && c.is_open())
            .ok_or(SendError::NoChannel)?;
        if data.len() > usize::from(channel.remote_mtu.min(MTU)) {
            return Err(SendError::TooLong);
        }
        if self.outbox.iter().all(Option::is_some) {
            return Err(SendError::Busy);
        }
        self.queue(channel.handle, channel.remote_cid, &[data]);
        Ok(())
    }

    /// Opens a channel to `psm` on the link `handle`. Returns our CID, or
    /// `None` if there is no such link or no room. [`ChannelEvent::Opened`]
    /// follows once both sides are configured, [`ChannelEvent::Failed`] if
    /// the peer refuses.
    pub fn connect(&mut self, handle: ConnHandle, psm: u16) -> Option<u16> {
        if !self.links.iter().flatten().any(|l| l.handle == handle) || self.outbox_room() == 0 {
            return None;
        }
        let slot = self.channels.iter().position(Option::is_none)?;
        let local_cid = self.allocate_cid();
        let ident = self.ident();
        self.channels[slot] = Some(Channel {
            handle,
            psm,
            local_cid,
            remote_cid: 0,
            remote_mtu: MTU,
            outgoing: true,
            ours_done: false,
            theirs_done: false,
            config_ident: ident,
        });
        let (p, c) = (psm.to_le_bytes(), local_cid.to_le_bytes());
        self.signal(
            handle,
            code::CONNECTION_REQUEST,
            ident,
            &[p[0], p[1], c[0], c[1]],
        );
        Some(local_cid)
    }

    /// Closes the channel `local_cid`. [`ChannelEvent::Closed`] follows when
    /// the peer confirms.
    pub fn disconnect(&mut self, local_cid: u16) {
        let Some(index) = self
            .channels
            .iter()
            .position(|c| c.is_some_and(|c| c.local_cid == local_cid))
        else {
            return;
        };
        let Some(channel) = self.channels[index] else {
            return;
        };
        if channel.remote_cid == 0 {
            // Still connecting: the peer has nothing to close yet.
            self.channels[index] = None;
            return self.push_event(ChannelEvent::Failed(channel));
        }
        let ident = self.ident();
        let (d, s) = (channel.remote_cid.to_le_bytes(), local_cid.to_le_bytes());
        self.signal(
            channel.handle,
            code::DISCONNECTION_REQUEST,
            ident,
            &[d[0], d[1], s[0], s[1]],
        );
    }

    /// The next PDU to send.
    pub fn pop_outbound(&mut self) -> Option<Outbound> {
        let first = self.outbox.iter().position(Option::is_some)?;
        let out = self.outbox[first].take();
        // Keep order: shift the rest forward.
        self.outbox[first..].rotate_left(1);
        out
    }

    /// The next channel event.
    pub fn pop_event(&mut self) -> Option<ChannelEvent> {
        let first = self.events.iter().position(Option::is_some)?;
        let event = self.events[first].take();
        self.events[first..].rotate_left(1);
        event
    }

    fn push_event(&mut self, event: ChannelEvent) {
        if let Some(slot) = self.events.iter_mut().find(|e| e.is_none()) {
            *slot = Some(event);
        }
    }

    /// Queues a B-frame for `cid` made of `parts`.
    fn queue(&mut self, handle: ConnHandle, cid: u16, parts: &[&[u8]]) {
        let len: usize = parts.iter().map(|p| p.len()).sum();
        let Some(slot) = self.outbox.iter_mut().find(|o| o.is_none()) else {
            self.dropped = self.dropped.saturating_add(1);
            return;
        };
        if 4 + len > MAX_PDU {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let mut out = Outbound {
            handle,
            len: 4 + len,
            bytes: [0; MAX_PDU],
        };
        out.bytes[0..2].copy_from_slice(&(len as u16).to_le_bytes());
        out.bytes[2..4].copy_from_slice(&cid.to_le_bytes());
        let mut at = 4;
        for part in parts {
            out.bytes[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        *slot = Some(out);
    }

    fn signal(&mut self, handle: ConnHandle, code: u8, ident: u8, data: &[u8]) {
        let len = (data.len() as u16).to_le_bytes();
        self.queue(
            handle,
            SIGNALING_CID,
            &[&[code, ident, len[0], len[1]], data],
        );
    }

    fn ident(&mut self) -> u8 {
        let ident = self.next_ident;
        self.next_ident = if ident == 255 { 1 } else { ident + 1 };
        ident
    }

    fn allocate_cid(&mut self) -> u16 {
        loop {
            let cid = self.next_cid;
            self.next_cid = if cid == u16::MAX {
                FIRST_DYNAMIC_CID
            } else {
                cid + 1
            };
            if self.channel(cid).is_none() {
                return cid;
            }
        }
    }

    fn on_signaling(&mut self, handle: ConnHandle, mut commands: &[u8]) {
        while commands.len() >= 4 {
            let (code, ident) = (commands[0], commands[1]);
            let len = usize::from(u16::from_le_bytes([commands[2], commands[3]]));
            if commands.len() < 4 + len {
                self.signal(
                    handle,
                    code::COMMAND_REJECT,
                    ident,
                    &reject::NOT_UNDERSTOOD.to_le_bytes(),
                );
                return;
            }
            let data = &commands[4..4 + len];
            commands = &commands[4 + len..];
            self.on_command(handle, code, ident, data);
        }
    }

    fn on_command(&mut self, handle: ConnHandle, code: u8, ident: u8, data: &[u8]) {
        let u16_at = |i: usize| data.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
        match code {
            code::CONNECTION_REQUEST => {
                let (Some(psm), Some(scid)) = (u16_at(0), u16_at(2)) else {
                    return self.reject(handle, ident);
                };
                self.on_connection_request(handle, ident, psm, scid);
            }
            code::CONFIGURATION_REQUEST => {
                let (Some(dcid), Some(flags)) = (u16_at(0), u16_at(2)) else {
                    return self.reject(handle, ident);
                };
                self.on_configuration_request(handle, ident, dcid, flags, &data[4..]);
            }
            code::CONFIGURATION_RESPONSE => {
                let (Some(scid), Some(result)) = (u16_at(0), u16_at(4)) else {
                    return;
                };
                self.on_configuration_response(handle, ident, scid, result);
            }
            code::DISCONNECTION_REQUEST => {
                let (Some(dcid), Some(scid)) = (u16_at(0), u16_at(2)) else {
                    return self.reject(handle, ident);
                };
                let found = self.channels.iter().position(|c| {
                    c.is_some_and(|c| {
                        c.handle == handle && c.local_cid == dcid && c.remote_cid == scid
                    })
                });
                let Some(i) = found else {
                    let mut ids = [0u8; 4];
                    ids[..2].copy_from_slice(&scid.to_le_bytes());
                    ids[2..].copy_from_slice(&dcid.to_le_bytes());
                    let reason = reject::INVALID_CID.to_le_bytes();
                    return self.signal(
                        handle,
                        code::COMMAND_REJECT,
                        ident,
                        &[reason[0], reason[1], ids[0], ids[1], ids[2], ids[3]],
                    );
                };
                self.signal(handle, code::DISCONNECTION_RESPONSE, ident, &data[..4]);
                if let Some(channel) = self.channels[i].take() {
                    self.push_event(ChannelEvent::Closed(channel));
                }
            }
            code::DISCONNECTION_RESPONSE => {
                if let Some(dcid) = u16_at(2)
                    && let Some(i) = self
                        .channels
                        .iter()
                        .position(|c| c.is_some_and(|c| c.handle == handle && c.local_cid == dcid))
                    && let Some(channel) = self.channels[i].take()
                {
                    self.push_event(ChannelEvent::Closed(channel));
                }
            }
            code::ECHO_REQUEST => self.signal(handle, code::ECHO_RESPONSE, ident, data),
            code::INFORMATION_REQUEST => {
                let Some(info_type) = u16_at(0) else {
                    return self.reject(handle, ident);
                };
                let mut out = [0u8; 12];
                out[..2].copy_from_slice(&info_type.to_le_bytes());
                let len = match info_type {
                    info::CONNECTIONLESS_MTU => {
                        out[2..4].copy_from_slice(&info::SUCCESS.to_le_bytes());
                        out[4..6].copy_from_slice(&MTU.to_le_bytes());
                        6
                    }
                    info::EXTENDED_FEATURES => {
                        out[2..4].copy_from_slice(&info::SUCCESS.to_le_bytes());
                        out[4..8].copy_from_slice(&info::FEATURES.to_le_bytes());
                        8
                    }
                    info::FIXED_CHANNELS => {
                        out[2..4].copy_from_slice(&info::SUCCESS.to_le_bytes());
                        out[4..12].copy_from_slice(&info::CHANNELS.to_le_bytes());
                        12
                    }
                    _ => {
                        out[2..4].copy_from_slice(&info::NOT_SUPPORTED.to_le_bytes());
                        4
                    }
                };
                self.signal(handle, code::INFORMATION_RESPONSE, ident, &out[..len]);
            }
            code::CONNECTION_RESPONSE => {
                let (Some(dcid), Some(scid), Some(result)) = (u16_at(0), u16_at(2), u16_at(4))
                else {
                    return;
                };
                self.on_connection_response(handle, ident, dcid, scid, result);
            }
            code::COMMAND_REJECT => {
                // A rejected connection request fails its channel.
                if let Some(i) = self.connecting(handle, ident)
                    && let Some(channel) = self.channels[i].take()
                {
                    self.push_event(ChannelEvent::Failed(channel));
                }
            }
            // Answers to requests we never send.
            code::ECHO_RESPONSE | code::INFORMATION_RESPONSE => {}
            _ => self.reject(handle, ident),
        }
    }

    fn reject(&mut self, handle: ConnHandle, ident: u8) {
        self.signal(
            handle,
            code::COMMAND_REJECT,
            ident,
            &reject::NOT_UNDERSTOOD.to_le_bytes(),
        );
    }

    fn on_connection_request(&mut self, handle: ConnHandle, ident: u8, psm: u16, scid: u16) {
        let respond = |l2cap: &mut Self, dcid: u16, result: u16| {
            let mut out = [0u8; 8];
            out[0..2].copy_from_slice(&dcid.to_le_bytes());
            out[2..4].copy_from_slice(&scid.to_le_bytes());
            out[4..6].copy_from_slice(&result.to_le_bytes());
            l2cap.signal(handle, code::CONNECTION_RESPONSE, ident, &out);
        };
        if !self.psms.contains(&Some(psm)) {
            return respond(self, 0, connection::PSM_NOT_SUPPORTED);
        }
        let Some(slot) = self.channels.iter().position(Option::is_none) else {
            return respond(self, 0, connection::NO_RESOURCES);
        };
        let local_cid = self.allocate_cid();
        respond(self, local_cid, connection::SUCCESS);

        let config_ident = self.request_configuration(handle, scid);
        self.channels[slot] = Some(Channel {
            handle,
            psm,
            local_cid,
            remote_cid: scid,
            remote_mtu: MTU,
            outgoing: false,
            ours_done: false,
            theirs_done: false,
            config_ident,
        });
    }

    /// Sends our configuration request, just our MTU, and returns its
    /// identifier.
    fn request_configuration(&mut self, handle: ConnHandle, remote_cid: u16) -> u8 {
        let ident = self.ident();
        let mut out = [0u8; 8];
        out[0..2].copy_from_slice(&remote_cid.to_le_bytes());
        out[4] = config::MTU;
        out[5] = 2;
        out[6..8].copy_from_slice(&MTU.to_le_bytes());
        self.signal(handle, code::CONFIGURATION_REQUEST, ident, &out);
        ident
    }

    /// The slot of our channel whose connection request was `ident`.
    fn connecting(&self, handle: ConnHandle, ident: u8) -> Option<usize> {
        self.channels.iter().position(|c| {
            c.is_some_and(|c| {
                c.handle == handle && c.outgoing && c.remote_cid == 0 && c.config_ident == ident
            })
        })
    }

    fn on_connection_response(
        &mut self,
        handle: ConnHandle,
        ident: u8,
        dcid: u16,
        scid: u16,
        result: u16,
    ) {
        let Some(index) = self.connecting(handle, ident) else {
            return;
        };
        let Some(mut channel) = self.channels[index] else {
            return;
        };
        if channel.local_cid != scid {
            return;
        }
        match result {
            connection::SUCCESS if dcid >= FIRST_DYNAMIC_CID => {
                channel.remote_cid = dcid;
                channel.config_ident = self.request_configuration(handle, dcid);
                self.channels[index] = Some(channel);
            }
            connection::PENDING => {}
            _ => {
                self.channels[index] = None;
                self.push_event(ChannelEvent::Failed(channel));
            }
        }
    }

    fn on_configuration_request(
        &mut self,
        handle: ConnHandle,
        ident: u8,
        dcid: u16,
        flags: u16,
        mut options: &[u8],
    ) {
        let Some(index) = self
            .channels
            .iter()
            .position(|c| c.is_some_and(|c| c.handle == handle && c.local_cid == dcid))
        else {
            let mut out = [0u8; 6];
            out[0..2].copy_from_slice(&reject::INVALID_CID.to_le_bytes());
            out[4..6].copy_from_slice(&dcid.to_le_bytes());
            return self.signal(handle, code::COMMAND_REJECT, ident, &out);
        };
        let Some(mut channel) = self.channels[index] else {
            return;
        };

        let mut result = config::SUCCESS;
        // Rejected or unknown options are echoed back in the response.
        let mut echo = [0u8; 32];
        let mut echo_len = 0;
        let mut mtu = channel.remote_mtu;

        while options.len() >= 2 {
            let (kind, len) = (options[0], usize::from(options[1]));
            let Some(value) = options.get(2..2 + len) else {
                break;
            };
            options = &options[2 + len..];
            match kind & !config::HINT {
                config::MTU if len == 2 => {
                    let wanted = u16::from_le_bytes([value[0], value[1]]);
                    if wanted < MIN_MTU {
                        result = config::UNACCEPTABLE;
                        if echo_len + 4 <= echo.len() {
                            echo[echo_len..echo_len + 4].copy_from_slice(&[
                                config::MTU,
                                2,
                                MIN_MTU as u8,
                                (MIN_MTU >> 8) as u8,
                            ]);
                            echo_len += 4;
                        }
                    } else {
                        mtu = wanted;
                    }
                }
                config::FLUSH_TIMEOUT | config::QOS | config::FCS => {}
                config::RETRANSMISSION if value.first() == Some(&0) => {} // basic mode
                config::RETRANSMISSION => {
                    // Only basic mode: counter-propose it.
                    if result != config::UNKNOWN_OPTIONS {
                        result = config::UNACCEPTABLE;
                    }
                    if echo_len + 11 <= echo.len() {
                        echo[echo_len..echo_len + 11].copy_from_slice(&[
                            config::RETRANSMISSION,
                            9,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ]);
                        echo_len += 11;
                    }
                }
                _ if kind & config::HINT != 0 => {}
                _ => {
                    if result != config::UNKNOWN_OPTIONS {
                        result = config::UNKNOWN_OPTIONS;
                        echo_len = 0;
                    }
                    if echo_len < echo.len() {
                        echo[echo_len] = kind;
                        echo_len += 1;
                    }
                }
            }
        }

        let continuation = flags & config::CONTINUATION;
        let mut out = [0u8; 6 + 32];
        out[0..2].copy_from_slice(&channel.remote_cid.to_le_bytes());
        out[2..4].copy_from_slice(&continuation.to_le_bytes());
        out[4..6].copy_from_slice(&result.to_le_bytes());
        out[6..6 + echo_len].copy_from_slice(&echo[..echo_len]);
        self.signal(
            handle,
            code::CONFIGURATION_RESPONSE,
            ident,
            &out[..6 + echo_len],
        );

        if result == config::SUCCESS {
            channel.remote_mtu = mtu;
            if continuation == 0 {
                channel.theirs_done = true;
            }
        }
        self.update(index, channel);
    }

    fn on_configuration_response(&mut self, handle: ConnHandle, ident: u8, scid: u16, result: u16) {
        let Some(index) = self.channels.iter().position(|c| {
            c.is_some_and(|c| c.handle == handle && c.local_cid == scid && c.config_ident == ident)
        }) else {
            return;
        };
        let Some(mut channel) = self.channels[index] else {
            return;
        };
        if result == config::SUCCESS {
            channel.ours_done = true;
            self.update(index, channel);
        } else {
            // Our only option is the MTU; fall back to proposing nothing,
            // which means the default MTU.
            channel.config_ident = self.ident();
            self.channels[index] = Some(channel);
            let mut out = [0u8; 4];
            out[0..2].copy_from_slice(&channel.remote_cid.to_le_bytes());
            self.signal(
                handle,
                code::CONFIGURATION_REQUEST,
                channel.config_ident,
                &out,
            );
        }
    }

    /// Stores `channel`, reporting it opened if this completed its
    /// configuration.
    fn update(&mut self, index: usize, channel: Channel) {
        let was_open = self.channels[index].is_some_and(|c| c.is_open());
        self.channels[index] = Some(channel);
        if channel.is_open() && !was_open {
            self.push_event(ChannelEvent::Opened(channel));
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    const HANDLE: u16 = 0x0040;

    fn handle() -> ConnHandle {
        ConnHandle::new(HANDLE)
    }

    fn l2cap() -> L2cap {
        let mut l2cap = L2cap::new();
        assert!(l2cap.register(psm::SDP));
        l2cap.connected(handle());
        l2cap
    }

    fn pdu(cid: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(&cid.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn signal(code: u8, ident: u8, data: &[u8]) -> Vec<u8> {
        let mut cmd = std::vec![code, ident];
        cmd.extend_from_slice(&(data.len() as u16).to_le_bytes());
        cmd.extend_from_slice(data);
        pdu(SIGNALING_CID, &cmd)
    }

    fn feed(l2cap: &mut L2cap, bytes: &[u8]) -> Option<Vec<u8>> {
        l2cap
            .on_acl(handle(), AclPacketBoundary::FirstFlushable, bytes)
            .map(|r| r.data.to_vec())
    }

    fn outbox(l2cap: &mut L2cap) -> Vec<Vec<u8>> {
        core::iter::from_fn(|| l2cap.pop_outbound().map(|o| o.as_bytes().to_vec())).collect()
    }

    /// Opens an SDP channel from the peer's CID 0x0070 and returns our CID.
    fn open(l2cap: &mut L2cap) -> u16 {
        feed(
            l2cap,
            &signal(code::CONNECTION_REQUEST, 1, &[0x01, 0x00, 0x70, 0x00]),
        );
        let out = outbox(l2cap);
        // Connection response (dcid 0x0040, scid 0x0070, success), then our config request.
        assert_eq!(
            out[0],
            signal(
                code::CONNECTION_RESPONSE,
                1,
                &[0x40, 0x00, 0x70, 0x00, 0, 0, 0, 0]
            )
        );
        let our_ident = out[1][5];
        assert_eq!(
            out[1],
            signal(
                code::CONFIGURATION_REQUEST,
                our_ident,
                &[0x70, 0x00, 0, 0, 0x01, 0x02, 0xa0, 0x02]
            )
        );

        // The peer's configuration request with MTU 1024, and its response to ours.
        feed(
            l2cap,
            &signal(
                code::CONFIGURATION_REQUEST,
                2,
                &[0x40, 0x00, 0, 0, 0x01, 0x02, 0x00, 0x04],
            ),
        );
        assert_eq!(
            outbox(l2cap),
            [signal(
                code::CONFIGURATION_RESPONSE,
                2,
                &[0x70, 0x00, 0, 0, 0, 0]
            )]
        );
        assert_eq!(l2cap.pop_event(), None);
        feed(
            l2cap,
            &signal(
                code::CONFIGURATION_RESPONSE,
                our_ident,
                &[0x40, 0x00, 0, 0, 0, 0],
            ),
        );
        let Some(ChannelEvent::Opened(channel)) = l2cap.pop_event() else {
            panic!("channel not opened");
        };
        assert_eq!(channel.remote_mtu, 1024);
        channel.local_cid
    }

    #[test]
    fn opens_a_channel_and_carries_data() {
        let mut l2cap = l2cap();
        let cid = open(&mut l2cap);
        assert_eq!(cid, 0x0040);

        assert_eq!(
            feed(&mut l2cap, &pdu(cid, b"request")),
            Some(b"request".to_vec())
        );
        l2cap.send(cid, b"response").unwrap();
        assert_eq!(outbox(&mut l2cap), [pdu(0x0070, b"response")]);
    }

    #[test]
    fn reassembles_fragments() {
        let mut l2cap = l2cap();
        let cid = open(&mut l2cap);
        let whole = pdu(cid, &[7u8; 300]);
        assert!(
            l2cap
                .on_acl(handle(), AclPacketBoundary::FirstFlushable, &whole[..2])
                .is_none()
        );
        assert!(
            l2cap
                .on_acl(handle(), AclPacketBoundary::Continuing, &whole[2..200])
                .is_none()
        );
        let done = l2cap.on_acl(handle(), AclPacketBoundary::Continuing, &whole[200..]);
        assert_eq!(done.unwrap().data, &[7u8; 300][..]);
    }

    #[test]
    fn drops_oversized_pdus() {
        let mut l2cap = l2cap();
        let cid = open(&mut l2cap);
        let big = pdu(cid, &[0u8; MTU as usize + 1]);
        assert!(feed(&mut l2cap, &big).is_none());
        // The next PDU is fine.
        assert_eq!(feed(&mut l2cap, &pdu(cid, b"ok")), Some(b"ok".to_vec()));
    }

    #[test]
    fn refuses_unknown_psm() {
        let mut l2cap = l2cap();
        feed(
            &mut l2cap,
            &signal(code::CONNECTION_REQUEST, 9, &[0x03, 0x00, 0x71, 0x00]),
        );
        assert_eq!(
            outbox(&mut l2cap),
            [signal(
                code::CONNECTION_RESPONSE,
                9,
                &[0, 0, 0x71, 0x00, 0x02, 0x00, 0, 0]
            )]
        );
    }

    #[test]
    fn counter_proposes_basic_mode() {
        let mut l2cap = l2cap();
        let cid = open(&mut l2cap);
        // Retransmission and flow control option asking for ERTM (mode 3).
        let ertm = [0x40, 0x00, 0, 0, 0x04, 0x09, 0x03, 0, 0, 0, 0, 0, 0, 0, 0];
        feed(&mut l2cap, &signal(code::CONFIGURATION_REQUEST, 5, &ertm));
        let mut expected = std::vec![0x70, 0x00, 0, 0, 0x01, 0x00];
        expected.extend_from_slice(&[0x04, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            outbox(&mut l2cap),
            [signal(code::CONFIGURATION_RESPONSE, 5, &expected)]
        );
        assert!(l2cap.channel(cid).is_some());
    }

    #[test]
    fn rejects_unknown_options_but_skips_hints() {
        let mut l2cap = l2cap();
        open(&mut l2cap);
        // Option 0x20 is unknown; 0xa1 is an unknown hint.
        let request = [0x40, 0x00, 0, 0, 0xa1, 0x01, 0x00, 0x20, 0x01, 0x00];
        feed(
            &mut l2cap,
            &signal(code::CONFIGURATION_REQUEST, 6, &request),
        );
        assert_eq!(
            outbox(&mut l2cap),
            [signal(
                code::CONFIGURATION_RESPONSE,
                6,
                &[0x70, 0x00, 0, 0, 0x03, 0x00, 0x20]
            )]
        );
    }

    #[test]
    fn answers_information_and_echo() {
        let mut l2cap = l2cap();
        feed(
            &mut l2cap,
            &signal(code::INFORMATION_REQUEST, 3, &[0x02, 0x00]),
        );
        feed(
            &mut l2cap,
            &signal(code::INFORMATION_REQUEST, 4, &[0x03, 0x00]),
        );
        feed(
            &mut l2cap,
            &signal(code::INFORMATION_REQUEST, 5, &[0x09, 0x00]),
        );
        assert_eq!(
            outbox(&mut l2cap),
            [
                signal(
                    code::INFORMATION_RESPONSE,
                    3,
                    &[0x02, 0x00, 0, 0, 0x80, 0, 0, 0]
                ),
                signal(
                    code::INFORMATION_RESPONSE,
                    4,
                    &[0x03, 0x00, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0]
                ),
                signal(code::INFORMATION_RESPONSE, 5, &[0x09, 0x00, 0x01, 0x00]),
            ]
        );
    }

    #[test]
    fn answers_echo() {
        let mut l2cap = l2cap();
        feed(&mut l2cap, &signal(code::ECHO_REQUEST, 6, b"hi"));
        assert_eq!(outbox(&mut l2cap), [signal(code::ECHO_RESPONSE, 6, b"hi")]);
    }

    #[test]
    fn disconnection_closes_the_channel() {
        let mut l2cap = l2cap();
        let cid = open(&mut l2cap);
        feed(
            &mut l2cap,
            &signal(code::DISCONNECTION_REQUEST, 7, &[0x40, 0x00, 0x70, 0x00]),
        );
        assert_eq!(
            outbox(&mut l2cap),
            [signal(
                code::DISCONNECTION_RESPONSE,
                7,
                &[0x40, 0x00, 0x70, 0x00]
            )]
        );
        assert!(matches!(l2cap.pop_event(), Some(ChannelEvent::Closed(_))));
        assert!(l2cap.channel(cid).is_none());
        assert_eq!(l2cap.send(cid, b"x"), Err(SendError::NoChannel));
    }

    #[test]
    fn acl_disconnect_closes_channels() {
        let mut l2cap = l2cap();
        open(&mut l2cap);
        l2cap.disconnected(handle());
        assert!(matches!(l2cap.pop_event(), Some(ChannelEvent::Closed(_))));
        assert!(feed(&mut l2cap, &pdu(0x0040, b"x")).is_none());
    }

    /// Asks for an RFCOMM channel and returns our CID and the request's
    /// identifier.
    fn connect(l2cap: &mut L2cap) -> (u16, u8) {
        let cid = l2cap.connect(handle(), psm::RFCOMM).unwrap();
        let out = outbox(l2cap);
        let ident = out[0][5];
        let c = cid.to_le_bytes();
        assert_eq!(
            out,
            [signal(
                code::CONNECTION_REQUEST,
                ident,
                &[0x03, 0x00, c[0], c[1]]
            )]
        );
        (cid, ident)
    }

    #[test]
    fn opens_a_channel_to_the_peer() {
        let mut l2cap = l2cap();
        let (cid, ident) = connect(&mut l2cap);
        let c = cid.to_le_bytes();

        // Pending first, then success with the peer's CID 0x0080.
        feed(
            &mut l2cap,
            &signal(
                code::CONNECTION_RESPONSE,
                ident,
                &[0, 0, c[0], c[1], 0x01, 0x00, 0, 0],
            ),
        );
        assert!(outbox(&mut l2cap).is_empty());
        feed(
            &mut l2cap,
            &signal(
                code::CONNECTION_RESPONSE,
                ident,
                &[0x80, 0x00, c[0], c[1], 0, 0, 0, 0],
            ),
        );
        let out = outbox(&mut l2cap);
        let our_ident = out[0][5];
        assert_eq!(
            out,
            [signal(
                code::CONFIGURATION_REQUEST,
                our_ident,
                &[0x80, 0x00, 0, 0, 0x01, 0x02, 0xa0, 0x02]
            )]
        );

        feed(
            &mut l2cap,
            &signal(
                code::CONFIGURATION_RESPONSE,
                our_ident,
                &[c[0], c[1], 0, 0, 0, 0],
            ),
        );
        feed(
            &mut l2cap,
            &signal(
                code::CONFIGURATION_REQUEST,
                3,
                &[c[0], c[1], 0, 0, 0x01, 0x02, 0x00, 0x01],
            ),
        );
        assert_eq!(
            outbox(&mut l2cap),
            [signal(
                code::CONFIGURATION_RESPONSE,
                3,
                &[0x80, 0x00, 0, 0, 0, 0]
            )]
        );
        let Some(ChannelEvent::Opened(channel)) = l2cap.pop_event() else {
            panic!("channel not opened");
        };
        assert!(channel.outgoing);
        assert_eq!((channel.remote_cid, channel.remote_mtu), (0x0080, 256));

        l2cap.send(cid, b"hi").unwrap();
        assert_eq!(outbox(&mut l2cap), [pdu(0x0080, b"hi")]);

        // We close it.
        l2cap.disconnect(cid);
        let out = outbox(&mut l2cap);
        let ident = out[0][5];
        assert_eq!(
            out,
            [signal(
                code::DISCONNECTION_REQUEST,
                ident,
                &[0x80, 0x00, c[0], c[1]]
            )]
        );
        feed(
            &mut l2cap,
            &signal(
                code::DISCONNECTION_RESPONSE,
                ident,
                &[0x80, 0x00, c[0], c[1]],
            ),
        );
        assert!(matches!(l2cap.pop_event(), Some(ChannelEvent::Closed(_))));
        assert!(l2cap.channel(cid).is_none());
    }

    #[test]
    fn a_refused_connection_fails() {
        let mut l2cap = l2cap();
        let (cid, ident) = connect(&mut l2cap);
        let c = cid.to_le_bytes();
        feed(
            &mut l2cap,
            &signal(
                code::CONNECTION_RESPONSE,
                ident,
                &[0, 0, c[0], c[1], 0x02, 0x00, 0, 0],
            ),
        );
        assert!(matches!(l2cap.pop_event(), Some(ChannelEvent::Failed(c)) if c.local_cid == cid));
        assert!(l2cap.channel(cid).is_none());

        // A command reject fails the request too.
        let (cid, ident) = connect(&mut l2cap);
        feed(&mut l2cap, &signal(code::COMMAND_REJECT, ident, &[0, 0]));
        assert!(matches!(l2cap.pop_event(), Some(ChannelEvent::Failed(c)) if c.local_cid == cid));
    }

    #[test]
    fn connect_needs_a_link() {
        let mut l2cap = L2cap::new();
        assert_eq!(l2cap.connect(handle(), psm::SDP), None);
    }

    #[test]
    fn unknown_command_is_rejected() {
        let mut l2cap = l2cap();
        feed(&mut l2cap, &signal(0x42, 8, &[]));
        assert_eq!(
            outbox(&mut l2cap),
            [signal(code::COMMAND_REJECT, 8, &[0, 0])]
        );
    }
}
