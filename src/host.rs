//! The async runner: brings the controller up, then reads it, drives
//! [`Security`], [`L2cap`], [`Rfcomm`] and SDP, and sends their replies.
//! It also connects profiles on the application's behalf; see
//! [`Requests`].
//!
//! A command only completes while something reads the controller, so
//! [`run`] reads in one future and handles packets in another, joined by a
//! small channel. The application starts its own procedures (connecting,
//! authenticating) on the same controller concurrently, and hears about
//! progress through a [`Handler`].

use core::cell::Cell;

use bt_hci::cmd::Error;
use bt_hci::cmd::link_control::{
    AcceptConnectionRequest, IoCapabilityRequestReply, LinkKeyRequestNegativeReply,
    LinkKeyRequestReply, RejectConnectionRequest, UserConfirmationRequestNegativeReply,
    UserConfirmationRequestReply,
};
use bt_hci::controller::{Controller, ControllerCmdSync};
use bt_hci::data::{AclBroadcastFlag, AclPacket, AclPacketBoundary};
use bt_hci::event::{Event, EventKind};
use bt_hci::param::{BdAddr, ConnHandle, OobDataPresent};
use bt_hci::{ControllerToHostPacket, FromHciBytes};
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;

use crate::cmd::PinCodeRequestNegativeReply;
use crate::gap::{self, ClassicController, ControllerInfo};
use crate::l2cap::{self, ChannelEvent, L2cap};
use crate::rfcomm::{self, Dlc, Rfcomm, RfcommEvent, SendError};
use crate::sdp::{self, Lookup, SdpClient, SdpServer, ServiceRecord};
use crate::security::{Action, ConfirmRequest, LinkKeyStore, Notice, Security, SecurityConfig};

/// What the application hears from [`run`]. Every method has a default.
pub trait Handler {
    /// Bring-up finished; the device is live.
    fn ready(&mut self, info: &ControllerInfo) {
        let _ = info;
    }

    /// Every event, before the stack sees it; for application-level events
    /// such as inquiry results.
    fn event(&mut self, event: &Event<'_>) {
        let _ = event;
    }

    /// Connection and pairing progress.
    fn notice(&mut self, notice: Notice) {
        let _ = notice;
    }

    /// An L2CAP channel opened or closed.
    fn channel(&mut self, event: ChannelEvent) {
        let _ = event;
    }

    /// Data on an open channel whose PSM the stack does not serve itself.
    fn data(&mut self, channel: &l2cap::Channel, data: &[u8]) {
        let _ = (channel, data);
    }

    /// A peer opened RFCOMM channel `dlc`; `tx` can send on it right away.
    fn rfcomm_opened(&mut self, dlc: Dlc, tx: &mut RfcommTx<'_>) {
        let _ = (dlc, tx);
    }

    /// Data arrived on RFCOMM channel `dlc`.
    fn rfcomm_data(&mut self, dlc: Dlc, data: &[u8], tx: &mut RfcommTx<'_>) {
        let _ = (dlc, data, tx);
    }

    /// RFCOMM channel `dlc` closed.
    fn rfcomm_closed(&mut self, dlc: Dlc) {
        let _ = dlc;
    }

    /// The profile asked for with [`Requests::connect_profile`] is connected
    /// on `dlc`. Called just before [`Handler::rfcomm_opened`] for the same
    /// channel, which then carries data like any other.
    fn profile_connected(&mut self, bd_addr: BdAddr, uuid: u16, dlc: Dlc, tx: &mut RfcommTx<'_>) {
        let _ = (bd_addr, uuid, dlc, tx);
    }

    /// The profile asked for with [`Requests::connect_profile`] could not be
    /// connected.
    fn profile_failed(&mut self, bd_addr: BdAddr, uuid: u16, error: ProfileError) {
        let _ = (bd_addr, uuid, error);
    }

    /// Numeric comparison: return whether the user confirmed that both
    /// devices show `request.numeric_value`. Only asked when both sides can
    /// display and answer; the default accepts.
    #[allow(async_fn_in_trait)]
    async fn confirm(&mut self, request: ConfirmRequest) -> bool {
        let _ = request;
        true
    }

    /// A reply command was refused, typically because the connection went
    /// away meanwhile. The runner carries on.
    fn command_failed(&mut self, action: Action, error: bt_hci::param::Error) {
        let _ = (action, error);
    }

    /// `count` events were dropped because they arrived faster than they
    /// were handled (see [`run`]).
    fn events_dropped(&mut self, count: u32) {
        let _ = count;
    }
}

/// Sends on RFCOMM channels from inside [`Handler`] callbacks. Data is
/// buffered per channel and goes out as the peer's credits allow.
pub struct RfcommTx<'a> {
    rfcomm: &'a mut Rfcomm,
}

impl RfcommTx<'_> {
    /// Queues `data` on `dlc`, all or nothing.
    pub fn send(&mut self, dlc: Dlc, data: &[u8]) -> Result<(), SendError> {
        self.rfcomm.send(dlc, data)
    }

    /// Bytes `dlc` can still buffer.
    pub fn room(&self, dlc: Dlc) -> usize {
        self.rfcomm.room(dlc)
    }
}

/// Why [`Requests::connect_profile`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ProfileError {
    /// No ACL connection to the device: connect first.
    NotConnected,
    /// Another profile connection is in progress.
    Busy,
    /// No free L2CAP or RFCOMM slot.
    NoResources,
    /// The peer refused the L2CAP channel for SDP or RFCOMM.
    ChannelRefused,
    /// The peer's SDP answer was an error or unreadable.
    LookupFailed,
    /// The peer has no record of the service with an RFCOMM channel.
    NotFound,
    /// The peer refused the RFCOMM channel.
    Refused,
    /// The connection went down meanwhile.
    Disconnected,
}

/// Something the application asks [`run`] to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Request {
    /// See [`Requests::connect_profile`].
    ConnectProfile { bd_addr: BdAddr, uuid: u16 },
}

/// Requests for [`run`], from code running alongside it in the same task.
pub struct Requests {
    channel: Channel<NoopRawMutex, Request, 2>,
}

impl Default for Requests {
    fn default() -> Self {
        Self::new()
    }
}

impl Requests {
    pub const fn new() -> Self {
        Self {
            channel: Channel::new(),
        }
    }

    /// Connects to the service class `uuid` on the connected device
    /// `bd_addr`, the way a client connects a profile: looks up the
    /// service's RFCOMM channel with SDP and opens it. The outcome arrives
    /// as [`Handler::profile_connected`] or [`Handler::profile_failed`].
    /// Returns false if too many requests are waiting.
    ///
    /// The link should be authenticated and encrypted first; peers refuse
    /// most profiles otherwise.
    pub fn connect_profile(&self, bd_addr: BdAddr, uuid: u16) -> bool {
        self.channel
            .try_send(Request::ConnectProfile { bd_addr, uuid })
            .is_ok()
    }
}

/// Where a profile connection is.
#[derive(Clone, Copy)]
enum Step {
    /// Waiting for the SDP channel, then for the lookup.
    Lookup { cid: u16 },
    /// Waiting for the RFCOMM L2CAP channel to open `channel` on it.
    Session { cid: u16, channel: u8 },
    /// Waiting for the RFCOMM channel.
    Channel { dlc: Dlc },
}

#[derive(Clone, Copy)]
struct Pending {
    handle: ConnHandle,
    bd_addr: BdAddr,
    uuid: u16,
    step: Step,
}

/// A [`Handler`] that ignores everything and accepts every confirmation.
pub struct NoHandler;

impl Handler for NoHandler {}

/// Everything the runner drives, owned by the application so it can be a
/// `static` on a device.
pub struct Stack<'r, S> {
    pub security: Security,
    pub l2cap: L2cap,
    pub sdp: SdpServer<'r>,
    /// Register server channels with `stack.rfcomm.register(channel)`.
    pub rfcomm: Rfcomm,
    pub keys: S,
    sdp_client: SdpClient,
    /// ACL links and their peers, for requests that name a device.
    links: [Option<(ConnHandle, BdAddr)>; l2cap::MAX_CONNECTIONS],
    profile: Option<Pending>,
}

impl<'r, S: LinkKeyStore> Stack<'r, S> {
    /// A stack that pairs as `security` says, serves `records` over SDP and
    /// keeps link keys in `keys`.
    pub fn new(security: SecurityConfig, records: &'r [ServiceRecord<'r>], keys: S) -> Self {
        let mut l2cap = L2cap::new();
        l2cap.register(sdp::PSM);
        l2cap.register(rfcomm::PSM);
        Self {
            security: Security::new(security),
            l2cap,
            sdp: SdpServer::new(records),
            rfcomm: Rfcomm::new(),
            keys,
            sdp_client: SdpClient::new(),
            links: [None; l2cap::MAX_CONNECTIONS],
            profile: None,
        }
    }

    fn link_up(&mut self, handle: ConnHandle, bd_addr: BdAddr) {
        self.link_down(handle);
        if let Some(slot) = self.links.iter_mut().find(|l| l.is_none()) {
            *slot = Some((handle, bd_addr));
        }
    }

    fn link_down(&mut self, handle: ConnHandle) {
        for link in &mut self.links {
            if link.is_some_and(|(h, _)| h == handle) {
                *link = None;
            }
        }
    }

    /// Starts a [`Request::ConnectProfile`]: opens the SDP channel.
    fn start_profile<H: Handler>(&mut self, handler: &mut H, bd_addr: BdAddr, uuid: u16) {
        if self.profile.is_some() {
            return handler.profile_failed(bd_addr, uuid, ProfileError::Busy);
        }
        let Some((handle, _)) = self.links.iter().flatten().find(|(_, a)| *a == bd_addr) else {
            return handler.profile_failed(bd_addr, uuid, ProfileError::NotConnected);
        };
        match self.l2cap.connect(*handle, sdp::PSM) {
            Some(cid) => {
                self.profile = Some(Pending {
                    handle: *handle,
                    bd_addr,
                    uuid,
                    step: Step::Lookup { cid },
                });
            }
            None => handler.profile_failed(bd_addr, uuid, ProfileError::NoResources),
        }
    }

    fn fail_profile<H: Handler>(&mut self, handler: &mut H, error: ProfileError) {
        if let Some(p) = self.profile.take() {
            handler.profile_failed(p.bd_addr, p.uuid, error);
        }
    }

    /// The profile's L2CAP channel opened, failed or closed.
    fn on_profile_channel<H: Handler>(&mut self, handler: &mut H, event: ChannelEvent) {
        let Some(pending) = self.profile else {
            return;
        };
        match (pending.step, event) {
            (Step::Lookup { cid }, ChannelEvent::Opened(c)) if c.local_cid == cid => {
                let mut request = [0u8; sdp::MAX_CLIENT_REQUEST];
                let n = self.sdp_client.start(pending.uuid, &mut request);
                if self.l2cap.send(cid, &request[..n]).is_err() {
                    self.l2cap.disconnect(cid);
                    self.fail_profile(handler, ProfileError::NoResources);
                }
            }
            (Step::Session { cid, channel }, ChannelEvent::Opened(c)) if c.local_cid == cid => {
                self.open_channel(handler, cid, channel);
            }
            (
                Step::Lookup { cid } | Step::Session { cid, .. },
                ChannelEvent::Failed(c) | ChannelEvent::Closed(c),
            ) if c.local_cid == cid => {
                self.fail_profile(handler, ProfileError::ChannelRefused);
            }
            _ => {}
        }
    }

    /// The SDP lookup on channel `cid` gave `lookup`; a continuation request
    /// is in `request`.
    fn on_lookup<H: Handler>(&mut self, handler: &mut H, cid: u16, lookup: Lookup, request: &[u8]) {
        let Some(pending) = self.profile else {
            return;
        };
        if !matches!(pending.step, Step::Lookup { cid: c } if c == cid) {
            return;
        }
        let channel = match lookup {
            Lookup::Next(n) => {
                if self.l2cap.send(cid, &request[..n]).is_err() {
                    self.l2cap.disconnect(cid);
                    self.fail_profile(handler, ProfileError::NoResources);
                }
                return;
            }
            Lookup::Found(channel) => channel,
            Lookup::NotFound => {
                self.l2cap.disconnect(cid);
                return self.fail_profile(handler, ProfileError::NotFound);
            }
            Lookup::Failed => {
                self.l2cap.disconnect(cid);
                return self.fail_profile(handler, ProfileError::LookupFailed);
            }
        };
        // Not a failure from here on if the SDP channel closes.
        self.profile = Some(Pending {
            step: Step::Session { cid: 0, channel },
            ..pending
        });
        self.l2cap.disconnect(cid);
        // One RFCOMM session per pair of devices: reuse one either side
        // opened.
        if let Some(session) = self.l2cap.find(pending.handle, rfcomm::PSM) {
            let cid = session.local_cid;
            return self.open_channel(handler, cid, channel);
        }
        match self.l2cap.connect(pending.handle, rfcomm::PSM) {
            Some(cid) => {
                self.profile = Some(Pending {
                    step: Step::Session { cid, channel },
                    ..pending
                });
            }
            None => self.fail_profile(handler, ProfileError::NoResources),
        }
    }

    /// Opens RFCOMM `channel` on the session over L2CAP channel `cid`.
    fn open_channel<H: Handler>(&mut self, handler: &mut H, cid: u16, channel: u8) {
        let Some(pending) = self.profile else {
            return;
        };
        match self.rfcomm.connect(cid, channel) {
            Some(dlc) => {
                self.profile = Some(Pending {
                    step: Step::Channel { dlc },
                    ..pending
                });
            }
            None => self.fail_profile(handler, ProfileError::NoResources),
        }
    }
}

/// The commands [`run`] sends. Implemented for every controller that
/// supports them, such as bt-hci's `ExternalController`.
pub trait HostController:
    ClassicController
    + ControllerCmdSync<AcceptConnectionRequest>
    + ControllerCmdSync<RejectConnectionRequest>
    + ControllerCmdSync<LinkKeyRequestReply>
    + ControllerCmdSync<LinkKeyRequestNegativeReply>
    + ControllerCmdSync<PinCodeRequestNegativeReply>
    + ControllerCmdSync<IoCapabilityRequestReply>
    + ControllerCmdSync<UserConfirmationRequestReply>
    + ControllerCmdSync<UserConfirmationRequestNegativeReply>
{
}

impl<C> HostController for C where
    C: ClassicController
        + ControllerCmdSync<AcceptConnectionRequest>
        + ControllerCmdSync<RejectConnectionRequest>
        + ControllerCmdSync<LinkKeyRequestReply>
        + ControllerCmdSync<LinkKeyRequestNegativeReply>
        + ControllerCmdSync<PinCodeRequestNegativeReply>
        + ControllerCmdSync<IoCapabilityRequestReply>
        + ControllerCmdSync<UserConfirmationRequestReply>
        + ControllerCmdSync<UserConfirmationRequestNegativeReply>
{
}

/// A packet copied out of the read buffer.
enum Packet {
    /// Event code, parameter length and parameters, ready to parse.
    Event { bytes: [u8; 257], len: usize },
    Acl {
        handle: ConnHandle,
        boundary: AclPacketBoundary,
        data: [u8; gap::HOST_ACL_DATA_PACKET_LENGTH as usize],
        len: usize,
    },
}

/// How many packets can wait between the reader and the handler. RFCOMM
/// gives each peer [`rfcomm::RX_CREDITS`] frames in flight, each up to three
/// ACL packets, and events come on top.
const QUEUE: usize = 16;

/// ACL buffers in the controller: packets may only be sent while some are
/// free. Completed_Packets events return them; a disconnection returns that
/// link's outstanding ones.
struct Credits {
    free: Cell<u16>,
    outstanding: [Cell<(u16, u16)>; l2cap::MAX_CONNECTIONS],
    freed: Signal<NoopRawMutex, ()>,
}

impl Credits {
    fn new() -> Self {
        Self {
            free: Cell::new(0),
            outstanding: core::array::from_fn(|_| Cell::new((u16::MAX, 0))),
            freed: Signal::new(),
        }
    }

    /// The controller's buffer count, from Read_Buffer_Size.
    fn init(&self, total: u16) {
        self.free.set(total);
        self.freed.signal(());
    }

    async fn take(&self, handle: ConnHandle) {
        while self.free.get() == 0 {
            self.freed.wait().await;
        }
        self.free.set(self.free.get() - 1);
        let raw = handle.raw();
        let slot = self
            .outstanding
            .iter()
            .find(|c| c.get().0 == raw)
            .or_else(|| self.outstanding.iter().find(|c| c.get().1 == 0));
        if let Some(slot) = slot {
            let (_, count) = slot.get();
            slot.set((raw, count + 1));
        }
    }

    fn give(&self, handle: u16, count: u16) {
        if let Some(slot) = self.outstanding.iter().find(|c| c.get().0 == handle) {
            let (_, outstanding) = slot.get();
            slot.set((handle, outstanding.saturating_sub(count)));
        }
        self.free.set(self.free.get().saturating_add(count));
        self.freed.signal(());
    }

    fn reclaim(&self, handle: ConnHandle) {
        if let Some(slot) = self.outstanding.iter().find(|c| c.get().0 == handle.raw()) {
            let (raw, outstanding) = slot.get();
            slot.set((u16::MAX, 0));
            self.give(raw, outstanding);
        }
    }

    /// Credits from a Number_Of_Completed_Packets event's parameters.
    fn on_completed_packets(&self, params: &[u8]) {
        let Some((&count, entries)) = params.split_first() else {
            return;
        };
        for &[h0, h1, c0, c1] in entries.as_chunks::<4>().0.iter().take(usize::from(count)) {
            let handle = u16::from_le_bytes([h0, h1]) & 0x0fff;
            let completed = u16::from_le_bytes([c0, c1]);
            self.give(handle, completed);
        }
    }
}

/// Brings the controller up as `gap` describes, then runs the stack until
/// the controller fails, which is the only way it ends.
///
/// The reader never waits for the handler: while the handler waits for a
/// command to complete, only the reader can see the completion, so a reader
/// blocked on a full queue would deadlock both. When the queue is full the
/// packet is dropped instead and counted, and [`Handler::events_dropped`]
/// reports it.
///
/// `requests` carries what the application asks of the stack, such as
/// [`Requests::connect_profile`].
pub async fn run<C, S, H>(
    controller: &C,
    stack: &mut Stack<'_, S>,
    gap: &gap::Config<'_>,
    handler: &mut H,
    requests: &Requests,
) -> Error<C::Error>
where
    C: HostController,
    S: LinkKeyStore,
    H: Handler,
{
    let queue: Channel<NoopRawMutex, Packet, QUEUE> = Channel::new();
    let dropped = Cell::new(0u32);
    let credits = Credits::new();

    let reader = async {
        let mut buf = match controller.alloc_buf() {
            Ok(buf) => buf,
            Err(e) => return Error::Io(e),
        };
        loop {
            let packet = match controller.read(&mut buf).await {
                Ok(ControllerToHostPacket::Event(packet))
                    if packet.kind == EventKind::NumberOfCompletedPackets =>
                {
                    credits.on_completed_packets(packet.data);
                    continue;
                }
                Ok(ControllerToHostPacket::Event(packet)) => {
                    let params = &packet.data[..packet.data.len().min(255)];
                    let mut bytes = [0u8; 257];
                    bytes[0] = packet.kind.0;
                    bytes[1] = params.len() as u8;
                    bytes[2..2 + params.len()].copy_from_slice(params);
                    Packet::Event {
                        bytes,
                        len: 2 + params.len(),
                    }
                }
                Ok(ControllerToHostPacket::Acl(acl)) => {
                    let mut data = [0u8; gap::HOST_ACL_DATA_PACKET_LENGTH as usize];
                    let len = acl.data().len().min(data.len());
                    data[..len].copy_from_slice(&acl.data()[..len]);
                    Packet::Acl {
                        handle: acl.handle(),
                        boundary: acl.boundary_flag(),
                        data,
                        len,
                    }
                }
                Ok(_) => continue,
                Err(e) => return Error::Io(e),
            };
            if queue.try_send(packet).is_err() {
                dropped.set(dropped.get().saturating_add(1));
            }
        }
    };

    let processor = async {
        let info = match gap::bring_up(controller, gap).await {
            Ok(info) => info,
            Err(e) => return e,
        };
        let acl_len = usize::from(info.acl_data_packet_length.max(1));
        credits.init(info.total_num_acl_data_packets);
        handler.ready(&info);

        let mut response = [0u8; l2cap::MTU as usize];
        loop {
            let packet = match select(queue.receive(), requests.channel.receive()).await {
                Either::First(packet) => Some(packet),
                Either::Second(Request::ConnectProfile { bd_addr, uuid }) => {
                    stack.start_profile(handler, bd_addr, uuid);
                    None
                }
            };
            let lost = dropped.replace(0);
            if lost > 0 {
                handler.events_dropped(lost);
            }
            match packet {
                None => {}
                Some(Packet::Event { bytes, len }) => {
                    let Ok(event) = Event::from_hci_bytes_complete(&bytes[..len]) else {
                        continue;
                    };
                    handler.event(&event);
                    let out = stack.security.on_event(&event, &mut stack.keys);
                    match out.notice {
                        Some(Notice::Connected { handle, bd_addr }) => {
                            stack.l2cap.connected(handle);
                            stack.link_up(handle, bd_addr);
                        }
                        Some(Notice::Disconnected { handle, .. }) => {
                            if stack.profile.is_some_and(|p| p.handle == handle) {
                                stack.fail_profile(handler, ProfileError::Disconnected);
                            }
                            stack.link_down(handle);
                            stack.l2cap.disconnected(handle);
                            credits.reclaim(handle);
                        }
                        _ => {}
                    }
                    if let Some(notice) = out.notice {
                        handler.notice(notice);
                    }
                    if let Some(action) = out.action
                        && let Err(e) = reply(controller, handler, action).await
                    {
                        return e;
                    }
                    if let Some(request) = out.confirm {
                        let accept = handler.confirm(request).await;
                        if let Err(e) = reply(
                            controller,
                            handler,
                            stack.security.confirm(&request, accept),
                        )
                        .await
                        {
                            return e;
                        }
                    }
                }
                Some(Packet::Acl {
                    handle,
                    boundary,
                    data,
                    len,
                }) => {
                    if let Some(received) = stack.l2cap.on_acl(handle, boundary, &data[..len]) {
                        let channel = received.channel;
                        if channel.psm == sdp::PSM && channel.outgoing {
                            let mut request = [0u8; sdp::MAX_CLIENT_REQUEST];
                            let lookup = stack.sdp_client.on_response(received.data, &mut request);
                            stack.on_lookup(handler, channel.local_cid, lookup, &request);
                        } else if channel.psm == sdp::PSM {
                            let n =
                                stack
                                    .sdp
                                    .handle(received.data, channel.remote_mtu, &mut response);
                            if n > 0 {
                                let _ = stack.l2cap.send(channel.local_cid, &response[..n]);
                            }
                        } else if channel.psm == rfcomm::PSM {
                            if let Some(got) =
                                stack.rfcomm.on_data(channel.local_cid, received.data)
                            {
                                let mut tx = RfcommTx {
                                    rfcomm: &mut stack.rfcomm,
                                };
                                handler.rfcomm_data(got.dlc, got.data, &mut tx);
                            }
                        } else {
                            handler.data(&channel, received.data);
                        }
                    }
                }
            }

            while let Some(event) = stack.l2cap.pop_event() {
                match event {
                    ChannelEvent::Opened(c) if c.psm == rfcomm::PSM => {
                        stack.rfcomm.l2cap_opened(c.local_cid, c.remote_mtu);
                    }
                    ChannelEvent::Closed(c) if c.psm == rfcomm::PSM => {
                        stack.rfcomm.l2cap_closed(c.local_cid);
                    }
                    _ => {}
                }
                stack.on_profile_channel(handler, event);
                handler.channel(event);
            }
            while let Some(event) = stack.rfcomm.pop_event() {
                let profile = stack.profile.filter(|p| match (p.step, event) {
                    (Step::Channel { dlc }, RfcommEvent::Opened(d) | RfcommEvent::Failed(d)) => {
                        d == dlc
                    }
                    _ => false,
                });
                if profile.is_some() {
                    stack.profile = None;
                }
                match (event, profile) {
                    (RfcommEvent::Opened(dlc), profile) => {
                        let mut tx = RfcommTx {
                            rfcomm: &mut stack.rfcomm,
                        };
                        if let Some(p) = profile {
                            handler.profile_connected(p.bd_addr, p.uuid, dlc, &mut tx);
                        }
                        handler.rfcomm_opened(dlc, &mut tx);
                    }
                    (RfcommEvent::Closed(dlc), _) => handler.rfcomm_closed(dlc),
                    (RfcommEvent::Failed(_), Some(p)) => {
                        handler.profile_failed(p.bd_addr, p.uuid, ProfileError::Refused);
                    }
                    (RfcommEvent::Failed(_), None) => {}
                }
            }

            // RFCOMM frames become L2CAP PDUs as the outbox has room, and
            // PDUs become ACL packets as the controller has buffers.
            loop {
                while stack.l2cap.outbox_room() > 0
                    && let Some(frame) = stack.rfcomm.pop_outbound()
                {
                    let _ = stack.l2cap.send(frame.l2cap_cid, frame.as_bytes());
                }
                let mut sent = false;
                while let Some(pdu) = stack.l2cap.pop_outbound() {
                    sent = true;
                    if let Err(e) =
                        send_pdu(controller, &credits, pdu.handle, pdu.as_bytes(), acl_len).await
                    {
                        return Error::Io(e);
                    }
                }
                if !sent {
                    break;
                }
            }
        }
    };

    match select(reader, processor).await {
        Either::First(e) | Either::Second(e) => e,
    }
}

/// Sends one L2CAP PDU as ACL packets of at most `acl_len` bytes, each
/// waiting for a free controller buffer.
async fn send_pdu<C: Controller>(
    controller: &C,
    credits: &Credits,
    handle: ConnHandle,
    pdu: &[u8],
    acl_len: usize,
) -> Result<(), C::Error> {
    for (i, chunk) in pdu.chunks(acl_len).enumerate() {
        credits.take(handle).await;
        let boundary = if i == 0 {
            AclPacketBoundary::FirstFlushable
        } else {
            AclPacketBoundary::Continuing
        };
        let packet = AclPacket::new(handle, boundary, AclBroadcastFlag::PointToPoint, chunk);
        controller.write_acl_data(&packet).await?;
    }
    Ok(())
}

/// Sends a reply; a refusal goes to the handler, only an I/O error is
/// returned.
async fn reply<C: HostController, H: Handler>(
    controller: &C,
    handler: &mut H,
    action: Action,
) -> Result<(), Error<C::Error>> {
    match execute(controller, action).await {
        Err(Error::Hci(e)) => {
            handler.command_failed(action, e);
            Ok(())
        }
        other => other,
    }
}

/// Sends the command for `action`.
pub async fn execute<C: HostController>(
    controller: &C,
    action: Action,
) -> Result<(), Error<C::Error>> {
    match action {
        Action::AcceptConnection { bd_addr, role } => {
            controller
                .exec(&AcceptConnectionRequest::new(bd_addr, role))
                .await
        }
        Action::RejectConnection { bd_addr, reason } => {
            controller
                .exec(&RejectConnectionRequest::new(bd_addr, reason))
                .await
        }
        Action::LinkKeyReply { bd_addr, key } => controller
            .exec(&LinkKeyRequestReply::new(bd_addr, key))
            .await
            .map(drop),
        Action::LinkKeyNegativeReply { bd_addr } => controller
            .exec(&LinkKeyRequestNegativeReply::new(bd_addr))
            .await
            .map(drop),
        Action::PinCodeNegativeReply { bd_addr } => controller
            .exec(&PinCodeRequestNegativeReply::new(bd_addr))
            .await
            .map(drop),
        Action::IoCapabilityReply {
            bd_addr,
            io_capability,
            authentication_requirements,
        } => controller
            .exec(&IoCapabilityRequestReply::new(
                bd_addr,
                io_capability,
                OobDataPresent::NotPresent,
                authentication_requirements,
            ))
            .await
            .map(drop),
        Action::UserConfirmationReply {
            bd_addr,
            accept: true,
        } => controller
            .exec(&UserConfirmationRequestReply::new(bd_addr))
            .await
            .map(drop),
        Action::UserConfirmationReply {
            bd_addr,
            accept: false,
        } => controller
            .exec(&UserConfirmationRequestNegativeReply::new(bd_addr))
            .await
            .map(drop),
    }
}
