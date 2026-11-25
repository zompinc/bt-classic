//! The async runner: brings the controller up, then reads it, drives
//! [`Security`], [`L2cap`] and the [`SdpServer`], and sends their replies.
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
use bt_hci::param::{ConnHandle, OobDataPresent};
use bt_hci::{ControllerToHostPacket, FromHciBytes};
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;

use crate::cmd::PinCodeRequestNegativeReply;
use crate::gap::{self, ClassicController, ControllerInfo};
use crate::l2cap::{self, ChannelEvent, L2cap};
use crate::sdp::{self, SdpServer, ServiceRecord};
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

/// A [`Handler`] that ignores everything and accepts every confirmation.
pub struct NoHandler;

impl Handler for NoHandler {}

/// Everything the runner drives, owned by the application so it can be a
/// `static` on a device.
pub struct Stack<'r, S> {
    pub security: Security,
    pub l2cap: L2cap,
    pub sdp: SdpServer<'r>,
    pub keys: S,
}

impl<'r, S: LinkKeyStore> Stack<'r, S> {
    /// A stack that pairs as `security` says, serves `records` over SDP and
    /// keeps link keys in `keys`.
    pub fn new(security: SecurityConfig, records: &'r [ServiceRecord<'r>], keys: S) -> Self {
        let mut l2cap = L2cap::new();
        l2cap.register(sdp::PSM);
        Self {
            security: Security::new(security),
            l2cap,
            sdp: SdpServer::new(records),
            keys,
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

/// How many packets can wait between the reader and the handler.
const QUEUE: usize = 8;

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
pub async fn run<C, S, H>(
    controller: &C,
    stack: &mut Stack<'_, S>,
    gap: &gap::Config<'_>,
    handler: &mut H,
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
            let packet = queue.receive().await;
            let lost = dropped.replace(0);
            if lost > 0 {
                handler.events_dropped(lost);
            }
            match packet {
                Packet::Event { bytes, len } => {
                    let Ok(event) = Event::from_hci_bytes_complete(&bytes[..len]) else {
                        continue;
                    };
                    handler.event(&event);
                    let out = stack.security.on_event(&event, &mut stack.keys);
                    match out.notice {
                        Some(Notice::Connected { handle, .. }) => stack.l2cap.connected(handle),
                        Some(Notice::Disconnected { handle, .. }) => {
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
                Packet::Acl {
                    handle,
                    boundary,
                    data,
                    len,
                } => {
                    if let Some(received) = stack.l2cap.on_acl(handle, boundary, &data[..len]) {
                        let channel = received.channel;
                        if channel.psm == sdp::PSM {
                            let n =
                                stack
                                    .sdp
                                    .handle(received.data, channel.remote_mtu, &mut response);
                            if n > 0 {
                                let _ = stack.l2cap.send(channel.local_cid, &response[..n]);
                            }
                        } else {
                            handler.data(&channel, received.data);
                        }
                    }
                }
            }

            while let Some(event) = stack.l2cap.pop_event() {
                handler.channel(event);
            }
            while let Some(pdu) = stack.l2cap.pop_outbound() {
                if let Err(e) =
                    send_pdu(controller, &credits, pdu.handle, pdu.as_bytes(), acl_len).await
                {
                    return Error::Io(e);
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
