//! The async runner: reads the controller, drives [`Security`], and sends
//! its replies.
//!
//! A command only completes while something reads the controller, so
//! [`run`] reads in one future and handles events in another, joined by a
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
use bt_hci::event::Event;
use bt_hci::param::OobDataPresent;
use bt_hci::{ControllerToHostPacket, FromHciBytes};
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;

use crate::cmd::PinCodeRequestNegativeReply;
use crate::security::{Action, ConfirmRequest, LinkKeyStore, Notice, Security};

/// What the application hears from [`run`]. Every method has a default.
pub trait Handler {
    /// Every event, before [`Security`] sees it; for application-level
    /// events such as inquiry results.
    fn event(&mut self, event: &Event<'_>) {
        let _ = event;
    }

    /// Connection and pairing progress.
    fn notice(&mut self, notice: Notice) {
        let _ = notice;
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

/// The commands [`run`] sends. Implemented for every controller that
/// supports them, such as bt-hci's `ExternalController`.
pub trait PairingController:
    Controller
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

impl<C> PairingController for C where
    C: Controller
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

/// An event copied out of the read buffer: code, length, parameters.
struct RawEvent {
    bytes: [u8; 257],
    len: usize,
}

impl RawEvent {
    fn new(code: u8, params: &[u8]) -> Self {
        let params = &params[..params.len().min(255)];
        let mut bytes = [0u8; 257];
        bytes[0] = code;
        bytes[1] = params.len() as u8;
        bytes[2..2 + params.len()].copy_from_slice(params);
        Self {
            bytes,
            len: 2 + params.len(),
        }
    }
}

/// How many events can wait between the reader and the handler.
const QUEUE: usize = 8;

/// Runs the host until the controller fails, which is the only way it ends.
///
/// The reader never waits for the handler: while the handler waits for a
/// command to complete, only the reader can see the completion, so a reader
/// blocked on a full queue would deadlock both. When the queue is full the
/// event is dropped instead and counted, and [`Handler::events_dropped`]
/// reports it.
///
/// ACL data is dropped for now: nothing above HCI exists yet.
pub async fn run<C, S, H>(
    controller: &C,
    security: &mut Security,
    store: &mut S,
    handler: &mut H,
) -> Error<C::Error>
where
    C: PairingController,
    S: LinkKeyStore,
    H: Handler,
{
    let queue: Channel<NoopRawMutex, RawEvent, QUEUE> = Channel::new();
    let dropped = Cell::new(0u32);

    let reader = async {
        let mut buf = match controller.alloc_buf() {
            Ok(buf) => buf,
            Err(e) => return Error::Io(e),
        };
        loop {
            match controller.read(&mut buf).await {
                Ok(ControllerToHostPacket::Event(packet)) => {
                    if queue
                        .try_send(RawEvent::new(packet.kind.0, packet.data))
                        .is_err()
                    {
                        dropped.set(dropped.get().saturating_add(1));
                    }
                }
                Ok(_) => {}
                Err(e) => return Error::Io(e),
            }
        }
    };

    let processor = async {
        loop {
            let raw = queue.receive().await;
            let lost = dropped.replace(0);
            if lost > 0 {
                handler.events_dropped(lost);
            }
            let Ok(event) = Event::from_hci_bytes_complete(&raw.bytes[..raw.len]) else {
                continue;
            };
            handler.event(&event);
            let out = security.on_event(&event, store);
            if let Some(notice) = out.notice {
                handler.notice(notice);
            }
            if let Some(action) = out.action {
                if let Err(e) = execute(controller, action).await {
                    match e {
                        Error::Io(e) => return Error::Io(e),
                        Error::Hci(e) => handler.command_failed(action, e),
                    }
                }
            }
            if let Some(request) = out.confirm {
                let accept = handler.confirm(request).await;
                let action = security.confirm(&request, accept);
                if let Err(e) = execute(controller, action).await {
                    match e {
                        Error::Io(e) => return Error::Io(e),
                        Error::Hci(e) => handler.command_failed(action, e),
                    }
                }
            }
        }
    };

    match select(reader, processor).await {
        Either::First(e) | Either::Second(e) => e,
    }
}

/// Sends the command for `action`.
pub async fn execute<C: PairingController>(
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
