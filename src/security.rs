//! Connection acceptance and BR/EDR pairing: Secure Simple Pairing and stored
//! link keys (Core v5.4, Vol 3, Part C, 5 and Vol 2, Part F, 4).
//!
//! [`Security`] is a state machine with no I/O: feed it controller events
//! with [`Security::on_event`] and it says which reply command to send, what
//! to tell the application, and when a user has to confirm a pairing. The
//! [`crate::host`] runner drives it against a real controller.
//!
//! Legacy (PIN) pairing is refused: every phone of the last decade does SSP.

use bt_hci::event::Event;
use bt_hci::param::{
    AuthenticationRequirements, BdAddr, ConnHandle, ConnectionLinkType, EncryptionEnabledLevel,
    IoCapability, LinkKeyType, RejectReason, Role, Status,
};

/// A link key and how it was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StoredKey {
    /// The 128-bit key, as HCI carries it.
    pub key: [u8; 16],
    /// Combination key type: P-192 or P-256, with or without MITM protection.
    pub kind: LinkKeyType,
}

impl StoredKey {
    /// Whether pairing that made the key was protected against a man in the
    /// middle (numeric comparison or passkey, not Just Works).
    pub fn is_authenticated(&self) -> bool {
        matches!(
            self.kind,
            LinkKeyType::AuthenticatedCombinationKeyP192
                | LinkKeyType::AuthenticatedCombinationKeyP256
        )
    }
}

/// Where bonded devices' link keys live: flash on a device, a file on a PC.
pub trait LinkKeyStore {
    /// The key for `bd_addr`, if bonded.
    fn get(&mut self, bd_addr: &BdAddr) -> Option<StoredKey>;
    /// Stores or replaces the key for `bd_addr`.
    fn put(&mut self, bd_addr: BdAddr, key: StoredKey);
    /// Forgets `bd_addr`, for example after its key was rejected.
    fn remove(&mut self, bd_addr: &BdAddr);
}

/// A [`LinkKeyStore`] in RAM for up to `N` devices, forgotten on reset.
/// When full, a new device replaces the oldest one.
pub struct MemoryKeyStore<const N: usize> {
    entries: [Option<(BdAddr, StoredKey)>; N],
    next: usize,
}

impl<const N: usize> Default for MemoryKeyStore<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> MemoryKeyStore<N> {
    /// An empty store.
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            next: 0,
        }
    }

    /// The bonded devices.
    pub fn iter(&self) -> impl Iterator<Item = &(BdAddr, StoredKey)> {
        self.entries.iter().flatten()
    }
}

impl<const N: usize> LinkKeyStore for MemoryKeyStore<N> {
    fn get(&mut self, bd_addr: &BdAddr) -> Option<StoredKey> {
        self.iter()
            .find(|(addr, _)| addr == bd_addr)
            .map(|&(_, key)| key)
    }

    fn put(&mut self, bd_addr: BdAddr, key: StoredKey) {
        if N == 0 {
            return;
        }
        let slot = self
            .entries
            .iter()
            .position(|e| matches!(e, Some((addr, _)) if *addr == bd_addr))
            .or_else(|| self.entries.iter().position(Option::is_none))
            .unwrap_or_else(|| {
                let oldest = self.next;
                self.next = (self.next + 1) % N;
                oldest
            });
        self.entries[slot] = Some((bd_addr, key));
    }

    fn remove(&mut self, bd_addr: &BdAddr) {
        for entry in &mut self.entries {
            if matches!(entry, Some((addr, _)) if addr == bd_addr) {
                *entry = None;
            }
        }
    }
}

/// How the device pairs and accepts connections.
#[derive(Clone, Copy, Debug)]
pub struct SecurityConfig {
    /// What the device can show or enter. A dongle without a screen is
    /// `NoInputNoOutput`, which means Just Works pairing.
    pub io_capability: IoCapability,
    /// Require protection against a man in the middle. Impossible with
    /// `NoInputNoOutput`; stored keys made without it are not used.
    pub mitm: bool,
    /// Keep the link key after pairing, so the peer reconnects without
    /// pairing again.
    pub bonding: bool,
    /// The role asked for when accepting a connection. Phones expect an
    /// accessory to stay `Peripheral`.
    pub accept_role: Role,
    /// Accept incoming ACL connections at all.
    pub connectable: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            io_capability: IoCapability::NoInputNoOutput,
            mitm: false,
            bonding: true,
            accept_role: Role::Peripheral,
            connectable: true,
        }
    }
}

impl SecurityConfig {
    fn authentication_requirements(&self) -> AuthenticationRequirements {
        match (self.bonding, self.mitm) {
            (true, true) => AuthenticationRequirements::MitmRequiredGeneralBonding,
            (true, false) => AuthenticationRequirements::MitmNotRequiredGeneralBonding,
            (false, true) => AuthenticationRequirements::MitmRequiredNoBonding,
            (false, false) => AuthenticationRequirements::MitmNotRequiredNoBonding,
        }
    }
}

/// A reply command for the controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Action {
    /// Accept_Connection_Request.
    AcceptConnection { bd_addr: BdAddr, role: Role },
    /// Reject_Connection_Request.
    RejectConnection {
        bd_addr: BdAddr,
        reason: RejectReason,
    },
    /// Link_Key_Request_Reply.
    LinkKeyReply { bd_addr: BdAddr, key: [u8; 16] },
    /// Link_Key_Request_Negative_Reply: pair instead.
    LinkKeyNegativeReply { bd_addr: BdAddr },
    /// PIN_Code_Request_Negative_Reply: legacy pairing is refused.
    PinCodeNegativeReply { bd_addr: BdAddr },
    /// IO_Capability_Request_Reply.
    IoCapabilityReply {
        bd_addr: BdAddr,
        io_capability: IoCapability,
        authentication_requirements: AuthenticationRequirements,
    },
    /// User_Confirmation_Request_Reply or its negative reply.
    UserConfirmationReply { bd_addr: BdAddr, accept: bool },
}

/// Something the application may want to know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Notice {
    /// A device asked to connect; `accepted` says what we answered.
    ConnectionRequest { bd_addr: BdAddr, accepted: bool },
    /// An ACL connection is up.
    Connected { handle: ConnHandle, bd_addr: BdAddr },
    /// An ACL connection attempt failed.
    ConnectionFailed { bd_addr: BdAddr, status: Status },
    /// A connection went down.
    Disconnected { handle: ConnHandle, reason: Status },
    /// The controller asked for a link key; `bonded` says whether we had one.
    LinkKeyRequested { bd_addr: BdAddr, bonded: bool },
    /// The peer's side of the IO capability exchange.
    PeerIoCapability {
        bd_addr: BdAddr,
        io_capability: IoCapability,
        authentication_requirements: AuthenticationRequirements,
    },
    /// Pairing finished; the key is stored if bonding.
    Paired { bd_addr: BdAddr, kind: LinkKeyType },
    /// Pairing failed.
    PairingFailed { bd_addr: BdAddr, status: Status },
    /// A peer tried legacy PIN pairing, which was refused.
    LegacyPairingRefused { bd_addr: BdAddr },
    /// Authentication we started finished.
    Authenticated { handle: ConnHandle, status: Status },
    /// Encryption was switched on or off.
    Encryption {
        handle: ConnHandle,
        status: Status,
        enabled: bool,
    },
}

/// A pairing that needs the user to compare `numeric_value` with the one
/// the peer shows. Answer with [`Security::confirm`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConfirmRequest {
    pub bd_addr: BdAddr,
    pub numeric_value: u32,
}

/// What one event leads to. Any combination of the fields may be set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Output {
    /// Send this command.
    pub action: Option<Action>,
    /// Tell the application this.
    pub notice: Option<Notice>,
    /// Ask the user this, then call [`Security::confirm`].
    pub confirm: Option<ConfirmRequest>,
}

impl Output {
    fn action(action: Action) -> Self {
        Self {
            action: Some(action),
            ..Self::default()
        }
    }

    fn notice(notice: Notice) -> Self {
        Self {
            notice: Some(notice),
            ..Self::default()
        }
    }

    fn with_notice(mut self, notice: Notice) -> Self {
        self.notice = Some(notice);
        self
    }
}

/// How many pairings can be in progress at once.
const PENDING: usize = 4;

/// The pairing state machine. See the [module docs](self).
pub struct Security {
    config: SecurityConfig,
    /// Peers' IO capabilities from IO_Capability_Response, for deciding
    /// whether a confirmation needs the user.
    peer_io: [Option<(BdAddr, IoCapability)>; PENDING],
}

impl Security {
    /// A state machine for `config`.
    pub const fn new(config: SecurityConfig) -> Self {
        Self {
            config,
            peer_io: [None; PENDING],
        }
    }

    /// The configuration.
    pub const fn config(&self) -> &SecurityConfig {
        &self.config
    }

    /// Handles one controller event. Events this layer does not care about
    /// give an empty [`Output`].
    pub fn on_event(&mut self, event: &Event<'_>, store: &mut impl LinkKeyStore) -> Output {
        match event {
            Event::ConnectionRequest(e) => {
                let accepted = self.config.connectable && e.link_type == ConnectionLinkType::Acl;
                let action = if accepted {
                    Action::AcceptConnection {
                        bd_addr: e.bd_addr,
                        role: self.config.accept_role,
                    }
                } else {
                    Action::RejectConnection {
                        bd_addr: e.bd_addr,
                        reason: RejectReason::LimitedResources,
                    }
                };
                Output::action(action).with_notice(Notice::ConnectionRequest {
                    bd_addr: e.bd_addr,
                    accepted,
                })
            }
            Event::ConnectionComplete(e) => Output::notice(if e.status == Status::SUCCESS {
                Notice::Connected {
                    handle: e.handle,
                    bd_addr: e.bd_addr,
                }
            } else {
                Notice::ConnectionFailed {
                    bd_addr: e.bd_addr,
                    status: e.status,
                }
            }),
            Event::DisconnectionComplete(e) => Output::notice(Notice::Disconnected {
                handle: e.handle,
                reason: e.reason,
            }),
            Event::LinkKeyRequest(e) => {
                let usable = store
                    .get(&e.bd_addr)
                    .filter(|key| !self.config.mitm || key.is_authenticated());
                let action = match usable {
                    Some(key) => Action::LinkKeyReply {
                        bd_addr: e.bd_addr,
                        key: key.key,
                    },
                    None => Action::LinkKeyNegativeReply { bd_addr: e.bd_addr },
                };
                Output::action(action).with_notice(Notice::LinkKeyRequested {
                    bd_addr: e.bd_addr,
                    bonded: usable.is_some(),
                })
            }
            Event::PinCodeRequest(e) => {
                Output::action(Action::PinCodeNegativeReply { bd_addr: e.bd_addr })
                    .with_notice(Notice::LegacyPairingRefused { bd_addr: e.bd_addr })
            }
            Event::IoCapabilityRequest(e) => Output::action(Action::IoCapabilityReply {
                bd_addr: e.bd_addr,
                io_capability: self.config.io_capability,
                authentication_requirements: self.config.authentication_requirements(),
            }),
            Event::IoCapabilityResponse(e) => {
                self.remember_peer_io(e.bd_addr, e.io_capability);
                Output::notice(Notice::PeerIoCapability {
                    bd_addr: e.bd_addr,
                    io_capability: e.io_capability,
                    authentication_requirements: e.authentication_requirements,
                })
            }
            Event::UserConfirmationRequest(e) => {
                if self.needs_user(&e.bd_addr) {
                    Output {
                        confirm: Some(ConfirmRequest {
                            bd_addr: e.bd_addr,
                            numeric_value: e.numeric_value,
                        }),
                        ..Output::default()
                    }
                } else {
                    // Just Works: nothing to compare, so confirm on the user's behalf.
                    Output::action(Action::UserConfirmationReply {
                        bd_addr: e.bd_addr,
                        accept: true,
                    })
                }
            }
            Event::SimplePairingComplete(e) => {
                self.forget_peer_io(&e.bd_addr);
                if e.status == Status::SUCCESS {
                    // Paired is reported with the key, in Link_Key_Notification.
                    Output::default()
                } else {
                    Output::notice(Notice::PairingFailed {
                        bd_addr: e.bd_addr,
                        status: e.status,
                    })
                }
            }
            Event::LinkKeyNotification(e) => {
                if self.config.bonding {
                    store.put(
                        e.bd_addr,
                        StoredKey {
                            key: e.link_key,
                            kind: e.key_type,
                        },
                    );
                }
                Output::notice(Notice::Paired {
                    bd_addr: e.bd_addr,
                    kind: e.key_type,
                })
            }
            Event::AuthenticationComplete(e) => Output::notice(Notice::Authenticated {
                handle: e.handle,
                status: e.status,
            }),
            Event::EncryptionChangeV1(e) => Output::notice(Notice::Encryption {
                handle: e.handle,
                status: e.status,
                enabled: e.enabled != EncryptionEnabledLevel::Off,
            }),
            _ => Output::default(),
        }
    }

    /// The reply to a [`ConfirmRequest`].
    pub fn confirm(&self, request: &ConfirmRequest, accept: bool) -> Action {
        Action::UserConfirmationReply {
            bd_addr: request.bd_addr,
            accept,
        }
    }

    /// Numeric comparison only means something when both sides can show the
    /// number and answer yes or no; every other combination is Just Works.
    fn needs_user(&self, bd_addr: &BdAddr) -> bool {
        if self.config.io_capability != IoCapability::DisplayYesNo {
            return false;
        }
        let peer = self
            .peer_io
            .iter()
            .flatten()
            .find(|(addr, _)| addr == bd_addr)
            .map(|&(_, io)| io);
        // Without the peer's answer, ask rather than guess.
        peer.is_none_or(|io| io == IoCapability::DisplayYesNo)
    }

    fn remember_peer_io(&mut self, bd_addr: BdAddr, io: IoCapability) {
        self.forget_peer_io(&bd_addr);
        let slot = self.peer_io.iter().position(Option::is_none).unwrap_or(0);
        self.peer_io[slot] = Some((bd_addr, io));
    }

    fn forget_peer_io(&mut self, bd_addr: &BdAddr) {
        for entry in &mut self.peer_io {
            if matches!(entry, Some((addr, _)) if addr == bd_addr) {
                *entry = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bt_hci::FromHciBytes;

    const PHONE: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

    fn phone() -> BdAddr {
        BdAddr::new(PHONE)
    }

    /// Parses an event from its HCI bytes: code, length, parameters.
    fn event(code: u8, params: &[u8]) -> ([u8; 258], usize) {
        let mut buf = [0u8; 258];
        buf[0] = code;
        buf[1] = params.len() as u8;
        buf[2..2 + params.len()].copy_from_slice(params);
        (buf, 2 + params.len())
    }

    fn feed(
        security: &mut Security,
        store: &mut impl LinkKeyStore,
        code: u8,
        params: &[u8],
    ) -> Output {
        let (buf, len) = event(code, params);
        let event = Event::from_hci_bytes_complete(&buf[..len]).unwrap();
        security.on_event(&event, store)
    }

    fn with_addr(rest: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..6].copy_from_slice(&PHONE);
        out[6..6 + rest.len()].copy_from_slice(rest);
        out
    }

    #[test]
    fn accepts_acl_and_rejects_sco() {
        let mut security = Security::new(SecurityConfig::default());
        let mut store = MemoryKeyStore::<2>::new();

        // Connection_Request: address, class of device, link type ACL.
        let acl = with_addr(&[0x0c, 0x02, 0x5a, 0x01]);
        let out = feed(&mut security, &mut store, 0x04, &acl[..10]);
        assert_eq!(
            out.action,
            Some(Action::AcceptConnection {
                bd_addr: phone(),
                role: Role::Peripheral
            })
        );

        let sco = with_addr(&[0x0c, 0x02, 0x5a, 0x00]);
        let out = feed(&mut security, &mut store, 0x04, &sco[..10]);
        assert!(matches!(out.action, Some(Action::RejectConnection { .. })));
    }

    #[test]
    fn just_works_pairing_stores_the_key() {
        let mut security = Security::new(SecurityConfig::default());
        let mut store = MemoryKeyStore::<2>::new();
        let addr = with_addr(&[]);

        // Link_Key_Request without a bond: pair.
        let out = feed(&mut security, &mut store, 0x17, &addr[..6]);
        assert_eq!(
            out.action,
            Some(Action::LinkKeyNegativeReply { bd_addr: phone() })
        );

        // IO_Capability_Request: NoInputNoOutput, general bonding, no MITM.
        let out = feed(&mut security, &mut store, 0x31, &addr[..6]);
        assert_eq!(
            out.action,
            Some(Action::IoCapabilityReply {
                bd_addr: phone(),
                io_capability: IoCapability::NoInputNoOutput,
                authentication_requirements:
                    AuthenticationRequirements::MitmNotRequiredGeneralBonding,
            })
        );

        // IO_Capability_Response: the phone is DisplayYesNo and wants MITM.
        let response = with_addr(&[0x01, 0x00, 0x05]);
        feed(&mut security, &mut store, 0x32, &response[..9]);

        // User_Confirmation_Request: Just Works, confirmed without asking.
        let confirm = with_addr(&123456u32.to_le_bytes());
        let out = feed(&mut security, &mut store, 0x33, &confirm[..10]);
        assert_eq!(out.confirm, None);
        assert_eq!(
            out.action,
            Some(Action::UserConfirmationReply {
                bd_addr: phone(),
                accept: true
            })
        );

        // Simple_Pairing_Complete, then Link_Key_Notification with a P-256 unauthenticated key.
        let mut complete = [0u8; 7];
        complete[1..].copy_from_slice(&PHONE);
        assert_eq!(
            feed(&mut security, &mut store, 0x36, &complete),
            Output::default()
        );

        let mut notification = with_addr(&[0xab; 16]);
        notification[22] = 0x07;
        let out = feed(&mut security, &mut store, 0x18, &notification[..23]);
        assert_eq!(
            out.notice,
            Some(Notice::Paired {
                bd_addr: phone(),
                kind: LinkKeyType::UnauthenticatedCombinationKeyP256
            })
        );

        // The next Link_Key_Request is answered from the store.
        let out = feed(&mut security, &mut store, 0x17, &addr[..6]);
        assert_eq!(
            out.action,
            Some(Action::LinkKeyReply {
                bd_addr: phone(),
                key: [0xab; 16]
            })
        );
    }

    #[test]
    fn numeric_comparison_asks_the_user() {
        let mut security = Security::new(SecurityConfig {
            io_capability: IoCapability::DisplayYesNo,
            ..SecurityConfig::default()
        });
        let mut store = MemoryKeyStore::<2>::new();

        let response = with_addr(&[0x01, 0x00, 0x05]);
        feed(&mut security, &mut store, 0x32, &response[..9]);
        let confirm = with_addr(&654321u32.to_le_bytes());
        let out = feed(&mut security, &mut store, 0x33, &confirm[..10]);
        let request = out.confirm.unwrap();
        assert_eq!(request.numeric_value, 654321);
        assert_eq!(out.action, None);
        assert_eq!(
            security.confirm(&request, false),
            Action::UserConfirmationReply {
                bd_addr: phone(),
                accept: false
            }
        );

        // A NoInputNoOutput peer makes it Just Works even for us.
        let response = with_addr(&[0x03, 0x00, 0x04]);
        feed(&mut security, &mut store, 0x32, &response[..9]);
        let out = feed(&mut security, &mut store, 0x33, &confirm[..10]);
        assert_eq!(out.confirm, None);
    }

    #[test]
    fn mitm_ignores_unauthenticated_keys() {
        let mut security = Security::new(SecurityConfig {
            io_capability: IoCapability::DisplayYesNo,
            mitm: true,
            ..SecurityConfig::default()
        });
        let mut store = MemoryKeyStore::<2>::new();
        store.put(
            phone(),
            StoredKey {
                key: [1; 16],
                kind: LinkKeyType::UnauthenticatedCombinationKeyP192,
            },
        );
        let addr = with_addr(&[]);
        let out = feed(&mut security, &mut store, 0x17, &addr[..6]);
        assert_eq!(
            out.action,
            Some(Action::LinkKeyNegativeReply { bd_addr: phone() })
        );
    }

    #[test]
    fn legacy_pin_pairing_is_refused() {
        let mut security = Security::new(SecurityConfig::default());
        let mut store = MemoryKeyStore::<2>::new();
        let addr = with_addr(&[]);
        let out = feed(&mut security, &mut store, 0x16, &addr[..6]);
        assert_eq!(
            out.action,
            Some(Action::PinCodeNegativeReply { bd_addr: phone() })
        );
    }

    #[test]
    fn memory_store_replaces_the_oldest() {
        let key = |n| StoredKey {
            key: [n; 16],
            kind: LinkKeyType::CombinationKey,
        };
        let addr = |n| BdAddr::new([n; 6]);
        let mut store = MemoryKeyStore::<2>::new();
        store.put(addr(1), key(1));
        store.put(addr(2), key(2));
        store.put(addr(1), key(11)); // update in place
        store.put(addr(3), key(3)); // full: replaces the oldest slot
        assert_eq!(store.get(&addr(1)), None);
        assert_eq!(store.get(&addr(2)), Some(key(2)));
        assert_eq!(store.get(&addr(3)), Some(key(3)));
        store.remove(&addr(2));
        assert_eq!(store.get(&addr(2)), None);
    }
}
