//! Pairing helpers for the examples: a file-backed link key store and a
//! handler that prints progress and forwards it to the example's procedure.

use std::path::PathBuf;

use bt_classic::gap;
use bt_classic::host::Handler;
use bt_classic::security::{
    Action, ConfirmRequest, LinkKeyStore, MemoryKeyStore, Notice, StoredKey,
};
use bt_hci::FromHciBytes;
use bt_hci::event::Event;
use bt_hci::param::{BdAddr, ClockOffset, LinkKeyType, PageScanRepetitionMode};
use tokio::sync::mpsc::UnboundedSender;

use super::addr;

/// Link keys kept in a text file, one `ADDRESS KEY TYPE` line per bonded
/// device, so bonds survive a restart. Without a path, keys live in memory.
pub struct KeyFile {
    path: Option<PathBuf>,
    keys: MemoryKeyStore<16>,
}

impl KeyFile {
    /// Loads `path` if it exists; `None` keeps keys in memory only.
    pub fn open(path: Option<&str>) -> std::io::Result<Self> {
        let mut keys = MemoryKeyStore::new();
        let path = path.map(PathBuf::from);
        if let Some(path) = &path
            && path.exists()
        {
            for line in std::fs::read_to_string(path)?.lines() {
                if let Some((bd_addr, key)) = parse_line(line) {
                    keys.put(bd_addr, key);
                }
            }
        }
        Ok(Self { path, keys })
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let text: String = self
            .keys
            .iter()
            .map(|(bd_addr, key)| {
                let hex: String = key.key.iter().map(|b| format!("{b:02x}")).collect();
                format!("{} {hex} {}\n", addr(bd_addr), key.kind as u8)
            })
            .collect();
        if let Err(e) = std::fs::write(path, text) {
            eprintln!("could not save link keys to {}: {e}", path.display());
        }
    }
}

impl LinkKeyStore for KeyFile {
    fn get(&mut self, bd_addr: &BdAddr) -> Option<StoredKey> {
        self.keys.get(bd_addr)
    }

    fn put(&mut self, bd_addr: BdAddr, key: StoredKey) {
        self.keys.put(bd_addr, key);
        self.save();
    }

    fn remove(&mut self, bd_addr: &BdAddr) {
        self.keys.remove(bd_addr);
        self.save();
    }
}

fn parse_line(line: &str) -> Option<(BdAddr, StoredKey)> {
    let mut fields = line.split_whitespace();
    let bd_addr = parse_addr(fields.next()?)?;
    let hex = fields.next()?;
    let kind: u8 = fields.next()?.parse().ok()?;
    if hex.len() != 32 {
        return None;
    }
    let mut key = [0u8; 16];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    let kind = LinkKeyType::from_hci_bytes_complete(&[kind]).ok()?;
    Some((bd_addr, StoredKey { key, kind }))
}

/// Parses `AA:BB:CC:DD:EE:FF`.
pub fn parse_addr(text: &str) -> Option<BdAddr> {
    let mut bytes = [0u8; 6];
    let mut parts = text.split(':');
    for byte in bytes.iter_mut().rev() {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then(|| BdAddr::new(bytes))
}

/// What the console handler passes on to an example's procedure.
pub enum Progress {
    Notice(Notice),
    Found {
        bd_addr: BdAddr,
        page_scan_repetition_mode: PageScanRepetitionMode,
        clock_offset: ClockOffset,
        name: Option<String>,
    },
    InquiryComplete,
}

/// Prints notices and forwards them, with inquiry results, to `tx`.
pub struct Console {
    pub tx: UnboundedSender<Progress>,
}

impl Handler for Console {
    fn event(&mut self, event: &Event<'_>) {
        match event {
            Event::ExtendedInquiryResult(e) => {
                let _ = self.tx.send(Progress::Found {
                    bd_addr: e.bd_addr,
                    page_scan_repetition_mode: e.page_scan_repetition_mode,
                    clock_offset: e.clock_offset,
                    name: gap::eir_name(e.eir_data.as_ref()).map(str::to_owned),
                });
            }
            Event::InquiryComplete(_) => {
                let _ = self.tx.send(Progress::InquiryComplete);
            }
            _ => {}
        }
    }

    fn notice(&mut self, notice: Notice) {
        println!("   {}", describe(&notice));
        let _ = self.tx.send(Progress::Notice(notice));
    }

    async fn confirm(&mut self, request: ConfirmRequest) -> bool {
        println!(
            "   confirm pairing with {}: {:06} (accepting)",
            addr(&request.bd_addr),
            request.numeric_value
        );
        true
    }

    fn command_failed(&mut self, action: Action, error: bt_hci::param::Error) {
        println!("   {action:?} failed: {error:?}");
    }

    fn events_dropped(&mut self, count: u32) {
        println!("   {count} event(s) dropped");
    }
}

fn describe(notice: &Notice) -> String {
    match notice {
        Notice::ConnectionRequest { bd_addr, accepted } => format!(
            "connection request from {}: {}",
            addr(bd_addr),
            if *accepted { "accepted" } else { "rejected" }
        ),
        Notice::Connected { handle, bd_addr } => {
            format!(
                "connected to {} (handle 0x{:03x})",
                addr(bd_addr),
                handle.raw()
            )
        }
        Notice::ConnectionFailed { bd_addr, status } => {
            format!("connection to {} failed: {status:?}", addr(bd_addr))
        }
        Notice::Disconnected { handle, reason } => {
            format!("disconnected (handle 0x{:03x}): {reason:?}", handle.raw())
        }
        Notice::LinkKeyRequested { bd_addr, bonded } => format!(
            "link key for {}: {}",
            addr(bd_addr),
            if *bonded {
                "bonded, using stored key"
            } else {
                "none, pairing"
            }
        ),
        Notice::PeerIoCapability {
            bd_addr,
            io_capability,
            authentication_requirements,
        } => format!(
            "{} has {io_capability:?}, wants {authentication_requirements:?}",
            addr(bd_addr)
        ),
        Notice::Paired { bd_addr, kind } => format!("paired with {}: {kind:?}", addr(bd_addr)),
        Notice::PairingFailed { bd_addr, status } => {
            format!("pairing with {} failed: {status:?}", addr(bd_addr))
        }
        Notice::LegacyPairingRefused { bd_addr } => {
            format!("refused legacy PIN pairing from {}", addr(bd_addr))
        }
        Notice::Authenticated { handle, status } => {
            format!("authentication (handle 0x{:03x}): {status:?}", handle.raw())
        }
        Notice::Encryption {
            handle,
            status,
            enabled,
        } => format!(
            "encryption {} (handle 0x{:03x}): {status:?}",
            if *enabled { "on" } else { "off" },
            handle.raw()
        ),
    }
}
