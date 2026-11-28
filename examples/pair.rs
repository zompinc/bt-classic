//! Plays the phone: finds a device by name, connects, pairs, encrypts and
//! disconnects, then does it again to show the bond holds. A test peer for
//! the `discoverable` example.
//!
//! ```sh
//! cargo run --example pair -- --expect bt-classic --rounds 2
//! ```
//!
//! The first round must pair (Secure Simple Pairing, Just Works), or use the
//! bond in a `--keys` file from an earlier run; later rounds must
//! authenticate with the stored link key and not pair again. It exits with
//! status 1 otherwise. `--no-sc` turns Secure Connections off (P-192 keys).
//!
//! `--profile UUID` (16-bit, hex) then connects that profile in the last
//! round, the way a headset connects to a phone, sends `AT+CKPD=200\r` and
//! expects it echoed: `--profile 1108` against the `discoverable` example,
//! which echoes on its headset channel.

mod common;

use std::time::Duration;

use bt_classic::cmd::{WriteInquiryMode, inquiry_mode};
use bt_classic::gap::{self, ClassOfDevice, major};
use bt_classic::host::{self, Requests, Stack};
use bt_classic::security::{Notice, SecurityConfig};
use bt_hci::cmd::link_control::{
    AuthenticationRequested, CreateConnection, Disconnect, Inquiry, SetConnectionEncryption,
};
use bt_hci::controller::ControllerCmdSync;
use bt_hci::param::{AllowRoleSwitch, BdAddr, ConnHandle, DisconnectReason, PacketType, Status};
use common::pairing::{Console, KeyFile, Progress};
use common::{Hci, Options, addr};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use tokio::time::timeout;

/// The General Inquiry Access Code, 0x9E8B33.
const GIAC: [u8; 3] = [0x33, 0x8b, 0x9e];

/// How long any one step may take.
const STEP: Duration = Duration::from_secs(20);

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    const USAGE: &str = "pair --expect NAME [--rounds N] [--keys FILE] [--no-sc] [--profile UUID]";
    let options = Options::parse(USAGE);
    let Some(expected) = options.value("--expect").map(str::to_owned) else {
        common::exit_usage(USAGE);
    };
    let profile = match options
        .value("--profile")
        .map(|p| u16::from_str_radix(p, 16))
    {
        None => None,
        Some(Ok(uuid)) => Some(uuid),
        Some(Err(_)) => common::exit_usage(USAGE),
    };
    let rounds: u32 = options.value("--rounds").map_or(Ok(2), str::parse)?;
    let keys = KeyFile::open(options.value("--keys"))?;
    let hci = common::connect(&options).await?;

    let (tx, rx) = unbounded_channel();
    let mut console = Console {
        tx,
        echo: false,
        greeting: GREETING.to_vec(),
    };
    let security = SecurityConfig {
        connectable: false,
        ..SecurityConfig::default()
    };
    let mut stack = Stack::new(security, &[], keys);
    let config = gap::Config {
        name: "bt-classic-peer",
        class_of_device: ClassOfDevice::new(0, major::PHONE, 0x03),
        uuid16: &[],
        uuid128: &[],
        discoverable: false,
        connectable: false,
        secure_connections: !options.rest.iter().any(|a| a == "--no-sc"),
    };
    let requests = Requests::new();
    let runner = host::run(&hci, &mut stack, &config, &mut console, &requests);
    let procedure = procedure(&hci, &requests, rx, &expected, rounds, profile);

    let result = tokio::select! {
        result = procedure => result,
        error = runner => Err(format!("controller failed: {error:?}")),
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
    Ok(())
}

async fn procedure(
    hci: &Hci,
    requests: &Requests,
    mut rx: UnboundedReceiver<Progress>,
    expected: &str,
    rounds: u32,
    profile: Option<u16>,
) -> Result<(), String> {
    let fail = |what: &str| {
        let what = what.to_owned();
        move |e| format!("{what}: {e:?}")
    };

    // The runner brings the controller up first.
    while !matches!(next(&mut rx).await?, Progress::Ready(_)) {}
    hci.exec(&WriteInquiryMode::new(inquiry_mode::EXTENDED))
        .await
        .map_err(fail("inquiry mode"))?;
    hci.exec(&Inquiry::new(GIAC, 3, 0))
        .await
        .map_err(fail("inquiry"))?;
    println!("   looking for {expected:?}");

    let mut target = None;
    loop {
        match next(&mut rx).await? {
            Progress::Found {
                bd_addr,
                page_scan_repetition_mode,
                clock_offset,
                name,
            } if name.as_deref() == Some(expected) && target.is_none() => {
                println!("   found {expected:?} at {}", addr(&bd_addr));
                target = Some((bd_addr, page_scan_repetition_mode, clock_offset));
            }
            Progress::InquiryComplete => break,
            _ => {}
        }
    }
    let Some((bd_addr, psrm, clock_offset)) = target else {
        return Err(format!("no device named {expected:?} answered"));
    };

    let packet_types = PacketType::new()
        .set_dh1_may_be_used(true)
        .set_dm3_may_be_used(true)
        .set_dh3_may_be_used(true)
        .set_dm5_may_be_used(true)
        .set_dh5_may_be_used(true);

    for round in 1..=rounds {
        println!("   round {round}: connecting");
        let connect = CreateConnection::new(
            bd_addr,
            packet_types,
            psrm,
            0,
            clock_offset,
            AllowRoleSwitch::Allowed,
        );
        hci.exec(&connect)
            .await
            .map_err(fail("create connection"))?;
        let handle = wait(&mut rx, |n| match n {
            Notice::Connected { handle, bd_addr: a } if *a == bd_addr => Some(Ok(*handle)),
            Notice::ConnectionFailed { status, .. } => {
                Some(Err(format!("connection failed: {status:?}")))
            }
            _ => None,
        })
        .await??;

        hci.exec(&AuthenticationRequested::new(handle))
            .await
            .map_err(fail("authentication"))?;
        let mut paired = false;
        let mut bonded = false;
        let status = wait(&mut rx, |n| match n {
            Notice::Paired { .. } => {
                paired = true;
                None
            }
            Notice::LinkKeyRequested { bonded: b, .. } => {
                bonded = *b;
                None
            }
            Notice::PairingFailed { status, .. } => Some(*status),
            Notice::Authenticated { handle: h, status } if *h == handle => Some(*status),
            _ => None,
        })
        .await?;
        if status != Status::SUCCESS {
            return Err(format!("round {round}: authentication failed: {status:?}"));
        }
        match (round, paired, bonded) {
            // Round 1 pairs, unless a --keys file already holds a bond.
            (1, true, _) => println!("   round 1: paired"),
            (_, false, true) => println!("   round {round}: reconnected with the stored key"),
            (1, false, false) => {
                return Err(String::from("round 1: authenticated without pairing"));
            }
            _ => {
                return Err(format!(
                    "round {round}: paired again instead of using the bond"
                ));
            }
        }

        hci.exec(&SetConnectionEncryption::new(handle, true))
            .await
            .map_err(fail("encryption"))?;
        wait(&mut rx, |n| match n {
            Notice::Encryption {
                handle: h,
                status,
                enabled,
            } if *h == handle => Some((*status == Status::SUCCESS && *enabled).then_some(())),
            _ => None,
        })
        .await?
        .ok_or_else(|| format!("round {round}: encryption did not come on"))?;

        if let Some(uuid) = profile.filter(|_| round == rounds) {
            connect_profile(requests, &mut rx, bd_addr, uuid).await?;
        }
        disconnect(hci, &mut rx, handle).await?;
    }
    println!("   {rounds} round(s) passed");
    Ok(())
}

/// What a headset sends first; the peer under test echoes it.
const GREETING: &[u8] = b"AT+CKPD=200\r";

/// Connects profile `uuid` and checks that the greeting comes back.
async fn connect_profile(
    requests: &Requests,
    rx: &mut UnboundedReceiver<Progress>,
    bd_addr: BdAddr,
    uuid: u16,
) -> Result<(), String> {
    println!("   connecting profile 0x{uuid:04x}");
    if !requests.connect_profile(bd_addr, uuid) {
        return Err(String::from("request queue full"));
    }
    let dlc = loop {
        if let Progress::Profile(result) = next(rx).await? {
            break result.map_err(|e| format!("profile 0x{uuid:04x}: {e:?}"))?;
        }
    };
    let mut echoed = Vec::new();
    while echoed.len() < GREETING.len() {
        if let Progress::Data(d, data) = next(rx).await?
            && d == dlc
        {
            echoed.extend_from_slice(&data);
        }
    }
    if echoed != GREETING {
        return Err(format!("profile 0x{uuid:04x}: got {echoed:?} back"));
    }
    println!(
        "   profile 0x{uuid:04x}: greeting echoed on channel {}",
        dlc.channel()
    );
    Ok(())
}

async fn disconnect(
    hci: &Hci,
    rx: &mut UnboundedReceiver<Progress>,
    handle: ConnHandle,
) -> Result<(), String> {
    let request = Disconnect::new(handle, DisconnectReason::RemoteUserTerminatedConn);
    // Disconnect is answered with Command Status only, so it is an async command.
    bt_hci::controller::ControllerCmdAsync::exec(hci, &request)
        .await
        .map_err(|e| format!("disconnect: {e:?}"))?;
    wait(rx, |n| {
        matches!(n, Notice::Disconnected { handle: h, .. } if *h == handle).then_some(())
    })
    .await
}

/// The next progress report, or an error after [`STEP`].
async fn next(rx: &mut UnboundedReceiver<Progress>) -> Result<Progress, String> {
    match timeout(STEP, rx.recv()).await {
        Ok(Some(progress)) => Ok(progress),
        Ok(None) => Err(String::from("host stopped")),
        Err(_) => Err(String::from("timed out")),
    }
}

/// Waits for a notice that `pick` maps to a value, skipping the rest.
async fn wait<T>(
    rx: &mut UnboundedReceiver<Progress>,
    mut pick: impl FnMut(&Notice) -> Option<T>,
) -> Result<T, String> {
    loop {
        if let Progress::Notice(notice) = next(rx).await?
            && let Some(value) = pick(&notice)
        {
            return Ok(value);
        }
    }
}
