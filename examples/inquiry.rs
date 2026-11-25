//! Runs an inquiry and lists the classic devices that answer, with the name
//! and services from their EIR. A test peer for the `discoverable` example.
//!
//! ```sh
//! cargo run --example inquiry -- --seconds 5 --expect bt-classic
//! ```
//!
//! With `--expect NAME` it also pages that device for its name (Remote Name
//! Request, as phones do) and exits with status 1 unless both the EIR and
//! the remote name match.

mod common;

use bt_classic::cmd::{WriteInquiryMode, inquiry_mode};
use bt_classic::gap::{self, ClassOfDevice, eir_type};
use bt_hci::cmd::controller_baseband::{Reset, SetEventMask};
use bt_hci::cmd::link_control::{Inquiry, RemoteNameRequest};
use bt_hci::controller::ControllerCmdSync;
use bt_hci::event::Event;
use bt_hci::param::{BdAddr, ClockOffset, PageScanRepetitionMode, Status};
use common::{Options, addr};
use tokio::sync::mpsc;

/// The General Inquiry Access Code, 0x9E8B33.
const GIAC: [u8; 3] = [0x33, 0x8b, 0x9e];

/// The events this example acts on, copied out of the read buffer.
enum Report {
    Found {
        bd_addr: BdAddr,
        page_scan_repetition_mode: PageScanRepetitionMode,
        clock_offset: ClockOffset,
        name: Option<String>,
    },
    InquiryComplete(Status),
    RemoteName {
        status: Status,
        name: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse("inquiry [--seconds N] [--expect NAME]");
    let seconds: f64 = options.value("--seconds").map_or(Ok(5.0), str::parse)?;
    let expect = options.value("--expect").map(str::to_owned);
    // Inquiry length is in units of 1.28 s, 1 to 0x30.
    let length = ((seconds / 1.28).ceil() as u8).clamp(1, 0x30);
    let hci = common::connect(&options).await?;

    let (tx, mut rx) = mpsc::unbounded_channel();
    let events = common::events(&hci, |event| {
        let report = match event {
            Event::ExtendedInquiryResult(e) => {
                print_result(&e.bd_addr, e.class_of_device, e.rssi, e.eir_data.as_ref());
                Report::Found {
                    bd_addr: e.bd_addr,
                    page_scan_repetition_mode: e.page_scan_repetition_mode,
                    clock_offset: e.clock_offset,
                    name: gap::eir_name(e.eir_data.as_ref()).map(str::to_owned),
                }
            }
            Event::InquiryComplete(e) => Report::InquiryComplete(e.status),
            Event::RemoteNameRequestComplete(e) => {
                let raw: &[u8] = e.remote_name.as_ref();
                let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                Report::RemoteName {
                    status: e.status,
                    name: String::from_utf8_lossy(&raw[..end]).into_owned(),
                }
            }
            Event::InquiryResult(_) | Event::InquiryResultWithRssi(_) => {
                println!("   found a device without EIR");
                return None;
            }
            _ => return None,
        };
        let _ = tx.send(report);
        None::<()>
    });

    let scan = async {
        let fail = |e| format!("{e:?}");
        hci.exec(&Reset::new()).await.map_err(fail)?;
        hci.exec(&SetEventMask::new(gap::classic_event_mask()))
            .await
            .map_err(fail)?;
        hci.exec(&WriteInquiryMode::new(inquiry_mode::EXTENDED))
            .await
            .map_err(fail)?;
        hci.exec(&Inquiry::new(GIAC, length, 0))
            .await
            .map_err(fail)?;
        println!("   inquiring for {:.2} s", f64::from(length) * 1.28);

        let mut found = Vec::new();
        loop {
            match rx.recv().await {
                Some(Report::Found {
                    bd_addr,
                    page_scan_repetition_mode,
                    clock_offset,
                    name,
                }) => found.push((bd_addr, page_scan_repetition_mode, clock_offset, name)),
                Some(Report::InquiryComplete(status)) => {
                    println!("   inquiry complete: {status:?}, {} device(s)", found.len());
                    break;
                }
                Some(Report::RemoteName { .. }) => {}
                None => return Err(String::from("event loop ended")),
            }
        }

        let Some(expected) = expect else {
            return Ok(());
        };
        let Some(&(bd_addr, psrm, clock_offset, _)) = found
            .iter()
            .find(|(_, _, _, name)| name.as_deref() == Some(expected.as_str()))
        else {
            return Err(format!("no device named {expected:?} answered"));
        };

        let request = RemoteNameRequest::new(bd_addr, psrm, 0, clock_offset);
        hci.exec(&request).await.map_err(fail)?;
        loop {
            match rx.recv().await {
                Some(Report::RemoteName { status, name }) => {
                    println!(
                        "   remote name of {}: {name:?} ({status:?})",
                        addr(&bd_addr)
                    );
                    if name != expected {
                        return Err(format!("remote name {name:?}, expected {expected:?}"));
                    }
                    println!("   found {expected:?}");
                    return Ok(());
                }
                Some(_) => {}
                None => return Err(String::from("event loop ended")),
            }
        }
    };

    let result = tokio::select! {
        result = scan => result,
        result = events => result,
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
    Ok(())
}

fn print_result(bd_addr: &BdAddr, class_of_device: [u8; 3], rssi: i8, eir: &[u8]) {
    println!(
        "   found {} {:?}, class 0x{:06x}, RSSI {rssi} dBm",
        addr(bd_addr),
        gap::eir_name(eir).unwrap_or("<no name>"),
        ClassOfDevice(class_of_device).value(),
    );
    for (data_type, data) in gap::eir_structures(eir) {
        match data_type {
            eir_type::UUID16_COMPLETE | eir_type::UUID16_INCOMPLETE => {
                for uuid in data.as_chunks::<2>().0 {
                    println!("     service 0x{:04x}", u16::from_le_bytes(*uuid));
                }
            }
            eir_type::UUID128_COMPLETE | eir_type::UUID128_INCOMPLETE => {
                for uuid in data.as_chunks::<16>().0 {
                    let value = u128::from_le_bytes(*uuid);
                    println!("     service {}", uuid128(value));
                }
            }
            _ => {}
        }
    }
}

/// `4de17a00-52cb-11e6-bdf4-0800200c9a66`.
fn uuid128(value: u128) -> String {
    let hex = format!("{value:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}
