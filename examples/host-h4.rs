//! Brings up an HCI controller reachable over TCP and prints what it reports.
//!
//! Point it at rootcanal's HCI port (6402) or any other H4-over-TCP
//! controller:
//!
//! ```sh
//! cargo run --example host-h4 -- 127.0.0.1:6402 --btsnoop target/host-h4.btsnoop
//! ```
//!
//! Every packet is printed as hex; with `--btsnoop` they are also written to
//! a capture that Wireshark opens.

use std::error::Error;
use std::fs::File;
use std::io::Write as _;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use bt_classic::cmd::ReadBufferSize;
use bt_classic::trace::{Direction, Sink, Traced, btsnoop};
use bt_hci::ControllerToHostPacket;
use bt_hci::cmd::SyncCmd;
use bt_hci::cmd::controller_baseband::Reset;
use bt_hci::cmd::info::{ReadBdAddr, ReadLocalSupportedFeatures, ReadLocalVersionInformation};
use bt_hci::controller::{Controller, ExternalController};
use bt_hci_serial::SerialTransport;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embedded_io_adapters::tokio_1::FromTokio;
use tokio::net::TcpStream;

/// Prints each packet and, optionally, appends it to a btsnoop capture.
struct Tracer {
    capture: Option<Mutex<File>>,
}

impl Tracer {
    fn new(path: Option<&str>) -> std::io::Result<Self> {
        let capture = match path {
            Some(path) => {
                let mut file = File::create(path)?;
                file.write_all(&btsnoop::FILE_HEADER)?;
                Some(Mutex::new(file))
            }
            None => None,
        };
        Ok(Self { capture })
    }
}

impl Sink for Tracer {
    fn packet(&self, direction: Direction, packet: &[u8], original_len: usize) {
        let arrow = match direction {
            Direction::HostToController => "->",
            Direction::ControllerToHost => "<-",
        };
        let shown = &packet[..packet.len().min(32)];
        let hex: Vec<String> = shown.iter().map(|b| format!("{b:02x}")).collect();
        let more = if original_len > shown.len() {
            " ..."
        } else {
            ""
        };
        println!("{arrow} {}{more}", hex.join(" "));

        if let Some(capture) = &self.capture {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_micros() as u64);
            let header = btsnoop::record_header(direction, packet, original_len, now);
            let mut file = capture.lock().unwrap();
            let written = file
                .write_all(&header)
                .and_then(|()| file.write_all(packet));
            if let Err(e) = written {
                eprintln!("btsnoop write failed: {e}");
            }
        }
    }
}

fn usage() -> ! {
    eprintln!("usage: host-h4 [HOST:PORT] [--btsnoop FILE]");
    std::process::exit(2);
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut address = String::from("127.0.0.1:6402");
    let mut capture = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--btsnoop" => capture = Some(args.next().unwrap_or_else(|| usage())),
            "-h" | "--help" => usage(),
            _ => address = arg,
        }
    }

    let stream = TcpStream::connect(&address).await?;
    stream.set_nodelay(true)?;
    println!("connected to {address}");
    let (reader, writer) = stream.into_split();

    let tracer = Tracer::new(capture.as_deref())?;
    let reader: Traced<_, _> =
        Traced::new(FromTokio::new(reader), Direction::ControllerToHost, &tracer);
    let writer: Traced<_, _> =
        Traced::new(FromTokio::new(writer), Direction::HostToController, &tracer);
    let transport: SerialTransport<NoopRawMutex, _, _> = SerialTransport::new(reader, writer);
    let controller: ExternalController<_, 4> = ExternalController::new(transport);

    // Command completions only arrive while something reads, so the event
    // loop runs alongside the bring-up sequence.
    let events = async {
        let mut buf = [0u8; 259];
        loop {
            match controller.read(&mut buf).await {
                Ok(ControllerToHostPacket::Event(event)) => println!("   event {:?}", event.kind),
                Ok(_) => {}
                Err(e) => return e,
            }
        }
    };

    let bring_up = async {
        Reset::new().exec(&controller).await?;

        let version = ReadLocalVersionInformation::new().exec(&controller).await?;
        println!(
            "   HCI version {:?}, LMP version {:?}, company 0x{:04x}",
            version.hci_version,
            version.lmp_version,
            { version.company_identifier },
        );

        let address = ReadBdAddr::new().exec(&controller).await?;
        let bytes = address.raw();
        println!(
            "   BD_ADDR {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bytes[5], bytes[4], bytes[3], bytes[2], bytes[1], bytes[0],
        );

        let features = ReadLocalSupportedFeatures::new().exec(&controller).await?;
        println!(
            "   BR/EDR {}, Secure Simple Pairing {}, LE {}",
            yes_no(!features.supports_br_edr_not()),
            yes_no(features.supports_secure_simple_pairing()),
            yes_no(features.supports_le()),
        );

        let buffers = ReadBufferSize::new().exec(&controller).await?;
        println!(
            "   ACL buffers {} x {} bytes, SCO buffers {} x {} bytes",
            { buffers.total_num_acl_data_packets },
            { buffers.acl_data_packet_length },
            { buffers.total_num_synchronous_data_packets },
            buffers.synchronous_data_packet_length,
        );
        Ok::<_, bt_hci::cmd::Error<_>>(())
    };

    tokio::select! {
        result = bring_up => result.map_err(|e| format!("bring-up failed: {e:?}"))?,
        error = events => return Err(format!("controller read failed: {error:?}").into()),
    }
    println!("controller ready");
    Ok(())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
