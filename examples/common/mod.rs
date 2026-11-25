//! What the PC examples share: arguments, connecting to an H4-over-TCP
//! controller with tracing, and reading events.

#![allow(dead_code)] // Not every example uses every helper.

pub mod pairing;

use std::fs::File;
use std::io::Write as _;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use bt_classic::trace::{Direction, Sink, Traced, btsnoop};
use bt_classic::transport::SplitAcl;
use bt_hci::ControllerToHostPacket;
use bt_hci::controller::{Controller, ExternalController};
use bt_hci::event::Event;
use bt_hci::param::BdAddr;
use bt_hci_serial::SerialTransport;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embedded_io_adapters::tokio_1::FromTokio;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

type Reader = Traced<'static, FromTokio<OwnedReadHalf>, Tracer>;
type Writer = Traced<'static, FromTokio<OwnedWriteHalf>, Tracer>;

/// A controller reached over TCP, with every packet traced, and ACL packets
/// split to fit bt-hci's read buffer.
pub type Hci = ExternalController<SplitAcl<SerialTransport<NoopRawMutex, Reader, Writer>>, 4>;

/// Options every example takes; the rest are left in `rest`.
pub struct Options {
    /// `HOST:PORT` of the controller, rootcanal's HCI port by default.
    pub address: String,
    /// `--btsnoop FILE`: also write a capture.
    pub btsnoop: Option<String>,
    /// `--quiet`: do not print packets.
    pub quiet: bool,
    /// Everything else, in order.
    pub rest: Vec<String>,
}

impl Options {
    /// Parses the process arguments, exiting with `usage` on `--help`.
    pub fn parse(usage: &str) -> Self {
        let mut options = Self {
            address: String::from("127.0.0.1:6402"),
            btsnoop: None,
            quiet: false,
            rest: Vec::new(),
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--btsnoop" => {
                    options.btsnoop = Some(args.next().unwrap_or_else(|| exit_usage(usage)))
                }
                "--quiet" => options.quiet = true,
                "-h" | "--help" => exit_usage(usage),
                _ if !arg.starts_with('-') && options.rest.is_empty() && arg.contains(':') => {
                    options.address = arg
                }
                _ => options.rest.push(arg),
            }
        }
        options
    }

    /// The value after `flag` in `rest`, if present.
    pub fn value(&self, flag: &str) -> Option<&str> {
        let i = self.rest.iter().position(|a| a == flag)?;
        self.rest.get(i + 1).map(String::as_str)
    }
}

pub fn exit_usage(usage: &str) -> ! {
    eprintln!("usage: {usage}");
    eprintln!("common options: [HOST:PORT] [--btsnoop FILE] [--quiet]");
    std::process::exit(2);
}

/// Prints each packet and, optionally, appends it to a btsnoop capture.
pub struct Tracer {
    quiet: bool,
    capture: Option<Mutex<File>>,
}

impl Tracer {
    fn new(path: Option<&str>, quiet: bool) -> std::io::Result<Self> {
        let capture = match path {
            Some(path) => {
                let mut file = File::create(path)?;
                file.write_all(&btsnoop::FILE_HEADER)?;
                Some(Mutex::new(file))
            }
            None => None,
        };
        Ok(Self { quiet, capture })
    }
}

impl Sink for Tracer {
    fn packet(&self, direction: Direction, packet: &[u8], original_len: usize) {
        if !self.quiet {
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
        }

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

/// Connects to the controller at `options.address`.
pub async fn connect(options: &Options) -> std::io::Result<Hci> {
    let stream = TcpStream::connect(&options.address).await?;
    stream.set_nodelay(true)?;
    println!("connected to {}", options.address);
    let (reader, writer) = stream.into_split();

    // The examples run until they exit, so the tracer can live forever.
    let tracer: &'static Tracer = Box::leak(Box::new(Tracer::new(
        options.btsnoop.as_deref(),
        options.quiet,
    )?));
    let reader = Traced::new(FromTokio::new(reader), Direction::ControllerToHost, tracer);
    let writer = Traced::new(FromTokio::new(writer), Direction::HostToController, tracer);
    Ok(ExternalController::new(SplitAcl::new(
        SerialTransport::new(reader, writer),
    )))
}

/// Reads events until `handle` returns `Some`, and returns that.
///
/// Command completions are consumed by the controller on the way, so this
/// must run for commands to complete.
pub async fn events<T>(
    hci: &Hci,
    mut handle: impl FnMut(&Event<'_>) -> Option<T>,
) -> Result<T, String> {
    let mut buf = [0u8; 259];
    loop {
        match hci.read(&mut buf).await {
            Ok(ControllerToHostPacket::Event(packet)) => match Event::try_from(packet) {
                Ok(event) => {
                    if let Some(done) = handle(&event) {
                        return Ok(done);
                    }
                }
                Err(e) => eprintln!("   unparsed event: {e:?}"),
            },
            Ok(_) => {}
            Err(e) => return Err(format!("controller read failed: {e:?}")),
        }
    }
}

/// `AA:BB:CC:DD:EE:FF`, most significant byte first.
pub fn addr(address: &BdAddr) -> String {
    let b = address.raw();
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        b[5], b[4], b[3], b[2], b[1], b[0]
    )
}
