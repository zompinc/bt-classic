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

mod common;

use bt_classic::cmd::ReadBufferSize;
use bt_hci::cmd::SyncCmd;
use bt_hci::cmd::controller_baseband::Reset;
use bt_hci::cmd::info::{ReadBdAddr, ReadLocalSupportedFeatures, ReadLocalVersionInformation};
use common::{Options, addr};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse("host-h4");
    let controller = common::connect(&options).await?;

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
        println!("   BD_ADDR {}", addr(&address));

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

    // Command completions only arrive while something reads, so the event
    // loop runs alongside the bring-up sequence.
    let events = common::events(&controller, |event| {
        println!("   event {event:?}");
        None::<()>
    });

    tokio::select! {
        result = bring_up => result.map_err(|e| format!("bring-up failed: {e:?}"))?,
        result = events => result?,
    }
    println!("controller ready");
    Ok(())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
