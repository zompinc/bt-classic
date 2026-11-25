//! Brings a controller up as a discoverable, connectable classic device and
//! prints the events it gets until stopped.
//!
//! ```sh
//! cargo run --example discoverable -- --name bt-classic
//! ```
//!
//! It advertises an HSP headset and the wireless Android Auto service in its
//! EIR, as the dongle will. Connections are not accepted yet.

mod common;

use bt_classic::gap::{self, ClassOfDevice, audio_video, major, service};
use bt_hci::event::Event;
use common::{Options, addr};

/// HSP headset role.
const HSP_HS: u16 = 0x1108;
/// Wireless Android Auto's RFCOMM service.
const ANDROID_AUTO: u128 = 0x4de17a00_52cb_11e6_bdf4_0800200c9a66;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse("discoverable [--name NAME]");
    let name = options.value("--name").unwrap_or("bt-classic").to_owned();
    let hci = common::connect(&options).await?;

    let config = gap::Config {
        name: &name,
        class_of_device: ClassOfDevice::new(
            service::AUDIO,
            major::AUDIO_VIDEO,
            audio_video::WEARABLE_HEADSET,
        ),
        uuid16: &[HSP_HS],
        uuid128: &[ANDROID_AUTO],
        discoverable: true,
        connectable: true,
    };

    let device = async {
        let info = gap::bring_up(&hci, &config)
            .await
            .map_err(|e| format!("bring-up failed: {e:?}"))?;
        println!(
            "   discoverable as {name:?} at {}, ACL buffers {} x {} bytes",
            addr(&info.bd_addr),
            info.total_num_acl_data_packets,
            info.acl_data_packet_length,
        );
        std::future::pending::<Result<(), String>>().await
    };

    let events = common::events(&hci, |event| {
        match event {
            Event::ConnectionRequest(e) => println!(
                "   connection request from {}, class 0x{:06x} (not accepted yet)",
                addr(&e.bd_addr),
                ClassOfDevice(e.class_of_device).value(),
            ),
            other => println!("   event {other:?}"),
        }
        None::<()>
    });

    tokio::select! {
        result = device => result?,
        result = events => result?,
    }
    Ok(())
}
