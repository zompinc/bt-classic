//! Brings a controller up as a discoverable, connectable classic device that
//! accepts connections and pairs (Just Works), and prints what happens until
//! stopped.
//!
//! ```sh
//! cargo run --example discoverable -- --name bt-classic --keys target/discoverable-keys.txt
//! ```
//!
//! It advertises an HSP headset and the wireless Android Auto service in its
//! EIR, as the dongle will. With `--keys FILE`, link keys are kept in that
//! file, so bonded devices reconnect without pairing after a restart.

mod common;

use bt_classic::gap::{self, ClassOfDevice, audio_video, major, service};
use bt_classic::host;
use bt_classic::security::{Security, SecurityConfig};
use common::pairing::{Console, KeyFile};
use common::{Options, addr};
use tokio::sync::mpsc;

/// HSP headset role.
const HSP_HS: u16 = 0x1108;
/// Wireless Android Auto's RFCOMM service.
const ANDROID_AUTO: u128 = 0x4de17a00_52cb_11e6_bdf4_0800200c9a66;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse("discoverable [--name NAME] [--keys FILE] [--no-sc]");
    let name = options.value("--name").unwrap_or("bt-classic").to_owned();
    let mut keys = KeyFile::open(options.value("--keys"))?;
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
        secure_connections: !options.rest.iter().any(|a| a == "--no-sc"),
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

    // Progress is printed by the console; nothing here waits for it.
    let (tx, _rx) = mpsc::unbounded_channel();
    let mut console = Console { tx };
    let mut security = Security::new(SecurityConfig::default());
    let runner = host::run(&hci, &mut security, &mut keys, &mut console);

    tokio::select! {
        result = device => result?,
        error = runner => return Err(format!("controller failed: {error:?}").into()),
    }
    Ok(())
}
