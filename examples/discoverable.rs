//! Brings a controller up as a discoverable, connectable classic device that
//! accepts connections, pairs (Just Works), answers SDP queries and echoes
//! RFCOMM data, and prints what happens until stopped.
//!
//! ```sh
//! cargo run --example discoverable -- --name bt-classic --keys target/discoverable-keys.txt
//! ```
//!
//! It advertises and serves the records the dongle needs: the wireless
//! Android Auto service on RFCOMM channel 8 and an HSP headset on channel 6.
//! Both RFCOMM channels echo what they receive. With `--keys FILE`, link
//! keys are kept in that file, so bonded devices reconnect without pairing
//! after a restart.

mod common;

use bt_classic::gap::{self, ClassOfDevice, audio_video, major, service};
use bt_classic::host::{self, Requests, Stack};
use bt_classic::rfcomm_service_record;
use bt_classic::sdp::{Attribute, DataElement, ServiceRecord, attribute, uuid};
use bt_classic::security::SecurityConfig;
use common::Options;
use common::pairing::{Console, KeyFile};
use tokio::sync::mpsc;

/// Wireless Android Auto's RFCOMM service.
const ANDROID_AUTO: u128 = 0x4de17a00_52cb_11e6_bdf4_0800200c9a66;

/// What aa-dongle registers with BlueZ as "AA Wireless", a server on
/// channel 8.
static AA_WIRELESS: ServiceRecord<'static> = rfcomm_service_record!(
    handle: 0x0001_0001,
    classes: [DataElement::Uuid128(ANDROID_AUTO)],
    channel: 8,
    name: "AA Wireless",
);

/// BlueZ's HSP headset (HS) record: Headset and Generic Audio, HSP 1.2.
static HSP_HS: ServiceRecord<'static> = rfcomm_service_record!(
    handle: 0x0001_0002,
    classes: [DataElement::Uuid16(uuid::HEADSET), DataElement::Uuid16(uuid::GENERIC_AUDIO)],
    channel: 6,
    name: "Headset",
    profiles: [DataElement::Sequence(&[DataElement::Uuid16(uuid::HEADSET), DataElement::U16(0x0102)])],
    extra: [Attribute { id: attribute::REMOTE_AUDIO_VOLUME_CONTROL, value: DataElement::Bool(false) }],
);

static RECORDS: [ServiceRecord<'static>; 2] = [AA_WIRELESS, HSP_HS];

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse("discoverable [--name NAME] [--keys FILE] [--no-sc]");
    let name = options.value("--name").unwrap_or("bt-classic").to_owned();
    let keys = KeyFile::open(options.value("--keys"))?;
    let hci = common::connect(&options).await?;

    let config = gap::Config {
        name: &name,
        class_of_device: ClassOfDevice::new(
            service::AUDIO,
            major::AUDIO_VIDEO,
            audio_video::WEARABLE_HEADSET,
        ),
        uuid16: &[uuid::HEADSET],
        uuid128: &[ANDROID_AUTO],
        discoverable: true,
        connectable: true,
        secure_connections: !options.rest.iter().any(|a| a == "--no-sc"),
    };

    // Progress is printed by the console; nothing here waits for it.
    let (tx, _rx) = mpsc::unbounded_channel();
    let mut console = Console {
        tx,
        echo: true,
        greeting: Vec::new(),
    };
    let mut stack = Stack::new(SecurityConfig::default(), &RECORDS, keys);
    stack.rfcomm.register(8);
    stack.rfcomm.register(6);
    let requests = Requests::new();
    let error = host::run(&hci, &mut stack, &config, &mut console, &requests).await;
    Err(format!("controller failed: {error:?}").into())
}
