//! bt-classic on an original ESP32, with the controller in the same chip
//! through esp-radio: discoverable and connectable as `bt-classic`, pairs
//! (Just Works), serves the Android Auto (RFCOMM 8) and HSP headset (RFCOMM
//! 6) records and echoes RFCOMM data, like the PC `discoverable` example.
//!
//! esp-radio's default controller configuration already handles BR/EDR on
//! the ESP32. What it needs is short interrupt latency: see the `ESP_LOG`
//! note in `.cargo/config.toml`. Link keys live in RAM, so a reset forgets
//! bonds.

#![no_std]
#![no_main]

use bt_classic::gap::{self, ClassOfDevice, ControllerInfo, audio_video, major, service};
use bt_classic::host::{self, Handler, RfcommTx, Stack};
use bt_classic::l2cap::ChannelEvent;
use bt_classic::rfcomm::Dlc;
use bt_classic::rfcomm_service_record;
use bt_classic::sdp::{Attribute, DataElement, ServiceRecord, attribute, uuid};
use bt_classic::security::{MemoryKeyStore, Notice, SecurityConfig};
use bt_classic::transport::SplitAcl;
use bt_hci::controller::ExternalController;
use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::clock::{ClockConfig, CpuClock};
use esp_hal::timer::timg::TimerGroup;
use esp_radio::ble::controller::BleConnector;
use log::{info, warn};

esp_bootloader_esp_idf::esp_app_desc!();

/// Wireless Android Auto's RFCOMM service.
const ANDROID_AUTO: u128 = 0x4de17a00_52cb_11e6_bdf4_0800200c9a66;

static AA_WIRELESS: ServiceRecord<'static> = rfcomm_service_record!(
    handle: 0x0001_0001,
    classes: [DataElement::Uuid128(ANDROID_AUTO)],
    channel: 8,
    name: "AA Wireless",
);

static HSP_HS: ServiceRecord<'static> = rfcomm_service_record!(
    handle: 0x0001_0002,
    classes: [DataElement::Uuid16(uuid::HEADSET), DataElement::Uuid16(uuid::GENERIC_AUDIO)],
    channel: 6,
    name: "Headset",
    profiles: [DataElement::Sequence(&[DataElement::Uuid16(uuid::HEADSET), DataElement::U16(0x0102)])],
    extra: [Attribute { id: attribute::REMOTE_AUDIO_VOLUME_CONTROL, value: DataElement::Bool(false) }],
);

static RECORDS: [ServiceRecord<'static>; 2] = [AA_WIRELESS, HSP_HS];

/// Logs progress and echoes RFCOMM data.
struct Echo;

impl Handler for Echo {
    fn ready(&mut self, info: &ControllerInfo) {
        info!(
            "ready at {:02X?}, ACL buffers {} x {} bytes",
            info.bd_addr.raw(),
            info.total_num_acl_data_packets,
            info.acl_data_packet_length
        );
    }

    fn channel(&mut self, event: ChannelEvent) {
        info!("L2CAP {event:?}");
    }

    fn events_dropped(&mut self, count: u32) {
        warn!("{count} event(s) dropped");
    }

    fn notice(&mut self, notice: Notice) {
        info!("{notice:?}");
    }

    fn rfcomm_opened(&mut self, dlc: Dlc, _tx: &mut RfcommTx<'_>) {
        info!("RFCOMM channel {} opened", dlc.channel());
    }

    fn rfcomm_data(&mut self, dlc: Dlc, data: &[u8], tx: &mut RfcommTx<'_>) {
        info!("RFCOMM channel {}: {} byte(s)", dlc.channel(), data.len());
        if let Err(e) = tx.send(dlc, data) {
            warn!("echo dropped: {e:?}");
        }
    }

    fn rfcomm_closed(&mut self, dlc: Dlc) {
        info!("RFCOMM channel {} closed", dlc.channel());
    }
}

#[esp_hal::main]
async fn main(_spawner: Spawner) {
    let peripherals =
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(ClockConfig::from(CpuClock::max())));
    esp_log::init_uart!(peripherals);
    esp_alloc::heap_allocator!(size: 72 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0);

    let connector = BleConnector::new(
        peripherals.BT,
        esp_radio::ble::Config::default(),
    )
    .unwrap();
    // A BR/EDR ACL packet is up to 1021 bytes plus headers.
    let split: SplitAcl<_, 1028> = SplitAcl::new(connector);
    let hci: ExternalController<_, 4> = ExternalController::new(split);

    let config = gap::Config {
        name: "bt-classic",
        class_of_device: ClassOfDevice::new(
            service::AUDIO,
            major::AUDIO_VIDEO,
            audio_video::WEARABLE_HEADSET,
        ),
        uuid16: &[uuid::HEADSET],
        uuid128: &[ANDROID_AUTO],
        discoverable: true,
        connectable: true,
        secure_connections: true,
    };

    let mut stack = Stack::new(
        SecurityConfig::default(),
        &RECORDS,
        MemoryKeyStore::<4>::new(),
    );
    stack.rfcomm.register(8);
    stack.rfcomm.register(6);

    info!("starting bt-classic");
    let heartbeat = async {
        let mut minutes = 0u32;
        loop {
            Timer::after(Duration::from_secs(60)).await;
            minutes += 1;
            info!("alive, {minutes} min");
        }
    };
    let mut handler = Echo;
    let run = host::run(&hci, &mut stack, &config, &mut handler);
    // The heartbeat never ends, so only the runner can finish the select.
    let embassy_futures::select::Either::First(error) =
        embassy_futures::select::select(run, heartbeat).await;
    panic!("controller failed: {error:?}");
}
