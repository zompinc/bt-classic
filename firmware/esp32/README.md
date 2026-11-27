# bt-classic on the ESP32

bt-classic running on an original ESP32 with the chip's own Bluetooth controller, through esp-radio. It does what the PC `discoverable` example does: discoverable as `bt-classic`, pairs Just Works, serves the Android Auto (RFCOMM 8) and HSP headset (RFCOMM 6) records, and echoes RFCOMM data.

Checked on an ESP32-DevKitC (ESP32-D0WD-V3) with an Android phone: it pairs with a P-256 key, encrypts, connects the headset profile, and Android Auto opens channel 8.

## Build and flash

esp-hal's `main` branch needs the Xtensa toolchain 1.100 or later (`espup install`).

```sh
cd firmware/esp32
cargo run --release        # builds, flashes with espflash and opens the monitor
```

## Keep interrupt latency low

esp-radio's default controller configuration handles BR/EDR on the ESP32, but BR/EDR links do not survive long interrupt latency. esp-log writes each log line to the UART with interrupts disabled, about 10 ms per line at 115200 baud. Log lines while a link comes up make the link time out (HCI reason 0x08). For that reason `.cargo/config.toml` sets `ESP_LOG = "warn"`.
