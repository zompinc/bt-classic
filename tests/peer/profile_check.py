"""Profile check with Google Bumble playing the phone as a headset audio gateway.

Waits to be found, paired and connected, the way a phone waits for a headset
that connects to it, and serves two SDP records: Serial Port on RFCOMM
channel 2 as a decoy, and the Headset Audio Gateway (0x1112) on channel 3.
Whatever arrives on channel 3 is echoed. Run the `pair` example against it:

    python tests/peer/profile_check.py [TRANSPORT] &
    cargo run --example pair -- --expect bumble-ag --rounds 1 --profile 1112

It exits 0 once the gateway channel has opened and echoed something, and 1
if that has not happened within a minute. TRANSPORT defaults to rootcanal's
HCI port, tcp-client:127.0.0.1:6402. Needs bumble (pip install
bumble==0.0.236).
"""

import asyncio
import sys

from bumble import rfcomm
from bumble.core import UUID
from bumble.device import Device
from bumble.transport import open_transport

HEADSET_AG = UUID.from_16_bits(0x1112)
SERIAL_PORT = UUID.from_16_bits(0x1101)


async def main(transport):
    async with await open_transport(transport) as (source, sink):
        device = Device.with_hci("bumble-ag", "F0:F1:F2:F3:F4:F8", source, sink)
        device.classic_enabled = True

        echoed = asyncio.Event()

        def on_dlc(dlc):
            print(f"   gateway channel opened: {dlc}")

            def on_data(data):
                print(f"   gateway got {bytes(data)!r}, echoing")
                dlc.write(data)
                echoed.set()

            dlc.sink = on_data

        server = rfcomm.Server(device)
        decoy = server.listen(lambda dlc: print(f"   wrong channel opened: {dlc}"), 2)
        gateway = server.listen(on_dlc, 3)
        device.sdp_service_records = {
            0x00010001: rfcomm.make_service_sdp_records(0x00010001, decoy, SERIAL_PORT),
            0x00010002: rfcomm.make_service_sdp_records(0x00010002, gateway, HEADSET_AG),
        }

        await device.power_on()
        await device.set_discoverable(True)
        await device.set_connectable(True)
        print("   bumble-ag waiting")
        await asyncio.wait_for(echoed.wait(), 60)
        # Let the echo go out before the transport closes.
        await asyncio.sleep(2)
        print("   profile check passed")


if __name__ == "__main__":
    args = sys.argv[1:]
    try:
        asyncio.run(main(args[0] if args else "tcp-client:127.0.0.1:6402"))
    except Exception as error:  # noqa: BLE001 - any failure fails the check
        print(f"profile check failed: {error!r}")
        sys.exit(1)
