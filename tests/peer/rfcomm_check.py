"""RFCOMM check with Google Bumble playing the phone.

Finds a device by name, connects over BR/EDR, pairs and encrypts, looks up
the wireless Android Auto service's RFCOMM channel with SDP, opens it and
checks that what it sends comes back unchanged (the `discoverable` example
echoes). Payloads grow past one frame and past the device's transmit buffer,
so framing, credits and L2CAP fragmentation all get exercised. Also opens
the headset channel and checks that an unregistered channel is refused.
Exits 1 on any mismatch.

    python tests/peer/rfcomm_check.py [TRANSPORT] [NAME]

TRANSPORT defaults to rootcanal's HCI port, tcp-client:127.0.0.1:6402, and
NAME to bt-classic. Needs bumble (pip install bumble==0.0.236).
"""

import asyncio
import sys

from bumble import rfcomm
from bumble.core import BT_BR_EDR_TRANSPORT
from bumble.device import Device
from bumble.transport import open_transport

ANDROID_AUTO = "4de17a00-52cb-11e6-bdf4-0800200c9a66"
HEADSET = "00001108-0000-1000-8000-00805f9b34fb"


def check(condition, what):
    print(("   ok   " if condition else "   FAIL ") + what)
    if not condition:
        raise AssertionError(what)


async def find(device, wanted):
    found = asyncio.get_running_loop().create_future()

    def on_result(address, class_of_device, data, rssi):
        if wanted in str(data) and not found.done():
            found.set_result(address)

    device.on("inquiry_result", on_result)
    await device.start_discovery()
    try:
        return await asyncio.wait_for(found, 15)
    finally:
        await device.stop_discovery()


async def echo(dlc, payload):
    """Sends `payload` and waits until as many bytes came back."""
    received = bytearray()
    done = asyncio.Event()

    def on_data(data):
        received.extend(data)
        if len(received) >= len(payload):
            done.set()

    dlc.sink = on_data
    dlc.write(payload)
    await asyncio.wait_for(done.wait(), 20)
    return bytes(received)


async def main(transport, wanted):
    async with await open_transport(transport) as (source, sink):
        device = Device.with_hci("bumble-phone", "F0:F1:F2:F3:F4:F7", source, sink)
        device.classic_enabled = True
        await device.power_on()

        address = await find(device, wanted)
        print(f"   found {wanted} at {address}")
        connection = await device.connect(address, transport=BT_BR_EDR_TRANSPORT)

        # A phone pairs and encrypts before it opens RFCOMM.
        await connection.authenticate()
        await connection.encrypt()
        check(connection.is_encrypted, "link encrypted")

        channel = await rfcomm.find_rfcomm_channel_with_uuid(connection, ANDROID_AUTO)
        check(channel == 8, f"Android Auto found on RFCOMM channel {channel} via SDP")

        async with rfcomm.Client(connection) as mux:
            dlc = await mux.open_dlc(channel)
            print(f"   opened channel {channel}: {dlc}")

            pattern = bytes(i % 251 for i in range(5000))
            for size in (5, 300, 1000, 5000):
                payload = pattern[:size]
                back = await echo(dlc, payload)
                check(back == payload, f"{size}-byte echo intact")

            headset = await rfcomm.find_rfcomm_channel_with_uuid(connection, HEADSET)
            check(headset == 6, f"Headset found on RFCOMM channel {headset} via SDP")
            other = await mux.open_dlc(headset)
            check(await echo(other, b"AT+CKPD=200\r") == b"AT+CKPD=200\r", "headset channel echoes")
            await other.disconnect()

            try:
                await asyncio.wait_for(mux.open_dlc(5), 10)
                refused = False
            except Exception:  # noqa: BLE001 - any refusal will do
                refused = True
            check(refused, "unregistered channel 5 refused")

            await dlc.disconnect()

        await connection.disconnect()
        print("   RFCOMM check passed")


if __name__ == "__main__":
    args = sys.argv[1:]
    transport = args[0] if args else "tcp-client:127.0.0.1:6402"
    wanted = args[1] if len(args) > 1 else "bt-classic"
    try:
        asyncio.run(main(transport, wanted))
    except Exception as error:  # noqa: BLE001 - any failure fails the check
        print(f"RFCOMM check failed: {error!r}")
        sys.exit(1)
