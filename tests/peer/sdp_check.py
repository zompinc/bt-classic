"""SDP check with Google Bumble as the client.

Finds a device by name with an inquiry, connects over BR/EDR, and checks its
SDP records the way a phone reads them: the wireless Android Auto service on
RFCOMM channel 8 and an HSP headset on channel 6. Exits 1 on any mismatch.

    python tests/peer/sdp_check.py [TRANSPORT] [NAME]

TRANSPORT defaults to rootcanal's HCI port, tcp-client:127.0.0.1:6402, and
NAME to bt-classic. Needs bumble (pip install bumble==0.0.236).
"""

import asyncio
import sys

from bumble import sdp
from bumble.core import BT_BR_EDR_TRANSPORT, UUID
from bumble.device import Device
from bumble.transport import open_transport

ANDROID_AUTO = UUID("4de17a00-52cb-11e6-bdf4-0800200c9a66")
HEADSET = UUID.from_16_bits(0x1108)
GENERIC_AUDIO = UUID.from_16_bits(0x1203)
PUBLIC_BROWSE_ROOT = UUID.from_16_bits(0x1002)
RFCOMM = UUID.from_16_bits(0x0003)


def same_uuid(a, b):
    return a.to_bytes(force_128=True) == b.to_bytes(force_128=True)


def attribute(attributes, attribute_id):
    for a in attributes:
        if a.id == attribute_id:
            return a.value
    raise AssertionError(f"attribute 0x{attribute_id:04x} missing")


def uuids(element):
    return [e.value for e in element.value]


def rfcomm_channel(attributes):
    for protocol in attribute(attributes, 0x0004).value:
        items = protocol.value
        if same_uuid(items[0].value, RFCOMM):
            return items[1].value
    raise AssertionError("no RFCOMM in the protocol descriptor list")


def name(attributes):
    value = attribute(attributes, 0x0100).value
    return value.decode() if isinstance(value, bytes) else value


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


async def main(transport, wanted):
    async with await open_transport(transport) as (source, sink):
        device = Device.with_hci("bumble-sdp", "F0:F1:F2:F3:F4:F6", source, sink)
        device.classic_enabled = True
        await device.power_on()

        address = await find(device, wanted)
        print(f"   found {wanted} at {address}")
        connection = await device.connect(address, transport=BT_BR_EDR_TRANSPORT)

        # Bumble's default MTU fits every answer in one response; the
        # 48-byte minimum makes the server split them with continuation.
        for mtu in (0, 48):
            print(f"   SDP with {'the default MTU' if mtu == 0 else f'MTU {mtu}'}")
            await check_records(connection, mtu)

        await connection.disconnect()
        print("   SDP check passed")


async def check_records(connection, mtu):
    async with sdp.Client(connection, mtu=mtu) as client:
        handles = await client.search_services([ANDROID_AUTO])
        check(len(handles) == 1, f"one Android Auto record ({handles})")

        [aa] = await client.search_attributes([ANDROID_AUTO], [sdp.SDP_ALL_ATTRIBUTES_RANGE])
        check(
            any(same_uuid(u, ANDROID_AUTO) for u in uuids(attribute(aa, 0x0001))),
            "Android Auto class UUID",
        )
        check(rfcomm_channel(aa) == 8, f"Android Auto on RFCOMM channel {rfcomm_channel(aa)}")
        check(name(aa) == "AA Wireless", f"Android Auto record named {name(aa)!r}")

        [hsp] = await client.search_attributes([HEADSET], [sdp.SDP_ALL_ATTRIBUTES_RANGE])
        classes = uuids(attribute(hsp, 0x0001))
        check(
            same_uuid(classes[0], HEADSET) and same_uuid(classes[1], GENERIC_AUDIO),
            "Headset and Generic Audio classes",
        )
        check(rfcomm_channel(hsp) == 6, f"Headset on RFCOMM channel {rfcomm_channel(hsp)}")
        [profile] = attribute(hsp, 0x0009).value
        version = profile.value[1].value
        check(version == 0x0102, f"HSP version 0x{version:04x}")

        browsable = await client.search_services([PUBLIC_BROWSE_ROOT])
        check(len(browsable) == 2, f"both records in the public browse group ({browsable})")

        [handle] = handles
        selected = await client.get_attributes(handle, [0x0004, 0x0100])
        check([a.id for a in selected] == [0x0004, 0x0100], "attribute selection by ID")


if __name__ == "__main__":
    args = sys.argv[1:]
    transport = args[0] if args else "tcp-client:127.0.0.1:6402"
    wanted = args[1] if len(args) > 1 else "bt-classic"
    try:
        asyncio.run(main(transport, wanted))
    except Exception as error:  # noqa: BLE001 - any failure fails the check
        print(f"SDP check failed: {error!r}")
        sys.exit(1)
