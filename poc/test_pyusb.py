#!/usr/bin/env python3
"""Interract through pyUSB

Debug in Wireshark with: modprobe usbmon
"""
import usb.core
import usb.util
import usb.backend.libusb1


backend = usb.backend.libusb1.get_backend(find_library=lambda x: "/usr/lib/x86_64-linux-gnu/libusb-1.0.so")


# Nano S+
devs = list(usb.core.find(idVendor=0x2c97, idProduct=0x5009, backend=backend))
assert len(devs) == 1
dev = devs[0]

# print("Device:") ; print(dev)

for iface in dev.interfaces():
    if iface.bInterfaceClass != 0xb:
        continue
    eps = iface.endpoints()
    print(f"Found CCID in {iface}: {eps}")
    ep_in = None
    ep_out = None
    for ep in eps:
        if ep.bEndpointAddress & 0x80:
            ep_in = ep
        else:
            ep_out = ep

assert ep_in is not None
assert ep_out is not None

# CCID Packet - PC to Reader: Get Slot Status	
ep_out.write(bytes.fromhex("65000000000000000000"))
result = ep_in.read(256)
print(result)
