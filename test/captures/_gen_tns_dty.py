#!/usr/bin/env python3
"""Generate test/captures/tns_dty.pcap — a TTI_DTY (Set Datatypes) request.

The TTI_DTY body is built by pyoracle's encode_dictionary_dty(), wrapped in
the 10-byte TNS DATA framing, and emitted as a single TCP segment to port
1521 inside an IPv4 datagram (LINKTYPE_RAW, no Ethernet header).

This gives the dissector a deterministic, license-clean fixture for the
SQLNET_SET_DATATYPES decoder without needing a live Oracle capture.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..",
                                "pyoracle"))
from oracle.tns import encode_dictionary_dty  # noqa: E402

TTI_DTY_BODY = encode_dictionary_dty({"req": "us7ascii"})

# TNS DATA framing (matches pyoracle.encode_packet for Type=TNS_DATA=6).
tns_packet = struct.pack(">HhBBhh", len(TTI_DTY_BODY) + 10, 0, 6, 0, 0, 0) + TTI_DTY_BODY


def ipv4_checksum(header: bytes) -> int:
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) | header[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def tcp_checksum(src: bytes, dst: bytes, tcp_hdr_plus_data: bytes) -> int:
    pseudo = src + dst + b"\x00\x06" + struct.pack(">H", len(tcp_hdr_plus_data))
    buf = pseudo + tcp_hdr_plus_data
    if len(buf) % 2:
        buf += b"\x00"
    s = 0
    for i in range(0, len(buf), 2):
        s += (buf[i] << 8) | buf[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


src_ip = bytes([127, 0, 0, 1])
dst_ip = bytes([127, 0, 0, 1])
src_port = 54321
dst_port = 1521

# TCP header: src_port, dst_port, seq, ack, dataofs/flags, win, csum, urg.
tcp_no_csum = struct.pack(
    ">HHIIBBHHH",
    src_port, dst_port,
    1,            # seq
    0,            # ack
    0x50,         # data offset = 5 (20 bytes), no reserved bits
    0x18,         # flags: PSH|ACK
    65535,        # window
    0,            # checksum (computed below)
    0,            # urgent
)
csum = tcp_checksum(src_ip, dst_ip, tcp_no_csum + tns_packet)
tcp_hdr = tcp_no_csum[:16] + struct.pack(">H", csum) + tcp_no_csum[18:]
tcp_segment = tcp_hdr + tns_packet

ip_total_len = 20 + len(tcp_segment)
ip_no_csum = struct.pack(
    ">BBHHHBBH",
    0x45,         # version+ihl
    0,            # tos
    ip_total_len,
    1,            # id
    0x4000,       # flags=DF, frag=0
    64,           # ttl
    6,            # proto = TCP
    0,            # checksum
) + src_ip + dst_ip
ip_csum = ipv4_checksum(ip_no_csum)
ip_hdr = ip_no_csum[:10] + struct.pack(">H", ip_csum) + ip_no_csum[12:]
ip_packet = ip_hdr + tcp_segment

# pcap global header — LINKTYPE_RAW = 101 (IPv4-only payload).
pcap_hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
pkt_hdr = struct.pack("<IIII", 0, 0, len(ip_packet), len(ip_packet))

out = os.path.join(os.path.dirname(__file__), "tns_dty.pcap")
with open(out, "wb") as f:
    f.write(pcap_hdr + pkt_hdr + ip_packet)
print(f"wrote {out} ({os.path.getsize(out)} bytes)")
