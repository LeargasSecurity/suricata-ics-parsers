#!/usr/bin/env python3
# Regression pcap generator for the shared TPKT/COTP (TCP/102) code
# Copyright (C) 2026 Leargas Security
# License: GPL-2.0
"""Derive TCP/102 regression pcaps from tests/s7comm-write-var/input.pcap.

Pure standard library (no scapy). TCP/IP checksums are not recomputed; the
tests run Suricata with `-k none`.

    scripts/gen-iso102-regress-pcaps.py [SRC_PCAP] [TESTS_DIR]

Writes:
  s7comm-split-pdu/input.pcap   first S7 Job PDU split 3/4 + 1/4 across two
                                segments, with a server ACK in between
  iso102-not-s7comm/input.pcap  every COTP DT payload starting with the S7
                                protocol id (0x32) rewritten to an ISO 8327
                                session SPDU id (0x0D, CONNECT), as in MMS/ICCP
"""

import os
import struct
import sys

S7_PROTOCOL_ID = 0x32
ISO_SESSION_CN = 0x0D
COTP_DT = 0xF0


def read_pcap(path):
    data = open(path, "rb").read()
    header = data[:24]
    if struct.unpack("<I", header[:4])[0] != 0xA1B2C3D4:
        sys.exit("expected a little-endian classic pcap")
    if struct.unpack("<I", header[20:24])[0] != 1:
        sys.exit("expected Ethernet link type")
    packets, off = [], 24
    while off < len(data):
        ts, tu, caplen, _ = struct.unpack("<IIII", data[off:off + 16])
        packets.append((ts, tu, data[off + 16:off + 16 + caplen]))
        off += 16 + caplen
    return header, packets


def write_pcap(path, header, packets):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(header)
        for ts, tu, frame in packets:
            f.write(struct.pack("<IIII", ts, tu, len(frame), len(frame)) + frame)


def tcp_offsets(frame):
    """Return (tcp header offset, tcp header length) for an Ethernet/IPv4 frame."""
    tcp = 14 + (frame[14] & 0x0F) * 4
    return tcp, (frame[tcp + 12] >> 4) * 4


def with_payload(frame, payload, seq_add=0, flags=None):
    tcp, tcp_len = tcp_offsets(frame)
    hdr = bytearray(frame[:tcp + tcp_len])
    struct.pack_into(">H", hdr, 16, len(hdr) - 14 + len(payload))
    seq = struct.unpack(">I", hdr[tcp + 4:tcp + 8])[0]
    struct.pack_into(">I", hdr, tcp + 4, (seq + seq_add) & 0xFFFFFFFF)
    if flags is not None:
        hdr[tcp + 13] = flags
    return bytes(hdr) + payload


def server_ack(frame, acked):
    """Pure ACK from the server acknowledging `acked` bytes of client `frame`."""
    tcp, _ = tcp_offsets(frame)
    ack = bytearray(with_payload(frame, b"", flags=0x10))
    ack[26:30], ack[30:34] = frame[30:34], frame[26:30]
    ack[tcp:tcp + 2], ack[tcp + 2:tcp + 4] = frame[tcp + 2:tcp + 4], frame[tcp:tcp + 2]
    seq, ack_no = struct.unpack(">II", frame[tcp + 4:tcp + 12])
    struct.pack_into(">II", ack, tcp + 4, ack_no, (seq + acked) & 0xFFFFFFFF)
    return bytes(ack)


def is_s7_dt(payload):
    # TPKT(4) + COTP DT (LI=2: type, EOT/nr) + S7 header
    return (len(payload) > 7 and payload[0] == 0x03 and payload[4] == 0x02
            and (payload[5] & 0xF0) == COTP_DT and payload[7] == S7_PROTOCOL_ID)


def split_pdu(packets):
    out, done = [], False
    for ts, tu, frame in packets:
        tcp, tcp_len = tcp_offsets(frame)
        payload = frame[tcp + tcp_len:]
        dport = struct.unpack(">H", frame[tcp + 2:tcp + 4])[0]
        # First S7 Job (ROSCTR 1) after Setup Communication (function 0xF0)
        if (not done and dport == 102 and is_s7_dt(payload) and payload[8] == 0x01
                and payload[17] != 0xF0):
            # More than half in the first piece: the case the old
            # "bytes still missing" incomplete() result turned into a parser error.
            cut = len(payload) * 3 // 4
            out.append((ts, tu, with_payload(frame, payload[:cut])))
            out.append((ts, tu + 1, server_ack(frame, cut)))
            out.append((ts, tu + 2, with_payload(frame, payload[cut:], seq_add=cut)))
            done = True
        else:
            out.append((ts, tu, frame))
    if not done:
        sys.exit("no S7 Job PDU found to split")
    return out


def not_s7(packets):
    out = []
    for ts, tu, frame in packets:
        tcp, tcp_len = tcp_offsets(frame)
        payload = bytearray(frame[tcp + tcp_len:])
        if is_s7_dt(payload):
            payload[7] = ISO_SESSION_CN
        out.append((ts, tu, with_payload(frame, bytes(payload))))
    return out


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        root, "tests", "s7comm-write-var", "input.pcap")
    tests = sys.argv[2] if len(sys.argv) > 2 else os.path.join(root, "tests")
    header, packets = read_pcap(src)
    for name, fn in (("s7comm-split-pdu", split_pdu), ("iso102-not-s7comm", not_s7)):
        path = os.path.join(tests, name, "input.pcap")
        write_pcap(path, header, fn(packets))
        print("wrote", path)


if __name__ == "__main__":
    main()
