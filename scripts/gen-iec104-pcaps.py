#!/usr/bin/env python3
# Synthetic IEC 60870-5-104 pcap generator for the iec104 parser and rules
# Copyright (C) 2026 Leargas Security
# License: GPL-2.0
"""Generate IEC 60870-5-104 pcaps that exercise every rule in rules/iec104.rules.

Pure standard library (no scapy). Each pcap contains complete TCP sessions
(handshake, ACKed data, FIN) so Suricata parses them without midstream.

    scripts/gen-iec104-pcaps.py [OUTDIR]     # default: ./iec104-pcaps

Writes one pcap per scenario plus expected-sids.json mapping pcap -> SIDs.
"""

import json
import os
import struct
import sys

MASTER_IP = "10.10.1.10"
RTU_IP = "10.10.1.20"
ROGUE_IP = "10.10.66.6"
PORT = 2404

# --- IEC-104 encoding -------------------------------------------------------


def ioa3(v):
    return struct.pack("<I", v)[:3]


def cp56(ms=0, minute=30, hour=12, day=27, month=10, year=26):
    return struct.pack("<H", ms) + bytes([minute, hour, day, month, year])


def asdu(type_id, cot, ca, objects, sq=False, negative=False, test=False, oa=0):
    """objects: list of (ioa, element_bytes). With sq=True only the first IOA is sent."""
    vsq = (len(objects) & 0x7F) | (0x80 if sq else 0)
    cotb = (cot & 0x3F) | (0x40 if negative else 0) | (0x80 if test else 0)
    hdr = bytes([type_id, vsq, cotb, oa]) + struct.pack("<H", ca)
    if sq:
        return hdr + ioa3(objects[0][0]) + b"".join(e for _, e in objects)
    return hdr + b"".join(ioa3(i) + e for i, e in objects)


def u_frame(cf1):
    return bytes([0x68, 4, cf1, 0, 0, 0])


def s_frame(nr):
    return bytes([0x68, 4, 0x01, 0x00]) + struct.pack("<H", (nr << 1) & 0xFFFF)


def i_frame(ns, nr, body):
    apci = struct.pack("<HH", (ns << 1) & 0xFFFF, (nr << 1) & 0xFFFF)
    return bytes([0x68, len(apci) + len(body)]) + apci + body


STARTDT_ACT, STARTDT_CON = 0x07, 0x0B
STOPDT_ACT, STOPDT_CON = 0x13, 0x23
TESTFR_ACT, TESTFR_CON = 0x43, 0x83

# COT
SPONT, REQ, ACT, ACTCON, DEACT, ACTTERM, FILE, INROGEN = 3, 5, 6, 7, 8, 10, 13, 20
UNK_CA, UNK_IOA = 46, 47


# --- Minimal Ethernet/IPv4/TCP pcap writer ----------------------------------


def _csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _ip(addr):
    return bytes(int(x) for x in addr.split("."))


class Pcap:
    def __init__(self):
        self.records = []
        self.ts = 1793000000.0

    def add(self, frame, gap=0.01):
        self.ts += gap
        self.records.append((self.ts, frame))

    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, frame in self.records:
                sec = int(ts)
                usec = int(round((ts - sec) * 1e6))
                f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
                f.write(frame)


FIN, SYN, RST, PSH, ACK_F = 0x01, 0x02, 0x04, 0x08, 0x10


class TcpSession:
    """One TCP connection; client -> server is the IEC-104 control direction."""

    def __init__(self, pcap, client_ip, client_port, server_ip=RTU_IP, server_port=PORT):
        self.pcap = pcap
        self.c = (client_ip, client_port)
        self.s = (server_ip, server_port)
        self.cseq, self.sseq = 1000, 700000
        self.ip_id = 1
        self._seg(True, SYN, b"", syn=True)
        self._seg(False, SYN | ACK_F, b"", syn=True)
        self._seg(True, ACK_F, b"")

    def _seg(self, from_client, flags, payload, syn=False):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.cseq if from_client else self.sseq
        ack = self.sseq if from_client else self.cseq
        if flags == SYN:
            ack = 0
        tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], seq, ack, 5 << 4, flags, 65535, 0, 0)
        pseudo = _ip(src[0]) + _ip(dst[0]) + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack("!H", _csum(pseudo + tcp + payload)) + tcp[18:]
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), self.ip_id, 0x4000, 64, 6,
            0, _ip(src[0]), _ip(dst[0]),
        )
        ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
        self.ip_id += 1
        client_mac, server_mac = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"
        eth = server_mac + client_mac if from_client else client_mac + server_mac
        self.pcap.add(eth + b"\x08\x00" + ip + tcp + payload)
        advance = len(payload) + (1 if syn or flags & FIN else 0)
        if from_client:
            self.cseq += advance
        else:
            self.sseq += advance

    def send(self, from_client, *apdus):
        """Send APDUs in one segment, then ACK it from the peer."""
        self._seg(from_client, PSH | ACK_F, b"".join(apdus))
        self._seg(not from_client, ACK_F, b"")

    def close(self):
        self._seg(True, FIN | ACK_F, b"")
        self._seg(False, FIN | ACK_F, b"")
        self._seg(True, ACK_F, b"")


class Link:
    """IEC-104 link on top of a TCP session with automatic N(S)/N(R) tracking."""

    def __init__(self, pcap, client_ip=MASTER_IP, client_port=50000):
        self.tcp = TcpSession(pcap, client_ip, client_port)
        self.ns = {True: 0, False: 0}

    def u(self, from_master, cf1):
        self.tcp.send(from_master, u_frame(cf1))

    def i(self, from_master, *bodies):
        frames = []
        for body in bodies:
            frames.append(i_frame(self.ns[from_master], self.ns[not from_master], body))
            self.ns[from_master] = (self.ns[from_master] + 1) & 0x7FFF
        self.tcp.send(from_master, *frames)

    def s(self, from_master):
        self.tcp.send(from_master, s_frame(self.ns[not from_master]))

    def startdt(self):
        self.u(True, STARTDT_ACT)
        self.u(False, STARTDT_CON)

    def command(self, type_id, ca, ioa, elem, select_first=False):
        """Activation -> confirmation -> termination (optionally select-before-operate)."""
        if select_first:
            sel = bytearray(elem)
            sel[_qualifier_offset(type_id)] |= 0x80
            self.i(True, asdu(type_id, ACT, ca, [(ioa, bytes(sel))]))
            self.i(False, asdu(type_id, ACTCON, ca, [(ioa, bytes(sel))]))
        self.i(True, asdu(type_id, ACT, ca, [(ioa, elem)]))
        self.i(False, asdu(type_id, ACTCON, ca, [(ioa, elem)]))
        self.i(False, asdu(type_id, ACTTERM, ca, [(ioa, elem)]))
        self.s(True)

    def close(self):
        self.tcp.close()


def _qualifier_offset(type_id):
    base = type_id - 13 if 58 <= type_id <= 64 else type_id
    return {45: 0, 46: 0, 47: 0, 48: 2, 49: 2, 50: 4}[base]


# --- Scenarios --------------------------------------------------------------

CA = 1


def scenario_control(pcap):
    """Normal master/RTU control session hitting every control-direction rule."""
    l = Link(pcap)
    l.startdt()
    # General interrogation with a few monitor points.
    l.i(True, asdu(100, ACT, CA, [(0, b"\x14")]))
    l.i(False, asdu(100, ACTCON, CA, [(0, b"\x14")]))
    l.i(False, asdu(1, INROGEN, CA, [(1000 + n, b"\x01") for n in range(8)], sq=True),
        asdu(13, INROGEN, CA, [(2000, struct.pack("<f", 49.98) + b"\x00"),
                                (2001, struct.pack("<f", 230.4) + b"\x00")]))
    l.i(False, asdu(100, ACTTERM, CA, [(0, b"\x14")]))
    l.s(True)
    # Counter interrogation, read, clock sync.
    l.i(True, asdu(101, ACT, CA, [(0, b"\x05")]))
    l.i(False, asdu(101, ACTCON, CA, [(0, b"\x05")]))
    l.i(True, asdu(102, REQ, CA, [(2000, b"")]))
    l.i(False, asdu(13, REQ, CA, [(2000, struct.pack("<f", 50.01) + b"\x00")]))
    l.i(True, asdu(103, ACT, CA, [(0, cp56())]))
    l.i(False, asdu(103, ACTCON, CA, [(0, cp56())]))
    # Control commands.
    l.command(45, CA, 5000, b"\x01", select_first=True)          # single command ON
    l.command(46, CA, 5001, b"\x02")                             # double command ON
    l.command(47, CA, 5002, b"\x02")                             # regulating step higher
    l.command(48, CA, 6000, struct.pack("<h", 16384) + b"\x00")  # setpoint normalized 0.5
    l.command(49, CA, 6001, struct.pack("<h", 1200) + b"\x00")   # setpoint scaled
    l.command(50, CA, 6002, struct.pack("<f", 63.5) + b"\x00", select_first=True)
    l.command(51, CA, 6003, struct.pack("<I", 0xDEADBEEF))       # bitstring
    l.command(58, CA, 5003, b"\x00" + cp56())                    # C_SC_TA_1 OFF
    l.command(63, CA, 6004, struct.pack("<f", 12.25) + b"\x00" + cp56())  # C_SE_TC_1
    # Parameter change + activation.
    l.i(True, asdu(112, ACT, CA, [(6002, struct.pack("<f", 0.5) + b"\x01")]))
    l.i(False, asdu(112, ACTCON, CA, [(6002, struct.pack("<f", 0.5) + b"\x01")]))
    l.i(True, asdu(113, ACT, CA, [(6002, b"\x03")]))
    l.i(False, asdu(113, ACTCON, CA, [(6002, b"\x03")]))
    # Reset process.
    l.i(True, asdu(105, ACT, CA, [(0, b"\x01")]))
    l.i(False, asdu(105, ACTCON, CA, [(0, b"\x01")]))
    # Keep-alive and stop.
    l.u(True, TESTFR_ACT)
    l.u(False, TESTFR_CON)
    l.u(True, STOPDT_ACT)
    l.u(False, STOPDT_CON)
    l.close()


def scenario_monitor_only(pcap):
    """Benign spontaneous data only: should raise no alerts besides STARTDT."""
    l = Link(pcap)
    l.startdt()
    for n in range(5):
        l.i(False, asdu(30, SPONT, CA, [(1000 + n, b"\x01" + cp56(ms=n * 100))]),
            asdu(36, SPONT, CA, [(2000 + n, struct.pack("<f", 49.9 + n / 100) + b"\x00" + cp56())]))
        l.s(True)
        l.u(True, TESTFR_ACT)
        l.u(False, TESTFR_CON)
    l.close()


def scenario_recon(pcap):
    """Rogue host walks common addresses and IOAs; RTU answers 'unknown'."""
    l = Link(pcap, client_ip=ROGUE_IP, client_port=41000)
    l.startdt()
    for ca in range(1, 6):
        l.i(True, asdu(100, ACT, ca, [(0, b"\x14")]))
        if ca == CA:
            l.i(False, asdu(100, ACTCON, ca, [(0, b"\x14")]))
            l.i(False, asdu(100, ACTTERM, ca, [(0, b"\x14")]))
        else:
            l.i(False, asdu(100, UNK_CA, ca, [(0, b"\x14")], negative=True))
    for ioa in (1, 2, 3, 9999):
        l.i(True, asdu(102, REQ, CA, [(ioa, b"")]))
        l.i(False, asdu(102, UNK_IOA, CA, [(ioa, b"")], negative=True))
    l.close()


def scenario_file_transfer(pcap):
    """Directory listing and transfer of one file (e.g. disturbance record)."""
    l = Link(pcap)
    l.startdt()
    nof = 1
    l.i(True, asdu(122, FILE, CA, [(0, struct.pack("<H", 0) + b"\x00\x00")]))  # call directory
    l.i(False, asdu(126, FILE, CA, [(7000, struct.pack("<H", nof) + ioa3(512) + b"\x00" + cp56())]))
    l.i(True, asdu(122, FILE, CA, [(7000, struct.pack("<H", nof) + b"\x00\x01")]))   # select file
    l.i(False, asdu(120, FILE, CA, [(7000, struct.pack("<H", nof) + ioa3(512) + b"\x00")]))
    l.i(True, asdu(122, FILE, CA, [(7000, struct.pack("<H", nof) + b"\x00\x02")]))   # call file
    l.i(False, asdu(121, FILE, CA, [(7000, struct.pack("<H", nof) + b"\x01" + ioa3(512) + b"\x00")]))
    l.i(True, asdu(122, FILE, CA, [(7000, struct.pack("<H", nof) + b"\x01\x06")]))   # call section
    for _ in range(4):
        seg = bytes(range(128))
        l.i(False, asdu(125, FILE, CA, [(7000, struct.pack("<H", nof) + b"\x01" + bytes([len(seg)]) + seg)]))
    l.i(False, asdu(123, FILE, CA, [(7000, struct.pack("<H", nof) + b"\x01\x03\x00")]))  # last segment
    l.i(True, asdu(124, FILE, CA, [(7000, struct.pack("<H", nof) + b"\x01\x03")]))       # ack section
    l.close()


def scenario_reversed(pcap):
    """Command activation sent by the outstation side of the connection."""
    l = Link(pcap)
    l.startdt()
    l.i(False, asdu(45, ACT, CA, [(5000, b"\x01")]))
    l.close()


def scenario_anomalies(pcap):
    """One TCP session per anomaly; some anomalies stop parsing of their flow."""
    port = iter(range(51000, 52000))

    def link():
        lk = Link(pcap, client_port=next(port))
        lk.startdt()
        return lk

    # asdu_length_mismatch: M_SP_NA_1 declares 3 objects, carries 1.
    lk = link()
    body = bytearray(asdu(1, SPONT, CA, [(1, b"\x01")]))
    body[1] = 3
    lk.i(False, bytes(body))
    lk.close()

    # unknown_type_id: private type 200.
    lk = link()
    lk.i(True, asdu(200, ACT, CA, [(1, b"\x00\x00")]))
    lk.close()

    # invalid_cot: COT 0 and reserved COT 15.
    lk = link()
    lk.i(False, asdu(1, 0, CA, [(1, b"\x01")]))
    lk.i(False, asdu(1, 15, CA, [(2, b"\x01")]))
    lk.close()

    # unknown_u_function: U-format with undefined function bits.
    lk = link()
    lk.u(True, 0x0F)
    lk.close()

    # sequence_mismatch: N(S) jumps from 1 to 7 (injected/replayed frame).
    lk = link()
    lk.i(True, asdu(100, ACT, CA, [(0, b"\x14")]))
    lk.i(True, asdu(100, ACT, CA, [(0, b"\x14")]))
    lk.ns[True] = 7
    lk.i(True, asdu(45, ACT, CA, [(5000, b"\x01")]))
    lk.close()

    # invalid_length: APDU length byte 2 (below the 4-byte control field).
    lk = link()
    lk.tcp.send(True, bytes([0x68, 0x02, 0x00, 0x00]))
    lk.close()

    # malformed_apdu: I-frame whose ASDU is shorter than the 6-byte header.
    lk = link()
    lk.tcp.send(True, bytes([0x68, 0x06, 0x00, 0x00, 0x00, 0x00, 0x2D, 0x01]))
    lk.close()

    # invalid_start_byte: garbage after STARTDT; parser stops on this flow.
    lk = link()
    lk.tcp.send(True, b"\xAA\xBB\xCC\xDD\xEE\xFF")
    lk.close()


def scenario_flood(pcap):
    """Many APDUs per segment. Trips too_many_transactions only with a low max-tx."""
    l = Link(pcap)
    l.startdt()
    for _ in range(4):
        l.tcp.send(True, *[u_frame(TESTFR_ACT)] * 240)
    l.close()


SCENARIOS = [
    ("iec104-control.pcap", scenario_control,
     [3701001, 3701002, 3701003, 3701004, 3701005, 3701010, 3701011, 3701020, 3701030,
      3701031, 3701032, 3701040, 3701041, 3701050, 3701099]),
    ("iec104-monitor-only.pcap", scenario_monitor_only, [3701040]),
    ("iec104-recon.pcap", scenario_recon, [3701030, 3701032, 3701033, 3701040]),
    ("iec104-file-transfer.pcap", scenario_file_transfer, [3701040, 3701051]),
    ("iec104-reversed-command.pcap", scenario_reversed, [3701040, 3701060]),
    ("iec104-anomalies.pcap", scenario_anomalies,
     [3701001, 3701030, 3701040, 3701099, 3701300, 3701301, 3701302, 3701303, 3701304,
      3701305, 3701306, 3701307]),
    ("iec104-flood.pcap", scenario_flood, [3701040]),
]


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "iec104-pcaps"
    os.makedirs(outdir, exist_ok=True)
    expected = {}
    for name, fn, sids in SCENARIOS:
        pcap = Pcap()
        fn(pcap)
        pcap.write(os.path.join(outdir, name))
        expected[name] = {"sids": sids, "description": fn.__doc__.strip()}
        print("%-30s %4d packets  SIDs %s" % (name, len(pcap.records), ",".join(map(str, sids))))
    expected["iec104-flood.pcap"]["note"] = (
        "set app-layer.protocols.iec104.max-tx: 100 to trip SID 3701308"
    )
    with open(os.path.join(outdir, "expected-sids.json"), "w") as f:
        json.dump(expected, f, indent=2)
    print("wrote %s/expected-sids.json" % outdir)


if __name__ == "__main__":
    main()
