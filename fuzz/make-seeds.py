#!/usr/bin/env python3
# Build fuzz seed corpora from the suricata-verify test captures.
# Copyright (C) 2026 Leargas Security
# License: GPL-2.0
"""Write seed inputs for each cargo-fuzz target into fuzz/corpus/<target>/.

Seeds come from tests/*/input.pcap (decoded with tshark, which must be
installed):
  cotp         every TCP payload on TCP/102
  mms_message  every reassembled-or-single COTP DT user data (TSDU)
  mms_state    each TCP/102 capture as one stream: a direction byte
               (0 = to server, 1 = to client) before each TCP payload
  s7comm       TCP payloads of the S7comm captures
  iec104       TCP payloads of the IEC-104 captures

    fuzz/make-seeds.py
"""

import glob
import hashlib
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "fuzz", "corpus")


def payloads(pcap):
    """(dst_port, payload bytes) for each TCP segment with data."""
    out = subprocess.run(
        ["tshark", "-r", "-", "-Y", "tcp.len>0", "-T", "fields", "-E", "separator=|",
         "-e", "tcp.dstport", "-e", "tcp.payload"],
        stdin=open(pcap, "rb"), capture_output=True, text=True, check=True,
    ).stdout
    for line in out.splitlines():
        port, data = line.split("|")
        if data:
            yield int(port.split(",")[0]), bytes.fromhex(data.replace(":", ""))


def save(target, data):
    if not data:
        return
    d = os.path.join(OUT, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, hashlib.sha1(data).hexdigest()), "wb") as f:
        f.write(data)


def tsdus(stream):
    """User data of each COTP DT in a TPKT byte stream."""
    i = 0
    while i + 7 <= len(stream):
        n = int.from_bytes(stream[i + 2:i + 4], "big")
        if n < 7 or i + n > len(stream):
            return
        frame = stream[i:i + n]
        if frame[5] & 0xF0 == 0xF0:
            yield frame[5 + frame[4]:]
        i += n


def main():
    tests = os.path.join(ROOT, "tests")
    iso102 = sorted(glob.glob(f"{tests}/mms-*/input.pcap")
                    + glob.glob(f"{tests}/s7comm-*/input.pcap")
                    + glob.glob(f"{tests}/iso102-*/input.pcap"))
    for pcap in iso102:
        segs = list(payloads(pcap))
        save("mms_state", b"".join(bytes([0 if p == 102 else 1]) + d for p, d in segs)[:65536])
        for _, data in segs:
            save("cotp", data)
            if "s7comm" in pcap:
                save("s7comm", data)
        for to_server in (True, False):
            stream = b"".join(d for p, d in segs if (p == 102) == to_server)
            for t in tsdus(stream):
                save("mms_message", t)
    for pcap in sorted(glob.glob(f"{tests}/iec104-*/input.pcap")):
        for _, data in payloads(pcap):
            save("iec104", data)
    for t in sorted(os.listdir(OUT)):
        print(t, len(os.listdir(os.path.join(OUT, t))), "seeds")


if __name__ == "__main__":
    main()
