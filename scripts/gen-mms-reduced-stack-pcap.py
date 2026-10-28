#!/usr/bin/env python3
# Generate a clean "MMS directly over COTP" (reduced stack) test capture.
# Copyright (C) 2026 Leargas Security
# License: GPL-2.0
"""Write a deterministic reduced-stack MMS capture for tests/mms-reduced-stack.

Some MMS tools and scanners carry the MMS PDU straight after the COTP DT,
without the ISO 8327 session, ISO 8823 presentation and ACSE layers. This
builds one complete, well-formed TCP session that does exactly that:

    client -> server : COTP CR
    server -> client : COTP CC
    client -> server : DT  initiate-RequestPDU
    server -> client : DT  initiate-ResponsePDU
    client -> server : DT  confirmed-Request  start   { P1 }   (dangerous)
    server -> client : DT  confirmed-Response start
    client -> server : DT  confirmed-Request  read    { D1/V1 } (benign)
    server -> client : DT  confirmed-Response read
    client -> server : COTP DR

Pure standard library; no scapy. Checksums are not computed (tests use -k none).

    scripts/gen-mms-reduced-stack-pcap.py [OUT_PCAP]
"""

import struct
import sys

CLIENT = bytes([10, 0, 0, 1])
SERVER = bytes([10, 0, 0, 2])
CPORT, SPORT = 40102, 102


def tlv(tag, content):
    if len(content) < 0x80:
        return bytes(tag) + bytes([len(content)]) + content
    return bytes(tag) + bytes([0x81, len(content)]) + content


def ber_int(n):
    return bytes([n]) if n < 0x80 else bytes([0x00, n])


def tpkt(payload):
    return struct.pack(">BBH", 0x03, 0x00, len(payload) + 4) + payload


def cotp_cr():
    # LI, CR, dst-ref, src-ref, class/option
    return tpkt(bytes([0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00]))


def cotp_cc():
    return tpkt(bytes([0x06, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00]))


def cotp_dr():
    return tpkt(bytes([0x06, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00]))


def dt(mms):
    # COTP DT: LI=2, DT, TPDU-NR with EOT bit set
    return tpkt(bytes([0x02, 0xF0, 0x80]) + mms)


def initiate(tag):
    # MMSpdu initiate-Request/Response [8]/[9] with the usual negotiated params.
    body = (
        tlv([0x80], bytes([0xFA, 0x00]))  # localDetailCalling 64000
        + tlv([0x81], ber_int(5))         # maxServOutstandingCalling
        + tlv([0x82], ber_int(5))         # maxServOutstandingCalled
        + tlv([0x83], ber_int(10))        # dataStructureNestingLevel
    )
    return tlv(tag, body)


def name(ident):
    # ObjectName domain-specific [1] { domainId, itemId }  (visible strings)
    return tlv([0xA1], tlv([0x1A], b"D1") + tlv([0x1A], ident))


def confirmed_request(invoke, service_tlv):
    return tlv([0xA0], tlv([0x02], ber_int(invoke)) + service_tlv)


def confirmed_response(invoke, service_tlv):
    return tlv([0xA1], tlv([0x02], ber_int(invoke)) + service_tlv)


def start_request(invoke):
    # start [40] { programInvocationName [0] IMPLICIT Identifier "P1" }
    return confirmed_request(invoke, tlv([0xBF, 0x28], tlv([0x80], b"P1")))


def read_request(invoke):
    # read [4] { variableAccessSpecification [1] { listOfVariable [0] {
    #   { variableSpecification { name [0] ObjectName } } } } }
    var = tlv([0xA0], tlv([0xA0], name(b"V1")))
    return confirmed_request(invoke, tlv([0xA4], tlv([0xA1], tlv([0xA0], var))))


def confirmed_response_empty(invoke, tag):
    return confirmed_response(invoke, tlv(tag, b""))


# (payload, to_server) in order; None payloads are pure ACKs.
def build_stream():
    return [
        (cotp_cr(), True),
        (cotp_cc(), False),
        (dt(initiate([0xA8])), True),
        (dt(initiate([0xA9])), False),
        (dt(start_request(1)), True),
        (dt(confirmed_response_empty(1, [0xBF, 0x28])), False),
        (dt(read_request(2)), True),
        (dt(confirmed_response(2, tlv([0xA4], tlv([0xA1], tlv([0x80], ber_int(10)))))), False),
        (cotp_dr(), True),
    ]


def ip_tcp(src, sport, dst, dport, seq, ack, flags, payload):
    ihl = 5
    total = ihl * 4 + 20 + len(payload)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0x00, total, 0, 0x4000, 64, 6, 0, src, dst,
    )
    tcp = struct.pack(
        ">HHIIBBHHH", sport, dport, seq, ack, (5 << 4), flags, 0x2000, 0, 0
    )
    return ip + tcp + payload


def eth(frame):
    return b"\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00" + frame


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "mms-reduced-stack.pcap"
    packets = []
    ts = 1_700_000_000
    cseq = ack_c = 1
    sseq = ack_s = 1

    def add(frame):
        packets.append((ts, frame))

    # TCP handshake
    add(eth(ip_tcp(CLIENT, CPORT, SERVER, SPORT, 0, 0, 0x02, b"")))
    add(eth(ip_tcp(SERVER, SPORT, CLIENT, CPORT, 0, 1, 0x12, b"")))
    add(eth(ip_tcp(CLIENT, CPORT, SERVER, SPORT, 1, 1, 0x10, b"")))

    for payload, to_server in build_stream():
        if to_server:
            add(eth(ip_tcp(CLIENT, CPORT, SERVER, SPORT, cseq, ack_c, 0x18, payload)))
            cseq += len(payload)
            ack_s = cseq
            add(eth(ip_tcp(SERVER, SPORT, CLIENT, CPORT, sseq, ack_s, 0x10, b"")))
        else:
            add(eth(ip_tcp(SERVER, SPORT, CLIENT, CPORT, sseq, ack_s, 0x18, payload)))
            sseq += len(payload)
            ack_c = sseq
            add(eth(ip_tcp(CLIENT, CPORT, SERVER, SPORT, cseq, ack_c, 0x10, b"")))

    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, frame in packets:
            f.write(struct.pack("<IIII", t, 0, len(frame), len(frame)) + frame)
    print("wrote", out, "with", len(packets), "packets")


if __name__ == "__main__":
    main()
