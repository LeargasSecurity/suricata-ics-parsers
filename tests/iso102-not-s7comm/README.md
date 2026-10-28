# iso102-not-s7comm

Regression test that non-S7 traffic on TCP/102 is not labelled `s7comm`.

## Purpose
- MMS, IEC 61850 and ICCP share TCP/102 and the same TPKT/COTP CR/CC
  handshake with S7comm. Detection must look at the first COTP DT payload.
- Every DT payload's S7 protocol id (0x32) is replaced with an ISO 8327
  session SPDU id (0x0D, CONNECT). The S7comm probe must reject the flow, so
  it produces no S7comm events or alerts; the `mms` parser claims it instead
  (`app_proto: mms`).

## PCAP
Derived from `tests/s7comm-write-var/input.pcap` by
`scripts/gen-iso102-regress-pcaps.py`.
