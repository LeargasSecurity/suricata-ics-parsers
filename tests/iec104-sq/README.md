# iec104-sq

Tests IEC 60870-5-104 parsing of SQ=1 (sequence) ASDUs and multiple APDUs in a
single TCP segment.

## Purpose
- Verify four I-frames carried in one segment are each parsed as a transaction.
- Verify SQ=1 ASDUs (M_SP_NA_1, 16 objects each) decode with the correct base
  IOA (0, 16, 32, 48) and common address.
- Verify monitor-direction data raises no alerts, anomalies or `is_dangerous`.

## PCAP
`IEC104_SQ.pcapng` (saved as `input.pcap`; pcapng format) — a single segment of
interrogated single-point information with SQ=1. Mid-stream capture, so the
test config enables `stream.midstream`. Sourced from the Wireshark
SampleCaptures wiki.

## Running
See [`../iec104-commands/README.md`](../iec104-commands/README.md#running).
