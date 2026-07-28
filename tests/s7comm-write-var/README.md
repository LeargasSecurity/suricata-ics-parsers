# s7comm-write-var

Tests the S7comm parser's Read/Write Variable data-item extraction and
area/DB-aware detection keywords.

## Purpose
- Verify `s7comm.item.*` fields (area, area_name, db_number, address, length) are
  parsed from Read/Write Variable requests using S7ANY addressing.
- Verify COTP TSAP rack/slot extraction (`s7comm.cotp.*`).
- Verify the `s7comm.area` and `s7comm.db` detection keywords match.

## PCAP
`s7comm_varservice_libnodavedemo.pcap` — libnodave demo performing Read/Write
Variable operations against an S7-300 PLC. Sourced from the Wireshark
SampleCaptures wiki.
