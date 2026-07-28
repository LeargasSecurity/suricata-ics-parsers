# s7comm-recon-szl

Tests detection of S7comm reconnaissance via Read SZL (System Status List)
enumeration.

## Purpose
- Verify Userdata (ROSCTR 7) parsing extracts function group and subfunction.
- Verify the CPU Functions group (4) + Read SZL subfunction (1) is detected as
  reconnaissance (T0888 Remote System Information Discovery).
- Verify `s7comm.userdata_group` and `s7comm.subfunction` keywords match.

## PCAP
`s7comm_reading_plc_status.pcap` — reading PLC status/SZL from an S7-300 PLC.
Sourced from the Wireshark SampleCaptures wiki.
