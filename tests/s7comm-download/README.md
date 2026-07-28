# s7comm-download

Tests detection of S7comm program-download sequences and the `s7comm.dangerous`
keyword.

## Purpose
- Verify Request Download (function 0x1a) is parsed and flagged dangerous.
- Verify ATT&CK mapping (T0843 Program Download) is present in the EVE log.
- Verify the `s7comm.dangerous` boolean keyword matches.

## PCAP
`s7comm_downloading_block_db1.pcap` — TIA/Step7 downloading a block (DB1) to an
S7-300 PLC. Sourced from the Wireshark SampleCaptures wiki.
