# s7comm-split-pdu

Regression test for TPKT reassembly when an S7comm PDU spans TCP segments.

## Purpose
- The first S7 Job PDU after Setup Communication is split 3/4 + 1/4 across two
  segments, with a server ACK in between, so the parser sees a partial PDU.
- Older builds returned the number of bytes still *missing* from
  `AppLayerResult::incomplete()` instead of the total PDU size. Suricata treats
  `consumed + needed < input_len` as an internal error, so parsing stopped
  after Setup Communication. The output must now match `s7comm-write-var`.

## PCAP
Derived from `tests/s7comm-write-var/input.pcap` by
`scripts/gen-iso102-regress-pcaps.py`.
