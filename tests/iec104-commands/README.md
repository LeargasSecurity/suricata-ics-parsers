# iec104-commands

Tests IEC 60870-5-104 control-direction parsing and the shipped
`rules/iec104.rules` against a full master/outstation session.

## Purpose
- Verify STARTDT, General Interrogation and every control command in the
  capture (C_SC, C_DC, C_RC, C_BO, C_SE_NA/NB/NC) raise exactly the expected
  alerts, and nothing else (no anomaly/DoS false positives).
- Verify `iec104.dangerous` fires on each command activation but not on
  monitor-direction data.
- Verify EVE `iec104` records: U-format function names, ASDU header (type, COT,
  common address, IOA), command state/value decoding and ATT&CK mapping.

## PCAP
`iec104.pcap` — IEC 60870-5-104 master/outstation session (STARTDT, GI,
measurements, single/double/regulating/bitstring/setpoint commands).
Sourced from the Wireshark SampleCaptures wiki.

## Running
The plugin is loaded from `SURICATA_ICS_PLUGIN`; the test is skipped if unset.
Plugin EVE types are not in Suricata's schema, so pass `--no-validation`:

```bash
cd /path/to/suricata-8.0.x
SURICATA_ICS_PLUGIN=/path/to/libsuricata_s7comm.so \
  ../suricata-verify/run.py --no-validation --testdir=/path/to/repo/tests iec104-commands
```
