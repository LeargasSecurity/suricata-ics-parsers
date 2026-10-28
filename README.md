# Suricata S7comm ICS Protocol Parser

[![License: GPL v2](https://img.shields.io/badge/License-GPLv2-blue.svg)](LICENSE)

A [Suricata 8.0](https://suricata.io/) application-layer parser **plugin** for the
Siemens **S7comm** and **S7comm-plus** protocols, purpose-built for
Industrial Control System (ICS/OT) network monitoring.

Unlike signature-only approaches that match fixed byte offsets, this is a true
stateful protocol parser written in Rust. It performs full TPKT/COTP/S7comm
dissection, extracts meaningful protocol fields, correlates requests with
responses, exposes rich detection keywords, emits structured EVE JSON, and maps
observed operations to the [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
framework.

Maintained by **Leargas Security**.

> **Note:** This is an **out-of-tree** plugin. It is **not affiliated with or endorsed by OISF**.

---

## Features

- **Full protocol dissection** — TPKT (RFC 1006), COTP (ISO 8073), S7comm, and
  S7comm-plus (S7-1200/1500) headers.
- **COTP TSAP extraction** — decodes source/destination TSAP into rack/slot
  addressing.
- **Read/Write Variable item parsing** — extracts memory area, data-block
  number, byte address, and length (S7ANY addressing), including multi-item
  requests.
- **S7comm-plus dissection** — version, opcode, function code, and sequence
  number.
- **Request/response correlation** — matched by PDU reference with error
  class/code from the response.
- **10 detection keywords** plus a sticky buffer for content matching.
- **Protocol frames** (`s7comm.pdu`, `s7comm.s7comm`) for the `frame` keyword.
- **Structured EVE JSON** logging with resolved names and ATT&CK techniques.
- **App-layer anomaly events** for malformed PDUs, invalid protocol/ROSCTR,
  reconnaissance, password access, and more.
- **DoS guards** — configurable transaction and PDU-size limits.

---

## Requirements

- Suricata **8.0.x** built with plugin support (`--enable-plugins`).
- Rust toolchain (edition 2021) to build the plugin.
- The matching Suricata source tree (the plugin links against the `suricata`
  and `suricata-sys` crates that ship with it).

---

## Building

The plugin links against the Suricata Rust crates from the matching **Suricata
8.0.x source tree**. Point `SURICATA_SRC` at that tree (the directory that
contains `rust/`) and build with `make` — `Cargo.toml` is generated from
`Cargo.toml.in`, so nothing needs to be hand-edited:

```bash
# Default SURICATA_SRC is $HOME/suricata-8.0.6; override as needed:
make build SURICATA_SRC=/opt/suricata-8.0.6
```

The plugin is produced at `target/release/libsuricata_s7comm.so`.

Useful targets:

```bash
make test     SURICATA_SRC=/opt/suricata-8.0.6   # Rust unit tests
make install  SURICATA_SRC=/opt/suricata-8.0.6   # install .so + rules (sudo)
make clean
```

> Prefer containers? See [Docker](#docker) below — no local Suricata build
> required.
>
> The `.cargo/config.toml` sets the linker flag
> `-C link-args=-Wl,-undefined,dynamic_lookup` so the plugin can resolve
> Suricata's symbols at load time.

---

## Docker

Build a self-contained image with Suricata + the plugin preinstalled:

```bash
docker build -t suricata-s7comm .

# Offline: analyze a pcap
docker run --rm -v "$PWD:/data" suricata-s7comm -r /data/capture.pcap -l /data/out -k none

# Live: monitor a host interface
docker run --rm --net=host suricata-s7comm -i eth0 -k none
```

---

## Installation

```bash
# Install the plugin shared object and rules (from a build tree):
sudo make install SURICATA_SRC=/opt/suricata-8.0.6

# ...or manually:
sudo mkdir -p /usr/local/lib/suricata/plugins
sudo cp target/release/libsuricata_s7comm.so /usr/local/lib/suricata/plugins/
sudo cp rules/s7comm.rules rules/iec104.rules /usr/local/var/lib/suricata/rules/
```

Enable the plugin and protocol in `suricata.yaml`:

```yaml
plugins:
  - /usr/local/lib/suricata/plugins/libsuricata_s7comm.so

app-layer:
  protocols:
    s7comm:
      enabled: yes
      detection-ports:
        dp: 102
      # Optional tuning:
      # max-tx: 1024              # live-transaction cap (DoS guard)
      # max-request-size: 131072  # per-PDU byte cap (DoS guard)
    iec104:
      enabled: yes
      detection-ports:
        dp: 2404
      # max-tx: 1024

outputs:
  - eve-log:
      enabled: yes
      types:
        - s7comm
        - iec104
        - alert
        - anomaly

rule-files:
  - suricata.rules
  - s7comm.rules
  - iec104.rules
```

Validate the configuration:

```bash
suricata -c /usr/local/etc/suricata/suricata.yaml -r your.pcap -l /tmp/out -k none
```

---

## Running

### Offline (pcap)

```bash
suricata -c /usr/local/etc/suricata/suricata.yaml -r capture.pcap -l /tmp/out -k none
```

### Live (SPAN/mirror interface)

```bash
sudo suricata -c /usr/local/etc/suricata/suricata.yaml -i ens192 -k none
```

### As a persistent service (systemd)

```ini
[Unit]
Description=Suricata IDS with S7comm Parser
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/bin/rm -f /run/suricata.pid
ExecStart=/usr/local/bin/suricata -c /usr/local/etc/suricata/suricata.yaml -i ens192 -k none --pidfile /run/suricata.pid
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now suricata
```

Alerts and protocol logs are written to `/usr/local/var/log/suricata/eve.json`
and `fast.log`.

---

## Detection Keywords

See [`doc/s7comm-keywords.rst`](doc/s7comm-keywords.rst) for full details.

| Keyword | Type | Description |
| --- | --- | --- |
| `s7comm.function_code` | uint8 | S7comm function code (e.g. `0x04` Read, `0x05` Write, `0x29` PLC Stop) |
| `s7comm.rosctr` | uint8 | PDU type: 1 Job, 2 Ack, 3 Ack-Data, 7 Userdata |
| `s7comm.dangerous` | bool | Matches write/download/upload/control/stop operations |
| `s7comm.userdata_group` | uint8 | Userdata function group (5 = Security, 4 = CPU, …) |
| `s7comm.subfunction` | uint8 | Userdata subfunction |
| `s7comm.db` | uint16 | Data-block number (Read/Write Var) |
| `s7comm.area` | uint8 | Memory area (`0x84` DB, `0x82` Outputs, `0x83` Flags, …) |
| `s7comm.plus` | bool | Matches S7comm-plus (S7-1200/1500) traffic |
| `s7comm.plus_function` | uint16 | S7comm-plus function (`0x04f2` SetVariable, …) |
| `s7comm.data` | sticky buffer | Raw S7comm PDU payload for `content`/`pcre` matching |

Numeric keywords support the standard Suricata uint comparisons (`=`, `<`, `>`,
`<=`, `>=`, range `x-y`, bitmask `&`).

### Frames

| Frame | Description |
| --- | --- |
| `s7comm.pdu` | The entire TPKT/COTP/S7comm PDU |
| `s7comm.s7comm` | The S7comm portion (after TPKT and COTP) |

### App-layer events

`malformed_pdu`, `invalid_protocol_id`, `plc_stop`, `plc_mode_change`,
`program_download`, `program_upload`, `write_variable`, `read_szl`,
`password_access`, `s7_comm_plus_usage`, `too_many_transactions`.

---

## Bundled Rules

`rules/s7comm.rules` ships with the following signatures (SID range
`3700000–3700110`), each mapped to MITRE ATT&CK for ICS:

| SID | Signature | ATT&CK |
| --- | --- | --- |
| 3700001 | PLC Stop Command | T0858, T0814 |
| 3700002 | PLC Control (Mode Change) | T0858 |
| 3700003 | Request Download (Program Transfer) | T0843 |
| 3700004 | Download Block | T0843 |
| 3700005 | Download Ended | T0843 |
| 3700006 | Start Upload (Program Exfiltration) | T0845 |
| 3700007 | Upload Block | T0845 |
| 3700008 | End Upload | T0845 |
| 3700009 | Write Variable | T0836 |
| 3700010 | Setup Communication (New Session) | T0886 |
| 3700099 | Dangerous Operation Detected | — |
| 3700100 | S7comm-Plus Protocol Detected | — |
| 3700101 | Programmer Commands (Userdata) | T0843 |
| 3700102 | Security Function Access | T0859 |
| 3700103 | Read SZL (System Enumeration) | T0888 |
| 3700104 | Write to Data Block | T0836 |
| 3700105 | Write to Output Area (Process Manipulation) | T0836, T0831 |
| 3700106 | Write to Flags/Merker Area | T0836 |
| 3700107 | Write to Critical DB100 (example) | T0836 |
| 3700108 | S7comm-Plus SetVariable (Write) | T0836 |
| 3700109 | S7comm-Plus Explore (Enumeration) | T0888 |
| 3700110 | S7comm-Plus CreateObject | T0843 |

### Example rules

```
# Detect a PLC stop command
alert s7comm any any -> any 102 (msg:"S7COMM PLC Stop"; \
    s7comm.function_code:0x29; s7comm.rosctr:1; \
    classtype:attempted-dos; sid:3700001; rev:1;)

# Alert on any write to a critical data block
alert s7comm any any -> any 102 (msg:"S7COMM Write DB100"; \
    s7comm.function_code:0x05; s7comm.db:100; sid:3700107; rev:1;)

# Content match within the S7comm frame
alert s7comm any any -> any 102 (msg:"S7COMM payload"; \
    frame:s7comm.pdu; content:"|03 00|"; startswith; sid:9001; rev:1;)
```

---

## EVE JSON Output

Each completed transaction produces an `s7comm` event. Example (Write Variable
to the Flags/Merker area on an S7-300):

```json
{
  "event_type": "s7comm",
  "s7comm": {
    "pdu_reference": 2,
    "rosctr": "Job",
    "function_code": 5,
    "function_code_hex": "0x05",
    "function_name": "Write Variable",
    "item": {
      "count": 1,
      "area": 131,
      "area_name": "Flags (M)",
      "db_number": 0,
      "address": 0,
      "length": 4
    },
    "cotp": { "src_tsap": 256, "dst_tsap": 258, "rack": 0, "slot": 2 },
    "is_dangerous": true,
    "attack_technique": "T0836 Modify Parameter"
  }
}
```

Fields include (as applicable): `pdu_reference`, `rosctr`, `function_code`,
`function_code_hex`, `function_name`, `userdata_group`,
`userdata_group_name`, `userdata_subfunction`, `item{}`, `cotp{}`,
`plc_control_service`, `is_dangerous`, `attack_technique`, `error_class`,
`error_code`, `s7comm_plus`, and `plus{}`.

---

## Protocol Coverage

| Element | Support |
| --- | --- |
| TPKT / COTP (CR, CC, DT) | Yes |
| COTP TSAP (rack/slot) | Yes |
| S7comm Job / Ack / Ack-Data | Yes |
| Read / Write Variable item addressing | Yes (multi-item) |
| Program Download / Upload | Yes |
| PLC Control / Stop | Yes (with PI-service string) |
| Userdata groups (Programmer, CPU, Security, Time, ...) | Yes |
| Read SZL reconnaissance | Yes |
| S7comm-plus (S7-1200/1500) | Yes (header/opcode/function) |

---

## IEC 60870-5-104

The same plugin library also registers an `iec104` app-layer parser (TCP/2404).
Each APDU (I, S, or U format) is one unidirectional transaction. See
[`doc/iec104-keywords.rst`](doc/iec104-keywords.rst) for full details.

| Keyword | Type | Description |
| --- | --- | --- |
| `iec104.type_id` | uint8 | ASDU type (`45` C_SC_NA_1, `100` C_IC_NA_1, …) |
| `iec104.cot` | uint8 | Cause of transmission (`6` activation, `7` confirmation, …) |
| `iec104.common_address` | uint16 | ASDU common (station) address |
| `iec104.ioa` | uint32 | Matches any information object address in the ASDU |
| `iec104.u_function` | uint8 | U-format function (`0x07` STARTDT act, `0x13` STOPDT act, …) |
| `iec104.dangerous` | bool | Control commands, setpoints, parameter changes, reset process |
| `iec104.data` | sticky buffer | Raw APDU |

Frames: `iec104.pdu`, `iec104.asdu`. App-layer events include `command`,
`interrogation`, `reset_process`, `parameter_change`, `stop_data_transfer`,
`sequence_mismatch` (N(S) discontinuity), `unknown_address`,
`asdu_length_mismatch`, and `malformed_apdu`.

`rules/iec104.rules` (SIDs `3701001–3701308`) covers commands (T0855/T0831),
setpoints and parameters (T0836), reset process (T0816), interrogation and
address enumeration (T0861), STOPDT (T0815), and protocol anomalies.

Example EVE record (single command, execute ON):

```json
{
  "event_type": "iec104",
  "iec104": {
    "direction": "to_server",
    "apci": { "length": 14, "format": "I", "send_seq": 0, "recv_seq": 0 },
    "asdu": {
      "type_id": 45, "type_name": "C_SC_NA_1", "sq": false, "num_objects": 1,
      "cot": 6, "cot_name": "activation", "negative": false, "test": false,
      "originator": 0, "common_address": 1, "ioa": 5000,
      "command": { "select": false, "qualifier": 0, "state": 1 }
    },
    "is_dangerous": true,
    "attack_technique": "T0855 Unauthorized Command Message / T0831 Manipulation of Control"
  }
}
```

---

## Testing

### Rust unit tests

```bash
cargo test --release
```

Covers PDU parsing, COTP TSAP extraction, multi-item Read/Write Var,
S7comm-plus, invalid-ROSCTR handling, malformed-input safety, and enum
mappings.

### suricata-verify tests

Under [`tests/`](tests/), each directory is a self-contained
[suricata-verify](https://github.com/OISF/suricata-verify) test with a pcap,
rules, and output assertions:

| Test | Validates |
| --- | --- |
| `s7comm-write-var` | Read/Write Var item parsing, `s7comm.db`/`s7comm.area`, TSAP |
| `s7comm-download` | Program-download detection, `s7comm.dangerous`, ATT&CK |
| `s7comm-recon-szl` | Read SZL reconnaissance via userdata keywords |
| `s7comm-auth-password` | Security/password access + `frame` keyword |
| `s7comm-split-pdu` | S7 PDU split across TCP segments is reassembled (regression) |
| `iso102-not-s7comm` | Non-S7 (ISO session/MMS) TCP/102 traffic is not labelled `s7comm` |
| `iec104-commands` | IEC-104 STARTDT/GI/control commands vs. shipped `iec104.rules`, `iec104.dangerous`, EVE decoding |
| `iec104-sq` | IEC-104 SQ=1 ASDUs, multiple APDUs per segment, no false positives |

Run them from a built Suricata source directory (`run.py` uses
`./src/suricata`). The tests load the plugin from `SURICATA_ICS_PLUGIN` (they
are skipped if it is unset) and need `--no-validation`, because the plugin's
EVE types are not in Suricata's schema:

```bash
cd /path/to/suricata-8.0.x
SURICATA_ICS_PLUGIN=/path/to/suricata-ics-parsers/target/release/libsuricata_s7comm.so \
  ../suricata-verify/run.py --no-validation \
  --testdir=/path/to/suricata-ics-parsers/tests          # or a name/prefix, e.g. iec104
```

### Batch runner over a pcap directory

[`scripts/run-s7comm-pcaps.sh`](scripts/run-s7comm-pcaps.sh) runs Suricata with
the S7comm plugin over every pcap in a directory and prints a per-pcap summary
of packets, S7comm EVE logs, and S7comm alerts. It auto-detects the plugin
(freshly built or installed), generates a self-contained config (with
`stream.midstream` enabled so mid-stream sample captures parse), and writes
per-pcap `eve.json`/`run.log` under a results directory.

```bash
# Single pass over /mnt/pcap (default), results in ~/s7comm-results
scripts/run-s7comm-pcaps.sh

# Custom pcap and results directories
scripts/run-s7comm-pcaps.sh /path/to/pcaps /path/to/results
```

**Loop / watcher mode** — set `INTERVAL` (seconds) to scan continuously:

```bash
# Watch /mnt/pcap every 30s; only new/changed pcaps are processed
INTERVAL=30 scripts/run-s7comm-pcaps.sh

# Replay mode: reprocess every pcap on each pass (e.g. to feed a forwarder)
INTERVAL=30 REPROCESS=1 scripts/run-s7comm-pcaps.sh
```

Environment variables:

| Var | Default | Meaning |
| --- | --- | --- |
| `INTERVAL` | `0` | Seconds between passes; `0` = run once, `>0` = loop |
| `REPROCESS` | `0` | `1` = reprocess every pcap each pass; `0` = skip already-processed (by size/mtime) |
| `SURICATA` | `suricata` | Path to the Suricata binary |
| `PLUGIN` | auto | Path to `libsuricata_s7comm.so` |

In watcher mode a `.processed` state file records handled pcaps (keyed on
name + size + mtime) so only new or modified captures are re-run. `Ctrl-C`
stops the loop cleanly.

---

## Repository Layout

```
Cargo.toml.in         Plugin crate manifest template (Cargo.toml is generated)
.cargo/config.toml    Linker flags for plugin loading
src/
  lib.rs              Plugin module wiring
  plugin.rs           SCPluginRegister entry point
  s7comm.rs           App-layer state machine, frames, FFI, registration
  parser.rs           TPKT/COTP/S7comm/S7comm-plus nom parsers (+ unit tests)
  consts.rs           Protocol constants and enums (+ unit tests)
  detect.rs           Detection keyword + sticky-buffer registration
  log.rs              EVE JSON logger
  iec104/             IEC 60870-5-104 parser (consts, parser, state, detect, log)
rules/s7comm.rules    Bundled detection signatures
rules/iec104.rules    IEC 60870-5-104 detection signatures
doc/s7comm-keywords.rst  Keyword/frame/event reference
doc/iec104-keywords.rst  IEC 60870-5-104 keyword/frame/event reference
scripts/
  run-s7comm-pcaps.sh  Batch/loop runner over a pcap directory
tests/                suricata-verify tests with pcaps
```

---

## Limitations

- S7comm-plus dissection covers the header (version, opcode, function,
  sequence number); the encrypted/proprietary object payloads of v3 are not
  decoded.
- S7comm-plus paths are unit-tested but have not yet been validated against a
  real S7-1200/1500 capture.
- The example rule `3700107` (Write to DB100) is illustrative — tune the
  data-block number to your environment.
- IEC 60870-5-104 assumes the standard 104 profile (2-byte COT, 2-byte common
  address, 3-byte IOA). IEC 62351-3 (TLS-wrapped 104) is not decoded.

---

## License

GPL-2.0. See [`LICENSE`](LICENSE). Copyright (c) 2026 Leargas Security.

## Acknowledgements

Test captures are derived from publicly available samples, including the
Wireshark SampleCaptures wiki and [gymgit/s7-pcaps](https://github.com/gymgit/s7-pcaps)
(IP addresses randomized by their respective authors).
