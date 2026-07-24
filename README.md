# Suricata S7comm ICS Protocol Parser

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

The plugin links against the Suricata Rust crates from the Suricata source
tree. Adjust the paths in `Cargo.toml` if your Suricata source lives elsewhere:

```toml
[dependencies]
suricata     = { path = "/path/to/suricata-8.0.6/rust/" }
suricata-sys = { path = "/path/to/suricata-8.0.6/rust/sys" }
```

Then build:

```bash
cargo build --release
```

The plugin is produced at `target/release/libsuricata_s7comm.so`.

> The `.cargo/config.toml` sets the linker flag
> `-C link-args=-Wl,-undefined,dynamic_lookup` so the plugin can resolve
> Suricata's symbols at load time.

---

## Installation

```bash
# 1. Install the plugin shared object
sudo mkdir -p /usr/local/lib/suricata/plugins
sudo cp target/release/libsuricata_s7comm.so /usr/local/lib/suricata/plugins/

# 2. Install the detection rules
sudo cp rules/s7comm.rules /usr/local/var/lib/suricata/rules/
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

outputs:
  - eve-log:
      enabled: yes
      types:
        - s7comm
        - alert
        - anomaly

rule-files:
  - suricata.rules
  - s7comm.rules
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
| TPKT / COTP (CR, CC, DT) | ✅ |
| COTP TSAP (rack/slot) | ✅ |
| S7comm Job / Ack / Ack-Data | ✅ |
| Read / Write Variable item addressing | ✅ (multi-item) |
| Program Download / Upload | ✅ |
| PLC Control / Stop | ✅ (with PI-service string) |
| Userdata groups (Programmer, CPU, Security, Time, …) | ✅ |
| Read SZL reconnaissance | ✅ |
| S7comm-plus (S7-1200/1500) | ✅ header/opcode/function |

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

Run them from a Suricata source directory:

```bash
../suricata-verify/run.py --suricata=/usr/local/bin/suricata s7comm-write-var
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
Cargo.toml            Plugin crate manifest
.cargo/config.toml    Linker flags for plugin loading
src/
  lib.rs              Plugin module wiring
  plugin.rs           SCPluginRegister entry point
  s7comm.rs           App-layer state machine, frames, FFI, registration
  parser.rs           TPKT/COTP/S7comm/S7comm-plus nom parsers (+ unit tests)
  consts.rs           Protocol constants and enums (+ unit tests)
  detect.rs           Detection keyword + sticky-buffer registration
  log.rs              EVE JSON logger
rules/s7comm.rules    Bundled detection signatures
doc/s7comm-keywords.rst  Keyword/frame/event reference
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

---

## License

GPL-2.0. See [`Cargo.toml`](Cargo.toml). Copyright © 2026 Leargas Security.

## Acknowledgements

Test captures are derived from publicly available samples, including the
Wireshark SampleCaptures wiki and [gymgit/s7-pcaps](https://github.com/gymgit/s7-pcaps)
(IP addresses randomized by their respective authors).
