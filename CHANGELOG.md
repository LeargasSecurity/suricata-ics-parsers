# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- IEC 60870-5-104 app-layer parser (`iec104`, TCP/2404) in the same plugin:
  APCI I/S/U framing, ASDU header, IOA extraction, command/setpoint decoding
  (select/execute, state, value), N(S) continuity tracking, 7 detection
  keywords plus the `iec104.data` sticky buffer, `iec104.pdu`/`iec104.asdu`
  frames, EVE `iec104` logging with ATT&CK-ICS mapping, anomaly events, and
  `rules/iec104.rules` (SIDs 3701001-3701308).
- Suricata rules for the parser's anomaly/DoS app-layer events: malformed/
  oversized PDU, transaction flood (max-tx), and invalid protocol id
  (`rules/s7comm.rules`, SIDs 3700300-3700302; ATT&CK ICS T0814).
- `make`-based build with a `SURICATA_SRC`-driven `Cargo.toml` generated from
  `Cargo.toml.in`, so the plugin builds regardless of where the Suricata source
  tree lives (removes the previously hardcoded path).
- GitHub Actions CI: rustfmt check, Suricata 8.0.x source build, plugin build,
  Rust unit tests, artifact upload, and suricata-verify tests.
- `Dockerfile` + `.dockerignore` producing a runtime image with Suricata and the
  S7comm plugin preinstalled.
- Community health files: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`,
  issue templates, and a pull-request template.

## [0.1.0] - 2026-07-24

### Added
- Initial S7comm / S7comm-plus Suricata 8.0.x application-layer parser plugin.
- Full TPKT (RFC 1006) / COTP (ISO 8073) / S7comm dissection with COTP TSAP
  (rack/slot) extraction and request/response correlation.
- Read/Write Variable item parsing (memory area, DB number, address, length),
  including multi-item requests.
- S7comm-plus (S7-1200/1500) header, opcode, function, and sequence dissection.
- 10 detection keywords, a `s7comm.data` sticky buffer, and `s7comm.pdu` /
  `s7comm.s7comm` frames.
- Structured EVE JSON logging with resolved names and MITRE ATT&CK for ICS
  technique mapping.
- App-layer anomaly events for malformed and suspicious PDUs.
- Bundled detection ruleset (SIDs `3700000`–`3700110`) mapped to ATT&CK-ICS.
- Rust unit tests and four suricata-verify tests (write-var, download, recon-szl,
  auth-password).

[Unreleased]: https://github.com/LeargasSecurity/suricata-ics-parsers/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/LeargasSecurity/suricata-ics-parsers/releases/tag/v0.1.0
