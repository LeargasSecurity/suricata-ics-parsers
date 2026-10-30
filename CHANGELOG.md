# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-10-30

Rebuild for the Suricata 8.0.8 security release. Upgrade Suricata and the
plugin together: the plugin embeds parts of Suricata's Rust code from the
version it was built against, and Suricata loads a plugin built for another
release without complaint.

### Added
- The plugin logs a warning at startup when the running Suricata version
  differs from the version it was built against (looked up at runtime, so a
  missing symbol never stops the plugin from loading).

### Changed
- Built, tested and released against Suricata 8.0.8 (was 8.0.6): CI, the
  release workflow, the Docker image and the `make` default. No parser or
  rule changes; 64 captures give identical output on 8.0.6 and 8.0.8.

## [0.2.0] - 2026-10-28

### Added
- cargo-fuzz targets (`fuzz/`) for every parser that handles untrusted
  traffic: `cotp`, `mms_message`, `mms_state`, `s7comm` and `iec104`, with
  entry points in `src/fuzz_api.rs` (built only with `--cfg fuzzing`) and
  `fuzz/make-seeds.py` to seed them from the test captures. About 110 million
  executions found no crashes. CI fuzzes each target for 60 seconds on
  pushes to `main`, weekly and on demand.
- Release workflow (`.github/workflows/release.yml`): pushing a `v*` tag
  checks the tag against the crate version, builds on Ubuntu 22.04, runs the
  unit and suricata-verify tests as a gate, and publishes a GitHub release
  with the library, rules, docs and SHA-256 checksums, using the matching
  CHANGELOG section as release notes.
- CI job that builds the Docker image and smoke-tests it on S7comm,
  IEC-104 and MMS captures.
- MMS app-layer parser (`mms`, TCP/102) in the same plugin, for IEC 61850
  client/server traffic and ICCP / TASE.2: COTP DT reassembly, ISO 8327
  session, ISO 8823 presentation, ACSE and MMS decoding with `der-parser`
  (the same version as Suricata 8.0.x). Requests and responses are paired by
  invoke ID; the association is logged with application context, AP titles,
  authentication mechanism and the negotiated MMS parameters (never the
  password). Detects IEC 61850 controls and setting writes, data set changes,
  ICCP transfer set configuration (names learned from `Next_DSTransfer_Set`
  reads), program control, domain download/upload, deletions and file
  transfer, with ATT&CK-ICS mapping. 7 detection keywords (`mms.pdu_type`,
  `mms.service`, `mms.dangerous`, `mms.iccp_transfer_set`, and the
  `mms.domain`/`mms.item`/`mms.filename` multi-buffers), the `mms.pdu` frame,
  EVE `mms` logging, anomaly events, `rules/mms.rules` (SIDs
  3702001-3702303) and `doc/mms-keywords.rst`. Config:
  `app-layer.protocols.mms.max-tx` and `max-message-size`. At `max-tx` live
  transactions, pending requests are closed and parsing of the flow
  continues, so unanswered requests cannot switch off inspection.
- `CotpReassembler` in the shared `cotp` module: joins COTP DT segments
  (EOT flag) into complete messages, with a size limit.
- MMS carried directly on COTP (reduced stack, without the ISO session,
  presentation and ACSE layers) is detected and decoded, as used by some MMS
  tools and scanners. A malformed TPKT frame is now reported as
  `malformed_pdu` without disabling MMS inspection of the rest of the flow.
  `scripts/gen-mms-reduced-stack-pcap.py` and the `mms-reduced-stack` test
  cover it.
- suricata-verify tests `mms-iec61850-control`, `mms-iccp`, `mms-dataset`,
  `mms-file-segmented`, `mms-max-message-size` and `mms-auth`, and
  `scripts/gen-mms-pcaps.sh`, which generates their captures with
  libIEC61850 at a pinned commit.
- IEC 60870-5-104 app-layer parser (`iec104`, TCP/2404) in the same plugin:
  APCI I/S/U framing, ASDU header, IOA extraction, command/setpoint decoding
  (select/execute, state, value), N(S) continuity tracking, 7 detection
  keywords plus the `iec104.data` sticky buffer, `iec104.pdu`/`iec104.asdu`
  frames, EVE `iec104` logging with ATT&CK-ICS mapping, anomaly events, and
  `rules/iec104.rules` (SIDs 3701001-3701308).
- suricata-verify pcap tests for IEC-104: `iec104-commands` (control commands
  against the shipped `iec104.rules`) and `iec104-sq` (SQ=1 ASDUs). They load
  the plugin from `SURICATA_ICS_PLUGIN` and run with `--no-validation`.
- `scripts/gen-iec104-pcaps.py`: standard-library generator for synthetic
  IEC 60870-5-104 pcaps covering every rule in `rules/iec104.rules`.
- suricata-verify regression tests for TCP/102: `s7comm-split-pdu` (S7 PDU
  split across TCP segments) and `iso102-not-s7comm` (ISO session/MMS traffic
  is not labelled `s7comm`), with pcaps generated from `s7comm-write-var` by
  `scripts/gen-iso102-regress-pcaps.py`.
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

### Changed
- **Renamed the plugin library** from `libsuricata_s7comm.so` to
  `libsuricata_ics.so` (crate `suricata-ics-parsers`, plugin name
  `ics-parsers`), since it now carries S7comm, IEC 60870-5-104 and MMS.
  Update `plugins:` paths in `suricata.yaml`; `make install` also creates a
  `libsuricata_s7comm.so` compatibility symlink. App-layer protocol names,
  keywords, EVE types and rules are unchanged.
- TCP/102 flows whose first COTP DT carries an ISO 8327 session SPDU are now
  claimed by the `mms` parser (`app_proto: mms`) instead of ending as
  `failed`. The `iso102-not-s7comm` test expects this.
- TPKT/COTP handling for TCP/102 moved into a shared `cotp` module
  (`tpkt_frame()`, `parse_tpkt_cotp()`, `probe_iso102()`) so future ISO-stack
  parsers (MMS, IEC 61850, ICCP) can reuse it. The S7comm parser and both
  parsing directions now use it and reject non-TPKT data.
- S7comm protocol detection now looks past the COTP connection request/confirm
  to the first COTP DT payload and only claims the flow for S7comm (0x32) or
  S7comm-Plus (0x72). Other TCP/102 traffic (MMS, IEC 61850, ICCP) now ends as
  `app_proto: failed` instead of `s7comm`. Detection depth is now 512 bytes.
  A TCP/102 flow that only exchanges the COTP handshake, such as a scanner
  probing a PLC, is no longer labelled `s7comm`; no S7 transaction or alert
  was produced for these flows before either.

### Fixed
- Docker image: enable the `s7comm`, `iec104` and `mms` EVE record types
  (previously only alerts were logged), build with current stable Rust
  instead of the distro `rustc`, fail the build unless the plugin loads and
  logs MMS, and keep `pcap/` and `fuzz/` out of the build context.
- CI suricata-verify tests are now blocking.
- S7comm PDUs split across TCP segments no longer stop parsing for the flow.
  The parser reported the bytes still missing from `AppLayerResult::incomplete()`
  instead of the total PDU size, which Suricata treats as an internal error
  when more than about half the PDU had already arrived.
- The CI rustfmt check now actually checks the code. `cargo fmt` needs the
  generated `Cargo.toml`, so it always failed before reading any source and was
  marked non-blocking; CI now runs `rustfmt --check src/lib.rs` as a blocking
  check, and the crate has been formatted to pass it.
- suricata-verify tests now actually run: `s7comm-*` tests no longer use the
  unsupported `requires: plugins` and `min:` keys, load the plugin from
  `SURICATA_ICS_PLUGIN`, and enable EVE output in their configs. The
  `s7comm-write-var` Write Variable check now expects the four writes present
  in the capture. The CI verify step and README instructions no longer pass the
  non-existent `run.py --suricata` option.

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

[Unreleased]: https://github.com/LeargasSecurity/suricata-ics-parsers/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/LeargasSecurity/suricata-ics-parsers/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/LeargasSecurity/suricata-ics-parsers/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/LeargasSecurity/suricata-ics-parsers/releases/tag/v0.1.0
