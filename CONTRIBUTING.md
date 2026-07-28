# Contributing to suricata-ics-parsers

Thanks for your interest in improving the Suricata S7comm ICS parser. This
project is maintained by **Leargas Security** and released under **GPL-2.0**
(matching Suricata, which the plugin links against).

## Ground rules

- By contributing, you agree your work is licensed under **GPL-2.0**.
- Be respectful — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- This plugin is an **out-of-tree** distribution ahead of Suricata mainline
  inclusion. It is **not affiliated with or endorsed by OISF**.

## Development setup

The plugin links against the Rust crates that ship with a matching **Suricata
8.0.x** source tree.

```bash
# 1. Obtain and build a matching Suricata source tree (see README).
# 2. Build the plugin against it:
make build SURICATA_SRC=/path/to/suricata-8.0.6
make test  SURICATA_SRC=/path/to/suricata-8.0.6
```

`Cargo.toml` is generated from `Cargo.toml.in` by `make configure`; never edit
the generated `Cargo.toml` directly.

## Before you open a PR

- [ ] `cargo fmt --all` is clean.
- [ ] `make test` passes (Rust unit tests).
- [ ] New protocol behavior has a **suricata-verify** test under `tests/`
      (a PCAP, `test.rules`, and output assertions) — see existing tests as a
      template.
- [ ] New detection keywords / EVE fields are documented in
      `doc/s7comm-keywords.rst` and the README tables.
- [ ] New rules use a SID in the project range (`3700000`–`3700999`) and carry
      an ATT&CK-ICS reference where applicable.
- [ ] Commit messages are descriptive; reference an issue where relevant.

## Reporting bugs / requesting features

Use the GitHub issue templates. For anything security-sensitive, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## Adding a new protocol parser

Each parser should be a self-contained plugin crate following the same layout
(parser + keywords + logger + rules + docs + suricata-verify tests). Open an
issue first so we can align on scope and naming.
