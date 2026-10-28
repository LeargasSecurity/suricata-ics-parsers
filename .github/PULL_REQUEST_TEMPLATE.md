## Summary

<!-- What does this PR change and why? -->

## Type of change

- [ ] Bug fix
- [ ] New protocol coverage / keyword / EVE field
- [ ] New or updated detection rule(s)
- [ ] Build / CI / packaging
- [ ] Documentation

## Checklist

- [ ] `cargo fmt --all` is clean
- [ ] `make test` passes (Rust unit tests)
- [ ] Added/updated a **suricata-verify** test under `tests/` for behavior changes
- [ ] Updated the protocol's `doc/*-keywords.rst` and README tables for new keywords/fields
- [ ] New rules use the protocol's SID block (`3700xxx` S7comm, `3701xxx` IEC-104, `3702xxx` MMS; see CONTRIBUTING.md) with an ATT&CK-ICS reference
- [ ] I agree to license my contribution under **GPL-2.0**

## Testing notes

<!-- Suricata version, PCAPs used, sample EVE output / alerts. -->
