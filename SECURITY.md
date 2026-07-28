# Security Policy

## Supported versions

This project distributes a Suricata **8.0.x** application-layer plugin ahead of
Suricata mainline inclusion. Security fixes are applied to the latest release on
the `main` branch. Older tagged releases are not maintained.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately using **GitHub's private vulnerability reporting** for this
repository:

1. Go to the **Security** tab → **Report a vulnerability**.
2. Provide a description, affected version/commit, reproduction steps, and a
   PCAP or input sample if applicable.

Alternatively, email the maintainers at **security@leargas.io**
(update this address to your organization's monitored security contact).

Please include enough detail to reproduce:

- Suricata version and how the plugin was built (`SURICATA_SRC`, OS).
- The offending input (a minimal PCAP is ideal).
- Observed vs. expected behavior (crash, hang, memory growth, parser
  desync, false negative on a dangerous operation, etc.).

## Scope

Because this parser processes **untrusted network input**, we are especially
interested in:

- Panics, crashes, or unbounded memory/CPU on malformed S7comm/COTP/TPKT input.
- Parser desynchronization that could be used to evade detection.
- Bypasses of the `dangerous`/write/download/upload detection logic.

## Disclosure

We aim to acknowledge reports within a few business days and will coordinate a
fix and disclosure timeline with the reporter. Please give us a reasonable
window to remediate before any public disclosure.
