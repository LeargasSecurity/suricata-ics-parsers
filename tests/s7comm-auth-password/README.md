# s7comm-auth-password

Tests detection of S7comm security/password-protection access, Read SZL
reconnaissance, and the `frame` keyword.

## Purpose
- Verify the Security userdata group (5) is parsed and flagged dangerous with
  the correct ATT&CK mapping (T0859 / T0812).
- Verify Read SZL (CPU Functions group 4, subfunction 1) reconnaissance.
- Verify frame registration by matching content within the `s7comm.pdu` frame.

## PCAP
`step7_s300_AuthPassword.pcapng` — STEP7 Manager authenticating with a password
against an S7-300 PLC. Sourced from https://github.com/gymgit/s7-pcaps
(IPs randomized by the author). This is a mid-stream capture, so the test
enables `stream.midstream`.
