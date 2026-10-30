# mms-telemetry-segment-gap

Missing-telemetry visibility: data lost from an MMS flow must be reported as
lost, so it is not mistaken for normal inactivity.

## Purpose
- One COTP DT segment of a large, segmented FileRead response is missing.
- The remainder of the cut message is reported as gap loss (no
  `malformed_pdu`), and the request is marked `telemetry.missing: response`
  with `reason: stream_gap`.

## PCAP
`tests/mms-file-segmented/input.pcap` with frame 13 removed:

    editcap tests/mms-file-segmented/input.pcap tests/mms-telemetry-segment-gap/input.pcap 13
