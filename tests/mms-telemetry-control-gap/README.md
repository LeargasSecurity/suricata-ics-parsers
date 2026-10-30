# mms-telemetry-control-gap

Missing-telemetry visibility: data lost from an MMS flow must be reported as
lost, so it is not mistaken for normal inactivity.

## Purpose
- An IEC 61850 control (Operate write) is missing, as after a capture drop.
- The gap gets its own `mms` record (`telemetry.reason: stream_gap`) and a
  `stream_gap` event.
- The control's reply is marked `telemetry.missing: request` with an
  `orphan_response` event. It carries no `is_dangerous` flag, because danger
  is unknown when the request was not seen.

## PCAP
`tests/mms-iec61850-control/input.pcap` with frame 14 removed:

    editcap tests/mms-iec61850-control/input.pcap tests/mms-telemetry-control-gap/input.pcap 14
