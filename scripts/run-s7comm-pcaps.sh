#!/usr/bin/env bash
#
# run-s7comm-pcaps.sh — Batch-run Suricata with the S7comm parser plugin over
# every pcap in a directory (default /mnt/pcap) and summarize S7comm findings.
#
# Copyright (C) 2026 Leargas Security. License: GPL-2.0
#
# Usage:
#   scripts/run-s7comm-pcaps.sh [PCAP_DIR] [RESULTS_DIR]
#
# Defaults:
#   PCAP_DIR     /mnt/pcap
#   RESULTS_DIR  $HOME/s7comm-results/<timestamp>
#
# Environment overrides:
#   SURICATA     path to the suricata binary (default: suricata on PATH)
#   PLUGIN       path to libsuricata_s7comm.so (default: auto-detect)

set -uo pipefail

PCAP_DIR="${1:-/mnt/pcap}"
RESULTS_DIR="${2:-$HOME/s7comm-results/$(date +%Y%m%d-%H%M%S)}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SURICATA="${SURICATA:-suricata}"

# --- locate the plugin: prefer a freshly built one, fall back to installed ---
if [[ -n "${PLUGIN:-}" && -f "${PLUGIN:-}" ]]; then
    :
elif [[ -f "$REPO_DIR/target/release/libsuricata_s7comm.so" ]]; then
    PLUGIN="$REPO_DIR/target/release/libsuricata_s7comm.so"
elif [[ -f /usr/local/lib/suricata/plugins/libsuricata_s7comm.so ]]; then
    PLUGIN="/usr/local/lib/suricata/plugins/libsuricata_s7comm.so"
else
    echo "ERROR: could not find libsuricata_s7comm.so (build it or set \$PLUGIN)" >&2
    exit 1
fi

if ! command -v "$SURICATA" >/dev/null 2>&1; then
    echo "ERROR: suricata binary not found (set \$SURICATA)" >&2
    exit 1
fi

RULES_DIR="$REPO_DIR/rules"
if [[ ! -f "$RULES_DIR/s7comm.rules" ]]; then
    echo "ERROR: $RULES_DIR/s7comm.rules not found" >&2
    exit 1
fi

mkdir -p "$RESULTS_DIR"

# --- generate a self-contained Suricata config for the batch run ---
CFG="$RESULTS_DIR/suricata.yaml"
CLASS_FILE="/usr/local/etc/suricata/classification.config"
cat > "$CFG" <<EOF
%YAML 1.1
---
plugins:
  - $PLUGIN

# The gymgit/wireshark sample captures are mid-stream (no TCP handshake),
# so enable midstream pickup to parse them.
stream:
  midstream: true

app-layer:
  protocols:
    s7comm:
      enabled: yes
      detection-ports:
        dp: 102

default-rule-path: $RULES_DIR
rule-files:
  - s7comm.rules

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - s7comm
        - alert
        - anomaly
        - flow
EOF
[[ -r "$CLASS_FILE" ]] && echo "classification-file: $CLASS_FILE" >> "$CFG"

# --- gather pcaps ---
shopt -s nullglob
pcaps=("$PCAP_DIR"/*.pcap "$PCAP_DIR"/*.pcapng)
if (( ${#pcaps[@]} == 0 )); then
    echo "No .pcap/.pcapng files found in $PCAP_DIR" >&2
    exit 0
fi

echo "Plugin:  $PLUGIN"
echo "Config:  $CFG"
echo "Results: $RESULTS_DIR"
echo
printf '%-42s %8s %8s %8s  %s\n' "PCAP" "PKTS" "S7LOGS" "ALERTS" "STATUS"
printf '%.0s-' {1..88}; echo

total_logs=0; total_alerts=0; applicable=0
for pcap in "${pcaps[@]}"; do
    name="$(basename "$pcap")"
    out="$RESULTS_DIR/${name%.*}"
    mkdir -p "$out"

    "$SURICATA" -c "$CFG" -r "$pcap" -l "$out" -k none >"$out/run.log" 2>&1

    pkts=$(grep -oE 'read 1 file, [0-9]+ packets' "$out/run.log" 2>/dev/null \
           | grep -oE '[0-9]+ packets' | grep -oE '[0-9]+' | head -1)
    [[ -z "${pkts:-}" ]] && pkts="?"

    s7logs=$(grep -c '"event_type":"s7comm"' "$out/eve.json" 2>/dev/null)
    [[ -z "${s7logs:-}" ]] && s7logs=0

    alerts=$(python3 - "$out/eve.json" <<'PY' 2>/dev/null
import sys, json
c = 0
try:
    for line in open(sys.argv[1]):
        o = json.loads(line)
        if o.get("event_type") == "alert" and o.get("alert", {}).get("signature_id", 0) >= 3700000:
            c += 1
except Exception:
    pass
print(c)
PY
)
    [[ -z "${alerts:-}" ]] && alerts=0

    if [[ "$s7logs" -gt 0 ]]; then
        status="s7comm"
        applicable=$((applicable + 1))
    else
        status="no s7comm"
    fi

    printf '%-42s %8s %8s %8s  %s\n' "$name" "$pkts" "$s7logs" "$alerts" "$status"
    total_logs=$((total_logs + s7logs))
    total_alerts=$((total_alerts + alerts))
done

printf '%.0s-' {1..88}; echo
printf '%-42s %8s %8s %8s\n' \
    "TOTAL: ${#pcaps[@]} pcaps ($applicable with S7comm)" "" "$total_logs" "$total_alerts"
echo
echo "Per-pcap EVE logs and run logs are under: $RESULTS_DIR"
