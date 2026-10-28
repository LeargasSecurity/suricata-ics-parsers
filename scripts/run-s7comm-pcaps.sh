#!/usr/bin/env bash
#
# run-s7comm-pcaps.sh — Run Suricata with the S7comm parser plugin over every
# pcap in a directory (default /mnt/pcap) and summarize S7comm findings.
#
# Runs once by default, or loops as a watcher when INTERVAL is set.
#
# Copyright (C) 2026 Leargas Security. License: GPL-2.0
#
# Usage:
#   scripts/run-s7comm-pcaps.sh [PCAP_DIR] [RESULTS_DIR]
#
# Defaults:
#   PCAP_DIR     /mnt/pcap
#   RESULTS_DIR  $HOME/s7comm-results
#
# Environment overrides:
#   INTERVAL     seconds between passes. 0 = run once (default). >0 = loop.
#   REPROCESS    1 = reprocess every pcap each pass (replay mode).
#                0 = skip pcaps already processed at this size/mtime (default).
#   SURICATA     path to the suricata binary (default: suricata on PATH)
#   PLUGIN       path to libsuricata_ics.so (default: auto-detect)

set -uo pipefail

PCAP_DIR="${1:-/mnt/pcap}"
RESULTS_DIR="${2:-$HOME/s7comm-results}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SURICATA="${SURICATA:-suricata}"
INTERVAL="${INTERVAL:-0}"
REPROCESS="${REPROCESS:-0}"

# --- locate the plugin: prefer a freshly built one, fall back to installed ---
if [[ -n "${PLUGIN:-}" && -f "${PLUGIN:-}" ]]; then
    :
else
    # Fresh build first, then installed; libsuricata_s7comm.so is the pre-rename name.
    for candidate in "$REPO_DIR/target/release/libsuricata_ics.so" \
                     /usr/local/lib/suricata/plugins/libsuricata_ics.so \
                     /usr/local/lib/suricata/plugins/libsuricata_s7comm.so; do
        if [[ -f "$candidate" ]]; then
            PLUGIN="$candidate"
            break
        fi
    done
fi
if [[ -z "${PLUGIN:-}" || ! -f "${PLUGIN:-}" ]]; then
    echo "ERROR: could not find libsuricata_ics.so (build it or set \$PLUGIN)" >&2
    exit 1
fi

command -v "$SURICATA" >/dev/null 2>&1 || { echo "ERROR: suricata not found (set \$SURICATA)" >&2; exit 1; }

RULES_DIR="$REPO_DIR/rules"
[[ -f "$RULES_DIR/s7comm.rules" ]] || { echo "ERROR: $RULES_DIR/s7comm.rules not found" >&2; exit 1; }

mkdir -p "$RESULTS_DIR"
STATE_FILE="$RESULTS_DIR/.processed"
touch "$STATE_FILE"

# --- generate a self-contained Suricata config for the batch run ---
CFG="$RESULTS_DIR/suricata.yaml"
CLASS_FILE="/usr/local/etc/suricata/classification.config"
cat > "$CFG" <<EOF
%YAML 1.1
---
plugins:
  - $PLUGIN

# Sample captures are often mid-stream (no TCP handshake); enable midstream.
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

# Count S7comm alerts (sid >= 3700000) in an eve.json.
count_alerts() {
    python3 - "$1" <<'PY' 2>/dev/null
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
}

# Process every pcap once. Honors REPROCESS / state file for skipping.
run_pass() {
    shopt -s nullglob
    local pcaps=("$PCAP_DIR"/*.pcap "$PCAP_DIR"/*.pcapng)
    if (( ${#pcaps[@]} == 0 )); then
        echo "[$(date '+%F %T')] no .pcap/.pcapng files in $PCAP_DIR"
        return
    fi

    echo "[$(date '+%F %T')] pass over ${#pcaps[@]} pcap(s) in $PCAP_DIR"
    printf '%-42s %8s %8s %8s  %s\n' "PCAP" "PKTS" "S7LOGS" "ALERTS" "STATUS"
    printf '%.0s-' {1..88}; echo

    local total_logs=0 total_alerts=0 applicable=0 processed=0 skipped=0
    for pcap in "${pcaps[@]}"; do
        local name sig out
        name="$(basename "$pcap")"
        sig="$name|$(stat -c '%s:%Y' "$pcap" 2>/dev/null)"

        if [[ "$REPROCESS" != "1" ]] && grep -qxF "$sig" "$STATE_FILE" 2>/dev/null; then
            printf '%-42s %8s %8s %8s  %s\n' "$name" "-" "-" "-" "skip (done)"
            skipped=$((skipped + 1))
            continue
        fi

        out="$RESULTS_DIR/${name%.*}"
        mkdir -p "$out"
        # Clear prior output so counts reflect this pass (Suricata appends to eve.json).
        rm -f "$out/eve.json"
        "$SURICATA" -c "$CFG" -r "$pcap" -l "$out" -k none >"$out/run.log" 2>&1

        local pkts s7logs alerts
        pkts=$(grep -oE 'read 1 file, [0-9]+ packets' "$out/run.log" 2>/dev/null \
               | grep -oE '[0-9]+ packets' | grep -oE '[0-9]+' | head -1)
        [[ -z "${pkts:-}" ]] && pkts="?"
        s7logs=$(grep -c '"event_type":"s7comm"' "$out/eve.json" 2>/dev/null)
        [[ -z "${s7logs:-}" ]] && s7logs=0
        alerts=$(count_alerts "$out/eve.json"); [[ -z "${alerts:-}" ]] && alerts=0

        local status
        if [[ "$s7logs" -gt 0 ]]; then status="s7comm"; applicable=$((applicable + 1)); else status="no s7comm"; fi
        printf '%-42s %8s %8s %8s  %s\n' "$name" "$pkts" "$s7logs" "$alerts" "$status"

        # Record as processed (replace any prior entry for this name).
        grep -vF "$name|" "$STATE_FILE" > "$STATE_FILE.tmp" 2>/dev/null || true
        mv "$STATE_FILE.tmp" "$STATE_FILE" 2>/dev/null || true
        echo "$sig" >> "$STATE_FILE"

        total_logs=$((total_logs + s7logs))
        total_alerts=$((total_alerts + alerts))
        processed=$((processed + 1))
    done

    printf '%.0s-' {1..88}; echo
    printf 'processed %d, skipped %d, %d with S7comm | S7LOGS %d  ALERTS %d\n' \
        "$processed" "$skipped" "$applicable" "$total_logs" "$total_alerts"
    echo
}

echo "Plugin:  $PLUGIN"
echo "Config:  $CFG"
echo "Results: $RESULTS_DIR"
if [[ "$INTERVAL" -gt 0 ]]; then
    echo "Mode:    loop every ${INTERVAL}s (REPROCESS=$REPROCESS) — Ctrl-C to stop"
else
    echo "Mode:    single pass"
fi
echo

if [[ "$INTERVAL" -gt 0 ]]; then
    trap 'echo; echo "stopped."; exit 0' INT TERM
    while true; do
        run_pass
        sleep "$INTERVAL"
    done
else
    run_pass
    echo "Per-pcap EVE logs and run logs are under: $RESULTS_DIR"
fi
