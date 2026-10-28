#!/usr/bin/env bash
#
# gen-mms-pcaps.sh — Generate MMS / IEC 61850 test captures with libIEC61850.
#
# Builds the libIEC61850 example servers and clients at a pinned commit, runs
# each scenario against a server bound to 127.0.0.1:102, and records the
# loopback traffic with tcpdump. Used to (re)create the input.pcap files of
# the tests/mms-* suricata-verify tests.
#
# Copyright (C) 2026 Leargas Security. License: GPL-2.0
#
# Usage:
#   scripts/gen-mms-pcaps.sh [OUT_DIR]        # default: ./mms-pcaps
#
# Environment overrides:
#   LIBIEC61850_DIR   checkout/build directory (default: $HOME/src/libiec61850)
#
# Requirements: git, cmake, a C compiler, tcpdump, and sudo for tcpdump and
# for granting the example servers cap_net_bind_service (so they can bind
# port 102 without running as root). Port 102 on 127.0.0.1 must be free.
#
# Two small patches are applied to the examples: servers listen on 127.0.0.1
# only, and client_example5 takes the password as an optional third argument.

set -euo pipefail

LIBIEC61850_REPO="https://github.com/mz-automation/libiec61850.git"
LIBIEC61850_COMMIT="6e265c54af66ea686453b6d31c4dcce1cf7ad2bd"
SRC="${LIBIEC61850_DIR:-$HOME/src/libiec61850}"
OUT="$(mkdir -p "${1:-mms-pcaps}" && cd "${1:-mms-pcaps}" && pwd)"
EX="$SRC/build/examples"
SERVERS=(server_example_basic_io server_example_control server_example_files
         server_example_password_auth)

for tool in git cmake make tcpdump sudo ss; do
    command -v "$tool" >/dev/null || { echo "ERROR: $tool not found" >&2; exit 1; }
done
if ss -ltn | grep -qE '127\.0\.0\.1:102 |\*:102 |0\.0\.0\.0:102 '; then
    echo "ERROR: port 102 is already in use" >&2
    exit 1
fi

# --- build libIEC61850 at the pinned commit, with the two example patches ---
if [[ ! -d "$SRC/.git" ]]; then
    git clone -q "$LIBIEC61850_REPO" "$SRC"
fi
git -C "$SRC" fetch -q origin "$LIBIEC61850_COMMIT" 2>/dev/null || true
git -C "$SRC" checkout -q -f "$LIBIEC61850_COMMIT"

for s in "${SERVERS[@]}"; do
    f="$SRC/examples/$s/$s.c"
    grep -q setLocalIpAddress "$f" || sed -i \
        's|^\(\s*\)IedServer_start(iedServer, tcpPort);|\1IedServer_setLocalIpAddress(iedServer, "127.0.0.1");\n&|' "$f"
done
sed -i 's|    char\* password = "user1@testpw";|    char* password = (argc > 3) ? argv[3] : "user1@testpw";|' \
    "$SRC/examples/iec61850_client_example5/client_example5.c"

cmake -S "$SRC" -B "$SRC/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_EXAMPLES=ON >/dev/null
make -C "$SRC/build" -j"$(nproc)" "${SERVERS[@]}" iec61850_client_example1 \
    iec61850_client_example4 iec61850_client_example5 client_example_control \
    file-tool mms_utility >/dev/null

for s in "${SERVERS[@]}"; do
    sudo setcap cap_net_bind_service=+ep "$EX/$s/$s"
done

# 20 KB deterministic file: one FileRead response, split across several COTP DTs.
mkdir -p "$EX/server_example_files/vmd-filestore"
python3 -c "import sys; sys.stdout.buffer.write(bytes((i * 7 + 3) & 0xff for i in range(20000)))" \
    > "$EX/server_example_files/vmd-filestore/firmware.bin"

# capture NAME SERVER -- CLIENT_CMD...
capture() {
    local name=$1 server=$2
    shift 3
    local pcap="$OUT/$name.pcap"
    (cd "$EX/$server" && exec "./$server" >/dev/null 2>&1) &
    local spid=$!
    for _ in $(seq 40); do
        ss -ltn | grep -q '127.0.0.1:102 ' && break
        sleep 0.25
    done
    sudo tcpdump -i lo -U -s 0 -w "$pcap" 'tcp port 102' 2>/dev/null &
    local tpid=$!
    sleep 1
    (cd "$EX" && "$@") >/dev/null 2>&1 || true
    sleep 1
    sudo kill -INT $(pgrep -P "$tpid") "$tpid" 2>/dev/null || true
    kill -INT "$spid" 2>/dev/null || true
    wait 2>/dev/null || true
    sudo chown "$(id -u):$(id -g)" "$pcap"
    echo "wrote $pcap ($(tcpdump -nr "$pcap" 2>/dev/null | wc -l) packets)"
}

# IEC 61850 controls: select-before-operate and operate on GGIO1.SPCSOx
capture control server_example_control -- \
    timeout 30 iec61850_client_example_control/client_example_control localhost 102

# Data set (named variable list) define, read and delete
capture dataset server_example_basic_io -- \
    timeout 30 iec61850_client_example4/iec61850_client_example4 localhost 102

# File directory, open and a FileRead response segmented across COTP DTs
capture files server_example_files -- \
    timeout 30 iec61850_client_example_files/file-tool -h localhost get firmware.bin

# ACSE password authentication: accepted, then a wrong password (server closes)
capture auth server_example_password_auth -- bash -c \
    'c=iec61850_client_example5/iec61850_client_example5;
     timeout 4 $c localhost 102 user1@testpw; timeout 4 $c localhost 102 wrong-password; true'

# Reads, a write, report control block setup and reports
capture basic-io server_example_basic_io -- \
    timeout 10 iec61850_client_example1/iec61850_client_example1 localhost 102

# Identify, list domains, domain directory, read
capture browse server_example_basic_io -- bash -c \
    'm=mms_utility/mms_utility; $m -h localhost -i; $m -h localhost -d;
     $m -h localhost -t simpleIOGenericIO; $m -h localhost -a simpleIOGenericIO -r GGIO1\$MX\$AnIn1'
