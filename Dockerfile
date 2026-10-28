# Multi-stage build: compiles Suricata 8.0.x and the ICS parsers plugin
# (S7comm, IEC 60870-5-104, MMS), then ships a slim runtime image with
# Suricata + the plugin + rules preinstalled.
#
#   docker build -t suricata-ics .
#   docker run --rm -v "$PWD:/data" suricata-ics -r /data/capture.pcap -l /data/out -k none
#   docker run --rm --net=host suricata-ics -i eth0 -k none

ARG SURICATA_VERSION=8.0.6

# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS builder
ARG SURICATA_VERSION
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf automake libtool pkg-config curl ca-certificates \
        libpcre2-dev libyaml-dev libjansson-dev libcap-ng-dev libmagic-dev \
        libnet1-dev libpcap-dev zlib1g-dev libnss3-dev libnspr4-dev liblz4-dev \
    && rm -rf /var/lib/apt/lists/*

# Current stable Rust (the distro rustc can be older than the dependencies
# need; Cargo.lock is not committed, so the latest compatible crates resolve).
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && cargo install --force cbindgen

# Build and install Suricata.
WORKDIR /src
RUN curl -sSLO "https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz" \
    && tar xzf "suricata-${SURICATA_VERSION}.tar.gz"
WORKDIR /src/suricata-${SURICATA_VERSION}
RUN ./configure --prefix=/usr/local --enable-rust --disable-gccmarch-native \
    && make -j"$(nproc)" \
    && make install \
    && make install-conf \
    && ldconfig

# Build the plugin against the Suricata source tree.
WORKDIR /plugin
COPY . /plugin
RUN make build SURICATA_SRC="/src/suricata-${SURICATA_VERSION}" \
    && make install SURICATA_SRC="/src/suricata-${SURICATA_VERSION}" \
        PLUGIN_DIR=/usr/local/lib/suricata/plugins \
        RULES_DIR=/usr/local/var/lib/suricata/rules

# Enable the plugin, its rules and its EVE record types in the config.
RUN CONF=/usr/local/etc/suricata/suricata.yaml \
    && printf '\n# --- ICS parsers plugin (added at image build) ---\nplugins:\n  - /usr/local/lib/suricata/plugins/libsuricata_ics.so\n' >> "$CONF" \
    && sed -i 's#^rule-files:#rule-files:\n  - s7comm.rules\n  - iec104.rules\n  - mms.rules#' "$CONF" \
    && sed -i '0,/^      types:$/s//      types:\n        - s7comm\n        - iec104\n        - mms/' "$CONF" \
    && grep -q '^        - mms$' "$CONF"

# Fail the build unless the plugin loads, parses MMS and logs it.
RUN mkdir -p /tmp/smoke \
    && /usr/local/bin/suricata -c /usr/local/etc/suricata/suricata.yaml -k none \
        -r /plugin/tests/mms-reduced-stack/input.pcap -l /tmp/smoke \
    && grep -q '"event_type":"mms"' /tmp/smoke/eve.json \
    && grep -q '"signature_id":3702040' /tmp/smoke/eve.json \
    && rm -rf /tmp/smoke

# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcre2-8-0 libyaml-0-2 libjansson4 libcap-ng0 libmagic1 \
        libnet1 libpcap0.8 zlib1g libnss3 libnspr4 liblz4-1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local /usr/local
RUN ldconfig

ENTRYPOINT ["/usr/local/bin/suricata", "-c", "/usr/local/etc/suricata/suricata.yaml"]
CMD ["--build-info"]
