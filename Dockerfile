# Multi-stage build: compiles Suricata 8.0.x and the S7comm plugin, then ships a
# slim runtime image with Suricata + the plugin + rules preinstalled.
#
#   docker build -t suricata-s7comm .
#   docker run --rm -v "$PWD:/data" suricata-s7comm -r /data/capture.pcap -l /data/out -k none
#   docker run --rm --net=host suricata-s7comm -i eth0 -k none

ARG SURICATA_VERSION=8.0.6

# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS builder
ARG SURICATA_VERSION
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf automake libtool pkg-config curl ca-certificates \
        libpcre2-dev libyaml-dev libjansson-dev libcap-ng-dev libmagic-dev \
        libnet1-dev libpcap-dev zlib1g-dev libnss3-dev libnspr4-dev liblz4-dev \
        rustc cargo \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install --force cbindgen && cp "$HOME/.cargo/bin/cbindgen" /usr/local/bin/

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

# Enable the plugin, the s7comm app-layer, and eve s7comm logging in the config.
RUN CONF=/usr/local/etc/suricata/suricata.yaml \
    && printf '\n# --- S7comm plugin (added at image build) ---\nplugins:\n  - /usr/local/lib/suricata/plugins/libsuricata_s7comm.so\n' >> "$CONF" \
    && sed -i 's#^rule-files:#rule-files:\n  - s7comm.rules\n  - iec104.rules\n  - mms.rules#' "$CONF" || true

# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcre2-8-0 libyaml-0-2 libjansson4 libcap-ng0 libmagic1 \
        libnet1 libpcap0.8 zlib1g libnss3 libnspr4 liblz4-1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local /usr/local
RUN ldconfig

# Basic sanity check that the plugin loads.
RUN /usr/local/bin/suricata --build-info >/dev/null 2>&1 || true

ENTRYPOINT ["/usr/local/bin/suricata", "-c", "/usr/local/etc/suricata/suricata.yaml"]
CMD ["--build-info"]
