# Suricata S7comm plugin — build & packaging helper
#
# The plugin links against the Suricata Rust crates that ship with the matching
# Suricata source tree. Point SURICATA_SRC at that tree (the directory that
# contains `rust/`), then use the targets below. Cargo.toml is generated from
# Cargo.toml.in so the build works regardless of where Suricata lives.
#
#   make build                 # build against $SURICATA_SRC (default below)
#   make build SURICATA_SRC=/opt/suricata-8.0.6
#   make test                  # cargo unit tests
#   make install               # install the .so and rules (needs sudo)
#   make clean

# Path to the Suricata 8.0.x source tree (must contain rust/ and rust/sys/).
SURICATA_SRC ?= $(HOME)/suricata-8.0.6

# Derived path to the Rust crates inside the Suricata source tree.
SURICATA_RUST := $(abspath $(SURICATA_SRC)/rust)

PLUGIN_SO   := target/release/libsuricata_s7comm.so
PLUGIN_DIR  ?= /usr/local/lib/suricata/plugins
RULES_DIR   ?= /usr/local/var/lib/suricata/rules

.PHONY: all configure build test install clean check-suricata

all: build

check-suricata:
	@test -d "$(SURICATA_RUST)" || { \
	  echo "ERROR: Suricata Rust crates not found at $(SURICATA_RUST)"; \
	  echo "       Set SURICATA_SRC to your Suricata 8.0.x source tree, e.g.:"; \
	  echo "       make build SURICATA_SRC=/opt/suricata-8.0.6"; \
	  exit 1; }

# Generate Cargo.toml from the template with the resolved Suricata crate path.
configure: check-suricata Cargo.toml.in
	@sed 's#@SURICATA_RUST@#$(SURICATA_RUST)#g' Cargo.toml.in > Cargo.toml
	@echo "Generated Cargo.toml (suricata crates: $(SURICATA_RUST))"

build: configure
	cargo build --release
	@echo "Built $(PLUGIN_SO)"

test: configure
	cargo test --release

install: build
	install -d "$(PLUGIN_DIR)"
	install -m 0644 "$(PLUGIN_SO)" "$(PLUGIN_DIR)/"
	install -d "$(RULES_DIR)"
	install -m 0644 rules/s7comm.rules rules/iec104.rules rules/mms.rules "$(RULES_DIR)/"
	@echo "Installed plugin to $(PLUGIN_DIR) and rules to $(RULES_DIR)"

clean:
	cargo clean || true
	rm -f Cargo.toml
