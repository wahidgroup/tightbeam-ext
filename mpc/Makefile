# mpc extension targets: the HoneyBadgerMPC network adapter crate.
# Invoked directly (make -C mpc <target>) or through the repo root
# Makefile, which scopes targets by project (make test mpc).

.PHONY: setup check build test lint wasm client sbom smoke pack

REPO := ..
CRATES := -p tightbeam-mpc -p tightbeam-vm

# Cargo feature passthroughs (e.g., `make test mpc features="testing"`).
CARGO_FLAGS := $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

ifneq ($(filter 1,$(fix)),)
LINT_MODE := fix
else
LINT_MODE := check
endif

setup:
	@$(REPO)/scripts/setup.sh mpc

check:
	@echo "Checking mpc crates..."
	cargo check $(CRATES) --all-targets $(CARGO_FLAGS)

build:
	@echo "Building mpc crates..."
	cargo build --release $(CRATES) $(CARGO_FLAGS)

test:
	@echo "Running mpc cargo tests..."
ifeq ($(strip $(features)$(no-default)),)
	cargo test $(CRATES) --all-features
else
	cargo test $(CRATES) $(CARGO_FLAGS)
endif

lint: setup
	@echo "Linting mpc (mode: $(LINT_MODE))..."
ifeq ($(LINT_MODE),fix)
	cargo fmt $(CRATES)
	cargo clippy $(CRATES) --all-targets --all-features
else
	cargo fmt $(CRATES) --check
	cargo clippy $(CRATES) --all-targets --all-features -- -D warnings
endif

wasm:
	@echo "mpc has no wasm crate; nothing to do."

client:
	@echo "mpc publishes no client package; nothing to do."

sbom:
	@echo "mpc publishes no SBOM; nothing to do."

smoke:
	@echo "mpc has no client package to smoke; nothing to do."

pack:
	@echo "mpc has no npm package to pack; nothing to do."
