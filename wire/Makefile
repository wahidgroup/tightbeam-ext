# wire extension targets: the envelope rules that every message-oriented
# socket transport shares. Invoked directly (make -C wire <target>) or through
# the repo root Makefile (make test wire).

.PHONY: setup check build test lint wasm client sbom smoke pack

REPO := ..
CRATES := -p tightbeam-wire

CARGO_FLAGS := $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

ifneq ($(filter 1,$(fix)),)
LINT_MODE := fix
else
LINT_MODE := check
endif

setup:
	@$(REPO)/scripts/setup.sh wire

check:
	@echo "Checking wire crates..."
	cargo check $(CRATES) --all-targets $(CARGO_FLAGS)

build:
	@echo "Building wire crates..."
	cargo build --release $(CRATES) $(CARGO_FLAGS)

# The crate holds no socket kind, so the io tests of tightbeam-ws run its rules
# against a real peer.
test: setup
	@echo "Running wire cargo tests..."
	cargo test $(CRATES) $(CARGO_FLAGS)
	@echo "Running the ws io tests, which run the wire rules against a real peer..."
	cargo test -p tightbeam-ws --lib io::

lint: setup
	@echo "Linting wire (mode: $(LINT_MODE))..."
ifeq ($(LINT_MODE),fix)
	cargo fmt $(CRATES)
	cargo clippy $(CRATES) --all-targets
else
	cargo fmt $(CRATES) --check
	cargo clippy $(CRATES) --all-targets -- -D warnings
endif

# A wasm32 build needs the random source that the crate linking it selects, so
# the browser engine of ws proves this crate for wasm32.
wasm:
	@$(MAKE) -C $(REPO)/ws wasm

client:
	@echo "wire has no npm client; nothing to do."

sbom:
	@echo "wire publishes no SBOM; nothing to do."

smoke:
	@echo "wire has no npm client; nothing to do."

pack:
	@echo "wire has no npm client; nothing to do."
