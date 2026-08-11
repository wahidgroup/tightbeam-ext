# asn extension targets: DER codec crates for TypeScript MessageCodec façades.
# Invoked directly (make -C asn <target>) or through the repo root Makefile
# (make test asn).

.PHONY: setup check build test lint wasm client sbom smoke pack

REPO := ..
CRATES := -p tightbeam-asn -p tightbeam-asn-derive

CARGO_FLAGS := $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

ifneq ($(filter 1,$(fix)),)
LINT_MODE := fix
else
LINT_MODE := check
endif

setup:
	@$(REPO)/scripts/setup.sh asn

check:
	@echo "Checking asn crates..."
	cargo check $(CRATES) --all-targets $(CARGO_FLAGS)

build:
	@echo "Building asn crates..."
	cargo build --release $(CRATES) $(CARGO_FLAGS)

test: setup
	@echo "Running asn cargo tests..."
ifeq ($(strip $(features)$(no-default)),)
	cargo test $(CRATES) --all-features
else
	cargo test $(CRATES) $(CARGO_FLAGS)
endif
	@echo "Running asn vitest emit integration..."
	npm run test
	@echo "Running asn wasm32 JS round-trip tests..."
	CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
		cargo test -p tightbeam-asn --features wasm --target wasm32-unknown-unknown --test wasm_js_roundtrip

lint: setup
	@echo "Linting asn (mode: $(LINT_MODE))..."
ifeq ($(LINT_MODE),fix)
	cargo fmt $(CRATES)
	cargo clippy $(CRATES) --all-targets --all-features
	npm run lint:fix
else
	cargo fmt $(CRATES) --check
	cargo clippy $(CRATES) --all-targets --all-features -- -D warnings
	npm run lint
endif

wasm:
	@echo "asn has no product wasm crate; nothing to do."

client:
	@echo "asn has no npm client; nothing to do."

sbom:
	@echo "asn publishes no SBOM; nothing to do."

smoke:
	@echo "asn has no npm client; nothing to do."

pack:
	@echo "asn has no npm client; nothing to do."
