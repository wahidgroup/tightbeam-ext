# ws extension targets: WebSocket transport crates and the hybrid TS/wasm
# client. Invoked directly (make -C ws <target>) or through the repo root
# Makefile, which scopes targets by project (make test ws).

.PHONY: setup check build test lint wasm client sbom smoke pack

REPO := ..
CRATES := -p tightbeam-ws -p tightbeam-ws-wasm

# Browser client target: only compiled for wasm32, so the host-target
# lint/test steps never exercise it. `make wasm` guards it explicitly.
WASM_TARGET := wasm32-unknown-unknown
WASM_CRATE := tightbeam-ws-wasm

# Cargo feature passthroughs (e.g., `make test ws features="testing"`).
CARGO_FLAGS := $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

ifneq ($(filter 1,$(fix)),)
LINT_MODE := fix
else
LINT_MODE := check
endif

# Local `make test` skips wasm-opt (~1m per target). `make ci` passes
# wasm_opt=1 so the suite still builds release-sized wasm.
ifneq ($(filter 1,$(wasm_opt)),)
TEST_WASM_PACK_FLAGS :=
else
TEST_WASM_PACK_FLAGS := --no-opt
endif

setup:
	@$(REPO)/scripts/setup.sh ws

check:
	@echo "Checking ws crates..."
	cargo check $(CRATES) --all-targets $(CARGO_FLAGS)

build:
	@echo "Building ws crates..."
	cargo build --release $(CRATES) $(CARGO_FLAGS)

test: setup
	@$(MAKE) client WASM_PACK_FLAGS="$(TEST_WASM_PACK_FLAGS)"
	@echo "Running ws cargo tests..."
ifeq ($(strip $(features)$(no-default)),)
	cargo test $(CRATES) --all-features
else
	cargo test $(CRATES) $(CARGO_FLAGS)
endif
	@echo "Running ws TS unit tests (vitest)..."
	npm run test

lint: setup
	@echo "Linting ws (mode: $(LINT_MODE))..."
ifeq ($(LINT_MODE),fix)
	cargo fmt $(CRATES)
	cargo clippy $(CRATES) --all-targets --all-features
	npm run lint:fix
else
	cargo fmt $(CRATES) --check
	cargo clippy $(CRATES) --all-targets --all-features -- -D warnings
	npm run lint
endif

wasm: setup
	@echo "Linting and building $(WASM_CRATE) for $(WASM_TARGET)..."
	cargo clippy -p $(WASM_CRATE) --target $(WASM_TARGET) -- -D warnings
	cargo build -p $(WASM_CRATE) --target $(WASM_TARGET)

client: setup
	@echo "Building the ws TS/wasm client package..."
	WASM_PACK_FLAGS="$(WASM_PACK_FLAGS)" npm run build

sbom: setup
	@echo "Generating the ws client SBOM..."
	npm run sbom

smoke: setup
	@echo "Smoking built ws client exports..."
	@test -f client/dist/index.js || (echo "client dist missing - run make client first"; exit 1)
	cd client && npm run smoke

pack: sbom
	@echo "Checking ws npm pack contents..."
	@test -f client/dist/index.js || (echo "client dist missing - run make client first"; exit 1)
	cd client && npm run pack:check
