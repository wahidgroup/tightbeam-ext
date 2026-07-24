# pubsub extension targets: the topic registry crate and the subscription
# manager client. Invoked directly (make -C pubsub <target>) or through
# the repo root Makefile, which scopes targets by project (make test pubsub).

.PHONY: setup test lint wasm client sbom smoke pack

REPO := ..
CRATES := -p tightbeam-pubsub

# Cargo feature passthroughs (e.g., `make test pubsub features="testing"`).
CARGO_FLAGS := $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

ifneq ($(filter 1,$(fix)),)
LINT_MODE := fix
else
LINT_MODE := check
endif

setup:
	@$(REPO)/scripts/setup.sh pubsub

test: client
	@echo "Running pubsub cargo tests..."
ifeq ($(strip $(features)$(no-default)),)
	cargo test $(CRATES) --all-features
else
	cargo test $(CRATES) $(CARGO_FLAGS)
endif
	@echo "Running pubsub TS unit tests (vitest)..."
	npm run test

lint: setup
	@echo "Linting pubsub (mode: $(LINT_MODE))..."
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
	@echo "pubsub has no wasm crate; nothing to do."

client: setup
	@echo "Building the pubsub client package..."
	@# The pubsub client compiles against the ws client's dist (file: link).
	@$(MAKE) -C $(REPO)/ws client
	npm run build

sbom:
	@echo "pubsub publishes no SBOM; nothing to do."

smoke: setup
	@echo "Smoking built pubsub client exports..."
	@test -f client/dist/index.js || (echo "client dist missing - run make client first"; exit 1)
	cd client && npm run smoke

pack: setup
	@echo "Checking pubsub npm pack contents..."
	@test -f client/dist/index.js || (echo "client dist missing - run make client first"; exit 1)
	cd client && npm run pack:check
