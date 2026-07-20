.PHONY: all help help-body help-ref version setup check build clean test lint spellcheck wasm client doc audit ci release check-yanked

.NOTPARALLEL: ci

.DEFAULT_GOAL := help

# Project metadata for help/version
PROJECT := tightbeam-ws
VERSION := $(shell awk -F\" '/^\s*version\s*=\s*"/{print $$2; exit}' Cargo.toml 2>/dev/null)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
GIT_DIRTY := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo "+dirty")

define PRINT_PAGER
@{ $(1); } | less -FRX
endef

# Browser client target: only compiled for wasm32, so the host-target lint/test
# steps never exercise it. `make wasm` guards it explicitly.
WASM_TARGET := wasm32-unknown-unknown
WASM_CRATE := tightbeam-ws-wasm

# npm workspace root for the ws browser stack (builder + client + e2e).
NPM_ROOT := ws

# Cargo feature passthroughs (e.g., `make test features="testing"`).
CARGO_FLAGS := $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

ifneq ($(filter 1,$(fix)),)
LINT_MODE := fix
else
LINT_MODE := check
endif

AUDIT_MODE := $(LINT_MODE)

ifneq ($(filter 1,$(debug)),)
export RUST_LOG = debug
endif

RELEASE_VERSION := $(version)

help:
	$(call PRINT_PAGER,$(MAKE) help-body)

help-body:
	@printf 'USAGE:\n'
	@printf '    make <target> [fix=1] [debug=1] [features="<comma-separated>"] [no-default=1]\n'
	@printf '                  [version=vX.Y.Z] [dry-run=1] [allow-staged=1] [yank=1] [ui=1] [trace=1]\n\n'
	@printf 'DESCRIPTION:\n'
	@printf '    Build, test, lint, and release %s following POSIX/GNU CLI conventions.\n\n' '$(PROJECT)'
	@printf 'TARGETS:\n'
	@printf '    all             Build everything: Rust workspace + TS/wasm client\n'
	@printf '    help            Show this help and exit\n'
	@printf '    help-ref        Show reference documentation links\n'
	@printf '    version         Show project version information\n'
	@printf '    setup           Setup the development environment (idempotent)\n'
	@printf '    check           Run code check (honors cargo features)\n'
	@printf '    build           Build the workspace (honors cargo features)\n'
	@printf '    clean           Clean build artifacts\n'
	@printf '    test            Run the whole suite: cargo tests (all features) + dockerized e2e\n'
	@printf '    lint            Lint + spellcheck everything: Rust + TypeScript + cspell (fix=1 to auto-fix)\n'
	@printf '    spellcheck      Spellcheck the repository with cspell\n'
	@printf '    wasm            Lint and build the browser client for wasm32\n'
	@printf '    client          Build the published hybrid TS/wasm client package\n'
	@printf '    doc             Build documentation (all features)\n'
	@printf '    audit           Security audit: cargo audit + npm audit (fix=1 for npm fixes)\n'
	@printf '    ci              Full pipeline: lint + build + test + wasm + client\n'
	@printf '    release         Release workflow (see OPTIONS)\n'
	@printf '    check-yanked    Check if the current version has been yanked\n\n'
	@printf 'OPTIONS / VARIABLES:\n'
	@printf '    fix             If set (e.g., fix=1), apply lint/audit fixes\n'
	@printf '    debug           If set (e.g., debug=1), RUST_LOG=debug + verbose e2e reporter\n'
	@printf '    features        Comma-separated Cargo feature list passed as --features\n'
	@printf '    no-default      If set (e.g., 1), passes --no-default-features to Cargo\n'
	@printf '    version         Release version (e.g., version=v0.2.0)\n'
	@printf '    dry-run         If set (e.g., dry-run=1), preview release without changes\n'
	@printf '    allow-staged    If set (e.g., allow-staged=1), include staged files in release\n'
	@printf '    yank            If set (e.g., yank=1), yank a published version\n'
	@printf '    ui              If set (e.g., ui=1), run the e2e suite in Playwright UI mode\n'
	@printf '    trace           If set (e.g., trace=1), force Playwright traces\n'
	@printf '    NPM_INSTALL_FLAGS  Extra flags for npm install/ci (e.g. --ignore-scripts)\n'
	@printf '    CI              If set (CI=true), setup.sh uses npm ci\n\n'
	@printf 'EXAMPLES:\n'
	@printf '    make setup\n'
	@printf '    make lint\n'
	@printf '    make lint fix=1\n'
	@printf '    make test debug=1\n'
	@printf '    make build features="testing"\n'
	@printf '    make audit fix=1\n'
	@printf '    make release version=v0.2.0\n'
	@printf '    make release version=v0.2.0 dry-run=1\n'
	@printf '    make release yank=1\n\n'
	@printf 'EXIT STATUS:\n'
	@printf '    0    Success\n'
	@printf '    >0   Error occurred\n\n'

help-ref:
	@printf 'REFERENCES:\n'
	@printf '    GNU CLI Guidelines: https://www.gnu.org/prep/standards/html_node/Command_002dLine-Interfaces.html\n'
	@printf '    POSIX Utility Syntax: https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html\n'
	@printf '    GNU Make Goals: https://www.gnu.org/software/make/manual/html_node/Goals.html\n\n'

version:
	@v='$(VERSION)'; c='$(GIT_COMMIT)'; d='$(GIT_DIRTY)'; [ -n "$$v" ] || v=unknown; \
	printf '%s %s (%s%s)\n' '$(PROJECT)' "$$v" "$$c" "$$d"

setup:
	@chmod +x scripts/setup.sh scripts/get-port.sh
	@NPM_INSTALL_FLAGS="$(NPM_INSTALL_FLAGS)" ./scripts/setup.sh

all: build client
	@echo "Build complete: Rust workspace + TS/wasm client."

check: setup
	@echo "Checking $(PROJECT)..."
	cargo check --all-targets $(CARGO_FLAGS)

build: setup
	@echo "Building $(PROJECT)..."
	cargo build --release $(CARGO_FLAGS)

clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf built target .make

test: client
	@echo "Running cargo tests..."
ifeq ($(strip $(features)$(no-default)),)
	cargo test --all-features
else
	cargo test $(CARGO_FLAGS)
endif
	@echo "Running TS unit tests (vitest)..."
	cd $(NPM_ROOT) && npm run test
	@echo "Running dockerized e2e (echo server + TS app)..."
	@E2E_UI="$(if $(filter 1,$(ui)),1,)" \
		E2E_TRACE="$(if $(filter 1,$(trace)),1,)" \
		E2E_DEBUG="$(if $(filter 1,$(debug)),1,)" \
		./scripts/test-e2e.sh

lint: setup
	@echo "Running linters (mode: $(LINT_MODE))..."
	@echo "Linting Rust..."
ifeq ($(LINT_MODE),fix)
	cargo fmt --all
	cargo clippy --all-targets --all-features
	@echo "Linting TypeScript..."
	cd $(NPM_ROOT) && npm run lint:fix
else
	cargo fmt --all --check
	cargo clippy --all-targets --all-features -- -D warnings
	@echo "Linting TypeScript..."
	cd $(NPM_ROOT) && npm run lint
endif
	@$(MAKE) spellcheck

spellcheck: setup
	@echo "Checking spelling..."
	$(NPM_ROOT)/node_modules/.bin/cspell "**/*" --no-progress

wasm: setup
	@echo "Linting and building $(WASM_CRATE) for $(WASM_TARGET)..."
	cargo clippy -p $(WASM_CRATE) --target $(WASM_TARGET) -- -D warnings
	cargo build -p $(WASM_CRATE) --target $(WASM_TARGET)

client: setup
	@echo "Building TS workspace (tightbeam-ts + wasm-pack web client)..."
	cd $(NPM_ROOT) && npm run build

doc: setup
	@echo "Building documentation..."
	cargo doc --no-deps --all-features

audit: setup
	@chmod +x scripts/audit.sh
	@AUDIT_MODE=$(AUDIT_MODE) ./scripts/audit.sh

ci:
	$(MAKE) lint
	$(MAKE) build
	$(MAKE) test
	$(MAKE) wasm
	$(MAKE) client

release: setup
	@DRY_RUN="$(if $(filter 1,$(dry-run)),1,)" \
		ALLOW_STAGED="$(if $(filter 1,$(allow-staged)),1,)" \
		YANK="$(if $(filter 1,$(yank)),1,)" \
		./scripts/release.sh "$(RELEASE_VERSION)"

check-yanked:
	@./scripts/check-yanked.sh
