.PHONY: all help help-body version setup check build clean test lint spellcheck wasm client doc release check-yanked

.DEFAULT_GOAL := all

# Project metadata for help/version
PROJECT := tightbeam-ws
VERSION := $(shell awk -F\" '/^\s*version\s*=\s*"/{print $$2; exit}' Cargo.toml 2>/dev/null)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
GIT_DIRTY := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo "+dirty")

# Browser client target: only compiled for wasm32, so the host-target lint/test
# steps never exercise it. `make wasm` guards it explicitly.
WASM_TARGET := wasm32-unknown-unknown
WASM_CRATE := tightbeam-ws-wasm

# Published hybrid TS/wasm client package.
WEB_CLIENT := clients/web

# Self-contained e2e harness: dockerized echo server + headless TS example app.
E2E_DIR := e2e

# Extract version and flags from positional args (e.g., `make release v0.1.0 --dry-run`)
RELEASE_VERSION := $(filter v%,$(MAKECMDGOALS))
RELEASE_FLAGS   := $(filter --%,$(MAKECMDGOALS))

# Default target: build everything (Rust workspace + TS/wasm client).
all: build client
	@echo "Build complete: Rust workspace + TS/wasm client."

help: help-body

help-body:
	@printf 'USAGE:\n'
	@printf '    make <target> [features="<comma-separated features>"] [no-default=1] [ARGS="<clippy-args>"]\n\n'
	@printf 'TARGETS:\n'
	@printf '    all             Build everything: Rust workspace + TS/wasm client (default)\n'
	@printf '    help            Show this help and exit\n'
	@printf '    version         Show project version information\n'
	@printf '    setup           Setup the development environment\n'
	@printf '    check           Run code check (honors cargo features)\n'
	@printf '    build           Build the workspace (honors cargo features)\n'
	@printf '    clean           Clean build artifacts\n'
	@printf '    test            Run the whole suite: cargo tests + dockerized e2e (TS app)\n'
	@printf '    lint            Lint + spellcheck everything: Rust + TypeScript + cspell (pass -- --fix to auto-fix)\n'
	@printf '    spellcheck      Spellcheck the repository with cspell\n'
	@printf '    wasm            Lint and build the browser client for wasm32\n'
	@printf '    client          Build the published hybrid TS/wasm client package\n'
	@printf '    doc             Build documentation (all features)\n'
	@printf '    release         Release workflow (make release v0.1.0 [--dry-run] [--allow-staged] [--yank])\n'
	@printf '    check-yanked    Check if the current version has been yanked\n\n'
	@printf 'OPTIONS / VARIABLES:\n'
	@printf '    features        Comma-separated Cargo feature list passed as --features\n'
	@printf '    no-default      If set (e.g., 1), passes --no-default-features to Cargo\n\n'
	@printf 'EXAMPLES:\n'
	@printf '    make build features="x509"\n'
	@printf '    make lint -- --fix\n\n'

version:
	@v='$(VERSION)'; c='$(GIT_COMMIT)'; d='$(GIT_DIRTY)'; [ -n "$$v" ] || v=unknown; \
	printf '%s %s (%s%s)\n' '$(PROJECT)' "$$v" "$$c" "$$d"

setup:
	@echo "Installing development tools..."
	rustup component add rustfmt clippy
	rustup target add $(WASM_TARGET)
	@command -v wasm-pack >/dev/null 2>&1 || cargo install wasm-pack
	npm install
	npm run build
	cd $(E2E_DIR) && npx playwright install chromium

check:
	@echo "Checking $(PROJECT)..."
	cargo check --all-targets $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

build:
	@echo "Building $(PROJECT)..."
	cargo build --release $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf built target

# Whole suite: cargo tests, then the self-contained dockerized e2e (rebuilds the
# client so the TS app exercises current artifacts). Requires `make setup`.
test: client
	@echo "Running cargo tests..."
	cargo test $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)
	@echo "Running dockerized e2e (echo server + TS app)..."
	./scripts/test-e2e.sh

# Collect extra args passed after the target (e.g., `make lint -- --fix`)
LINT_ARGS := $(filter-out lint,$(MAKECMDGOALS))
LINT_ARGS := $(filter-out --,$(LINT_ARGS))
ifneq ($(strip $(ARGS)),)
LINT_ARGS += $(ARGS)
endif

ifeq (,$(findstring --fix,$(LINT_ARGS)))
FMT_CMD := cargo fmt --all --check
CLIPPY_EXTRA := -- -D warnings
TS_LINT_CMD := npm run lint
LINT_MODE := check
else
FMT_CMD := cargo fmt --all
CLIPPY_EXTRA :=
TS_LINT_CMD := npm run lint:fix
LINT_MODE := fix
endif

lint:
	@echo "Running linters (mode: $(LINT_MODE))..."
	@echo "Linting Rust..."
	$(FMT_CMD)
	cargo clippy --all-targets --all-features $(filter-out --fix,$(LINT_ARGS)) $(CLIPPY_EXTRA)
	@echo "Linting TypeScript..."
	$(TS_LINT_CMD)
	@$(MAKE) spellcheck

spellcheck:
	@echo "Checking spelling..."
	npx cspell "**/*" --no-progress

wasm:
	@echo "Linting and building $(WASM_CRATE) for $(WASM_TARGET)..."
	cargo clippy -p $(WASM_CRATE) --target $(WASM_TARGET) -- -D warnings
	cargo build -p $(WASM_CRATE) --target $(WASM_TARGET)

client:
	@echo "Building TS workspace (typing + tightbeam-ts + wasm-pack web client)..."
	npm install
	npm run build

doc:
	@echo "Building documentation..."
	cargo doc --no-deps --all-features

check-yanked:
	@./scripts/check-yanked.sh

release:
	@./scripts/release.sh "$(RELEASE_VERSION)" $(RELEASE_FLAGS)

# Swallow option-like / version-token MAKECMDGOALS so make does not error on them.
--:
	@:
--%:
	@:
v%:
	@:
