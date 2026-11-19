# The targets of the store extension, which the root Makefile composes: docs/development.md.

.PHONY: setup check build test lint wasm client sbom smoke pack

REPO := ..
CRATES := $(addprefix -p ,$(shell REPO_ROOT='$(abspath $(REPO))' bash -c '. "$$REPO_ROOT/scripts/lib/extension.sh" && extension_crates store'))
ifeq ($(strip $(CRATES)),)
$(error scripts/lib/extension.sh lists no crate of store)
endif

CARGO_FLAGS := $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

ifneq ($(filter 1,$(fix)),)
LINT_MODE := fix
else
LINT_MODE := check
endif

setup:
	@$(REPO)/scripts/setup.sh store

check:
	@echo "Checking store crates..."
	cargo check $(CRATES) --all-targets $(CARGO_FLAGS)

build:
	@echo "Building store crates..."
	cargo build --release $(CRATES) $(CARGO_FLAGS)

test: setup
	@echo "Running store cargo tests..."
	cargo test $(CRATES) $(CARGO_FLAGS)

lint: setup
	@echo "Linting store (mode: $(LINT_MODE))..."
ifeq ($(LINT_MODE),fix)
	cargo fmt $(CRATES)
	cargo clippy $(CRATES) --all-targets
else
	cargo fmt $(CRATES) --check
	cargo clippy $(CRATES) --all-targets -- -D warnings
endif

wasm:
	@echo "store has no wasm build; nothing to do."

client:
	@echo "store has no npm client; nothing to do."

sbom:
	@echo "store publishes no SBOM; nothing to do."

smoke:
	@echo "store has no npm client; nothing to do."

pack:
	@echo "store has no npm client; nothing to do."
