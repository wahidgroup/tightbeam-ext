# grpc extension targets: the gRPC transport crate, which tunnels tightbeam
# envelopes over one bidirectional call. Invoked directly (make -C grpc
# <target>) or through the repo root Makefile (make test grpc).

.PHONY: setup check build test lint wasm client sbom smoke pack

REPO := ..
CRATES := -p tightbeam-grpc

CARGO_FLAGS := $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

ifneq ($(filter 1,$(fix)),)
LINT_MODE := fix
else
LINT_MODE := check
endif

setup:
	@$(REPO)/scripts/setup.sh grpc

check:
	@echo "Checking grpc crates..."
	cargo check $(CRATES) --all-targets $(CARGO_FLAGS)

build:
	@echo "Building grpc crates..."
	cargo build --release $(CRATES) $(CARGO_FLAGS)

test: setup
	@echo "Running grpc cargo tests..."
	cargo test $(CRATES) $(CARGO_FLAGS)

lint: setup
	@echo "Linting grpc (mode: $(LINT_MODE))..."
ifeq ($(LINT_MODE),fix)
	cargo fmt $(CRATES)
	cargo clippy $(CRATES) --all-targets --all-features
else
	cargo fmt $(CRATES) --check
	cargo clippy $(CRATES) --all-targets --all-features -- -D warnings
endif

wasm:
	@echo "grpc has no wasm crate; nothing to do."

client:
	@echo "grpc has no npm client; nothing to do."

sbom:
	@echo "grpc publishes no SBOM; nothing to do."

smoke:
	@echo "grpc has no npm client; nothing to do."

pack:
	@echo "grpc has no npm client; nothing to do."
