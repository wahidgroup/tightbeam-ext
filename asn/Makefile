# The targets of the asn extension, which the root Makefile composes: docs/development.md.

.PHONY: setup check build test lint wasm client sbom smoke pack fixture-package

REPO := ..
CRATES := $(addprefix -p ,$(shell REPO_ROOT='$(abspath $(REPO))' bash -c '. "$$REPO_ROOT/scripts/lib/extension.sh" && extension_crates asn'))
ifeq ($(strip $(CRATES)),)
$(error scripts/lib/extension.sh lists no crate of asn)
endif

CARGO_FLAGS := $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

# The JavaScript conversions of `tightbeam-asn` and of each derive expansion, which compile for wasm32 alone.
WASM_LINT := -p tightbeam-asn --target wasm32-unknown-unknown --lib --example fixture_package --test wasm_js_roundtrip

# Local `make test` skips wasm-opt on the ws client dependency. `make ci`
# passes wasm_opt=1 so CI still builds release-sized wasm.
ifneq ($(filter 1,$(wasm_opt)),)
TEST_WASM_PACK_FLAGS :=
else
TEST_WASM_PACK_FLAGS := --no-opt
endif

# The `fixture_package` example, bound for the web as a `wasm-pack` build of a consumer is.
FIXTURE_WASM := $(REPO)/target/wasm32-unknown-unknown/debug/examples/fixture_package.wasm
FIXTURE_PACKAGE := tests/fixture

# The module that the emitter writes from the fixture package, beside the suite that imports it.
FIXTURE_CODECS := tests/codecs.ts

# The same example bound for Node, whose `.d.ts` is the one a nodejs build writes, with its emitted module inside it.
FIXTURE_NODE_PACKAGE := $(FIXTURE_PACKAGE)/node

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
	@echo "Building the ws client and the fixture package that the TypeScript suite imports..."
	@$(MAKE) -C $(REPO)/ws client WASM_PACK_FLAGS="$(TEST_WASM_PACK_FLAGS)"
	@$(MAKE) fixture-package
	@echo "Type-checking the asn TypeScript suite..."
	npm run typecheck
	@echo "Running the asn TypeScript suite..."
	npm run test
	@echo "Running asn wasm32 JS round-trip tests..."
	CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
		cargo test -p tightbeam-asn --target wasm32-unknown-unknown --test wasm_js_roundtrip

lint: setup
	@echo "Linting asn (mode: $(LINT_MODE))..."
ifeq ($(LINT_MODE),fix)
	cargo fmt $(CRATES)
	cargo clippy $(CRATES) --all-targets --all-features
	cargo clippy $(WASM_LINT)
	npm run lint:fix
else
	cargo fmt $(CRATES) --check
	cargo clippy $(CRATES) --all-targets --all-features -- -D warnings
	cargo clippy $(WASM_LINT) -- -D warnings
	npm run lint
endif

wasm:
	@echo "asn has no product wasm crate; nothing to do."

fixture-package: setup
	@echo "Building the asn fixture wasm package and its codecs..."
	cargo build -p tightbeam-asn --example fixture_package --target wasm32-unknown-unknown
	wasm-bindgen --target web --out-dir $(FIXTURE_PACKAGE) --out-name asn_fixtures $(FIXTURE_WASM)
	wasm-bindgen --target experimental-nodejs-module --out-dir $(FIXTURE_NODE_PACKAGE) --out-name asn_fixtures $(FIXTURE_WASM)
	cargo run -p tightbeam-asn --features emit --bin tightbeam-asn-emit -- \
		--from-dts $(FIXTURE_PACKAGE)/asn_fixtures.d.ts --out $(FIXTURE_CODECS) --import '#asn-wasm'
	cargo run -p tightbeam-asn --features emit --bin tightbeam-asn-emit -- \
		--from-dts $(FIXTURE_NODE_PACKAGE)/asn_fixtures.d.ts --out $(FIXTURE_NODE_PACKAGE)/codecs.ts --import './asn_fixtures.js'

client:
	@echo "asn has no npm client; nothing to do."

sbom:
	@echo "asn publishes no SBOM; nothing to do."

smoke:
	@echo "asn has no npm client; nothing to do."

pack:
	@echo "asn has no npm client; nothing to do."
