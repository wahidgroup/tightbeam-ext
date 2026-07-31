.PHONY: all help help-body help-ref version setup check build clean test lint doc-lint spellcheck wasm client sbom smoke pack doc audit ci release check-yanked

.DEFAULT_GOAL := help

# Every extension project, discovered: a top-level directory owning a
# Makefile is a project. Each owns its targets there; this Makefile
# composes them. Naming projects after a target scopes it:
# `make test ws`, `make lint pubsub`. No project means every project.
PROJECTS := $(sort $(patsubst %/Makefile,%,$(wildcard */Makefile)))

.PHONY: $(PROJECTS)

SCOPE := $(filter $(PROJECTS),$(MAKECMDGOALS))
ifeq ($(SCOPE),)
SCOPE := $(PROJECTS)
endif

# Project names are extra goals, not work: the real target reads SCOPE.
$(PROJECTS):
	@:

# Flags forwarded to project Makefiles.
PASSTHRU := features="$(features)" no-default="$(no-default)" fix="$(fix)"

# Run one target in every scoped project.
define EACH_PROJECT
@for project in $(SCOPE); do $(MAKE) -C $$project $(1) $(PASSTHRU) || exit 1; done
endef

# Extension under release/version inspection (e.g., `make release ext=ws`).
# Each top-level extension directory versions its crates independently.
EXT := $(if $(ext),$(ext),ws)

# Project metadata for help/version
PROJECT := tightbeam-$(EXT)
VERSION := $(shell awk -F\" '/^[[:space:]]*version[[:space:]]*=[[:space:]]*"/{print $$2; exit}' $(EXT)/tightbeam-$(EXT)/Cargo.toml 2>/dev/null)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
GIT_DIRTY := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo "+dirty")

define PRINT_PAGER
@{ $(1); } | less -FRX
endef

# npm root the repo-wide tooling (cspell) resolves from.
NPM_ROOT := ws

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
	@printf '    make <target> [ws] [pubsub] [fix=1] [debug=1] [features="<comma-separated>"]\n'
	@printf '                  [no-default=1] [version=vX.Y.Z] [ext=<name>] [dry-run=1]\n'
	@printf '                  [allow-staged=1] [yank=1] [ui=1] [trace=1]\n\n'
	@printf 'DESCRIPTION:\n'
	@printf '    Build, test, lint, and release %s following POSIX/GNU CLI conventions.\n' '$(PROJECT)'
	@printf '    Naming projects scopes a target: `make test ws`, `make lint pubsub`.\n'
	@printf '    Without a project name, targets run for every project.\n\n'
	@printf 'TARGETS:\n'
	@printf '    all             Build everything: Rust workspace + client packages\n'
	@printf '    help            Show this help and exit\n'
	@printf '    help-ref        Show reference documentation links\n'
	@printf '    version         Show project version information\n'
	@printf '    setup           Setup the development environment (idempotent)\n'
	@printf '    check           Run code check (honors cargo features)\n'
	@printf '    build           Build the workspace (honors cargo features)\n'
	@printf '    clean           Clean build artifacts\n'
	@printf '    test            Run the suite: cargo tests + TS units + dockerized e2e\n'
	@printf '    lint            Lint + spellcheck + rustdoc (fix=1 to auto-fix)\n'
	@printf '    spellcheck      Spellcheck the repository with cspell\n'
	@printf '    wasm            Lint and build the browser client for wasm32\n'
	@printf '    client          Build the published client packages\n'
	@printf '    sbom            Generate the client software bill of materials\n'
	@printf '    smoke           Smoke-load the built client package exports\n'
	@printf '    pack            Assert npm pack contents\n'
	@printf '    doc             Build documentation (all features; -D warnings)\n'
	@printf '    audit           Security audit: cargo audit + npm audit (fix=1 for npm fixes)\n'
	@printf '    ci              Full pipeline: lint + build + test + wasm + client + smoke + pack\n'
	@printf '    release         Release an extension independently (see OPTIONS)\n'
	@printf '    check-yanked    Check if the extension version has been yanked\n\n'
	@printf 'OPTIONS / VARIABLES:\n'
	@printf '    ws / pubsub     Scope the target to the named project(s)\n'
	@printf '    fix             If set (e.g., fix=1), apply lint/audit fixes; rustdoc still denies warnings\n'
	@printf '    debug           If set (e.g., debug=1), RUST_LOG=debug + verbose e2e reporter\n'
	@printf '    features        Comma-separated Cargo feature list passed as --features\n'
	@printf '    no-default      If set (e.g., 1), passes --no-default-features to Cargo\n'
	@printf '    version         Release version (e.g., version=v0.2.0)\n'
	@printf '    ext             Extension to release/version (default: ws)\n'
	@printf '    dry-run         If set (e.g., dry-run=1), preview release without changes\n'
	@printf '    allow-staged    If set (e.g., allow-staged=1), include staged files in release\n'
	@printf '    yank            If set (e.g., yank=1), yank a published version\n'
	@printf '    ui              If set (e.g., ui=1), run the e2e suite in Playwright UI mode\n'
	@printf '    trace           If set (e.g., trace=1), force Playwright traces\n'
	@printf '    NPM_INSTALL_FLAGS  Extra flags for npm install/ci (e.g. --ignore-scripts)\n'
	@printf '    CI              If set (CI=true), setup.sh uses npm ci\n\n'
	@printf 'EXAMPLES:\n'
	@printf '    make setup\n'
	@printf '    make test ws\n'
	@printf '    make lint pubsub fix=1\n'
	@printf '    make test debug=1\n'
	@printf '    make build features="testing"\n'
	@printf '    make audit fix=1\n'
	@printf '    make release version=v0.2.0\n'
	@printf '    make release version=v0.2.0 ext=ws dry-run=1\n'
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
	@chmod +x scripts/*.sh $(PROJECTS:%=%/scripts/*.sh)
	@NPM_INSTALL_FLAGS="$(NPM_INSTALL_FLAGS)" ./scripts/setup.sh $(SCOPE)

all: build client
	@echo "Build complete: Rust workspace + client packages."

check: setup
	$(call EACH_PROJECT,check)

build: setup
	$(call EACH_PROJECT,build)

clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf built target .make

test: setup
	$(call EACH_PROJECT,test)
	@echo "Running dockerized e2e ($(SCOPE))..."
	@E2E_UI="$(if $(filter 1,$(ui)),1,)" \
		E2E_TRACE="$(if $(filter 1,$(trace)),1,)" \
		E2E_DEBUG="$(if $(filter 1,$(debug)),1,)" \
		./scripts/test-e2e.sh $(SCOPE)

lint: setup
	$(call EACH_PROJECT,lint)
	@$(MAKE) doc-lint
	@$(MAKE) spellcheck

# Rustdoc has no cargo --fix path for intra-doc / private-link warnings.
# Both lint and doc deny them so CI and local builds fail closed the same way.
doc-lint: setup
	@echo "Checking rustdoc (RUSTDOCFLAGS=-D warnings)..."
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

spellcheck: setup
	@echo "Checking spelling..."
	$(NPM_ROOT)/node_modules/.bin/cspell "**/*" --no-progress

wasm: setup
	$(call EACH_PROJECT,wasm)

client: setup
	$(call EACH_PROJECT,client)

sbom: setup
	$(call EACH_PROJECT,sbom)

smoke: setup
	$(call EACH_PROJECT,smoke)

pack: setup
	$(call EACH_PROJECT,pack)

doc: doc-lint
	@echo "Documentation build complete."

audit: setup
	@chmod +x scripts/audit.sh
	@AUDIT_MODE=$(AUDIT_MODE) ./scripts/audit.sh $(SCOPE)

ci:
	$(MAKE) lint SCOPE="$(SCOPE)"
	$(MAKE) build SCOPE="$(SCOPE)"
	$(MAKE) test SCOPE="$(SCOPE)"
	$(MAKE) wasm SCOPE="$(SCOPE)"
	$(MAKE) client SCOPE="$(SCOPE)"
	$(MAKE) smoke SCOPE="$(SCOPE)"
	$(MAKE) pack SCOPE="$(SCOPE)"

release: setup
	@EXT="$(EXT)" \
		DRY_RUN="$(if $(filter 1,$(dry-run)),1,)" \
		ALLOW_STAGED="$(if $(filter 1,$(allow-staged)),1,)" \
		YANK="$(if $(filter 1,$(yank)),1,)" \
		./scripts/release.sh "$(RELEASE_VERSION)"

check-yanked:
	@./scripts/check-yanked.sh "$(EXT)"
