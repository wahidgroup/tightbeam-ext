.PHONY: all help help-body help-ref version setup check build clean test lint doc-lint spellcheck format-scripts shellcheck wasm client sbom smoke pack doc audit ci release check-yanked

.DEFAULT_GOAL := help

# Every extension project, as scripts/lib/projects.sh discovers them. Each
# owns its targets in its own Makefile, and this Makefile composes them. Naming
# projects after a target scopes it: `make test ws`, `make lint pubsub`. No
# project means every project.
PROJECTS := $(shell REPO_ROOT='$(CURDIR)' bash -c '. scripts/lib/projects.sh && discover_projects')

.PHONY: $(PROJECTS)

# The projects named on the command line. A release names exactly one.
NAMED := $(filter $(PROJECTS),$(MAKECMDGOALS))
SCOPE := $(if $(NAMED),$(NAMED),$(PROJECTS))

# Project names are extra goals, not work: the real target reads SCOPE.
$(PROJECTS):
	@:

# Flags forwarded to project Makefiles.
PASSTHRU := features="$(features)" no-default="$(no-default)" fix="$(fix)" wasm_opt="$(wasm_opt)"

# Run one target in every scoped project.
define EACH_PROJECT
@for project in $(SCOPE); do $(MAKE) -C $$project $(1) $(PASSTHRU) || exit 1; done
endef

define PRINT_PAGER
@{ $(1); } | less -FRX
endef

# The npm project of the repo-wide tooling (cspell): the one whose
# node_modules cspell.yaml imports its base from.
TOOLING_ROOT := $(shell sed -n 's|^[[:space:]]*-[[:space:]]*\./\([^/]*\)/node_modules/.*$$|\1|p' cspell.yaml)

ifneq ($(filter 1,$(fix)),)
LINT_MODE := fix
else
LINT_MODE := check
endif

AUDIT_MODE := $(LINT_MODE)

ifneq ($(filter 1,$(debug)),)
export RUST_LOG = debug
endif

# The one extension of a release, named as a project goal or as ext=<name>,
# the form that scripts/release.sh prints.
RELEASE_EXT := $(sort $(NAMED) $(ext))

# The check of scripts/lib/extension.sh that runs before scripts/release.sh,
# which prints the version that scripts/release.sh then takes.
ifneq ($(filter 1,$(yank)),)
RELEASE_GATE := extension_require "$$1" && echo "$$2"
else
RELEASE_GATE := extension_release_gate "$$1" "$$2"
endif

help:
	$(call PRINT_PAGER,$(MAKE) help-body)

help-body:
	@printf 'USAGE:\n'
	@printf '    make <target> [<project>...] [fix=1] [debug=1] [features="<comma-separated>"]\n'
	@printf '                  [no-default=1] [version=vX.Y.Z] [ext=<project>] [dry-run=1]\n'
	@printf '                  [allow-staged=1] [yank=1] [ui=1] [trace=1]\n\n'
	@printf 'DESCRIPTION:\n'
	@printf '    Build, test, lint, and release the tightbeam-ext extensions following\n'
	@printf '    POSIX/GNU CLI conventions. Naming projects scopes a target:\n'
	@printf '    `make test ws`, `make lint pubsub`. Without a project name, targets\n'
	@printf '    run for every project. A release names exactly one project.\n\n'
	@printf 'TARGETS:\n'
	@printf '    all             Build everything: Rust workspace + client packages\n'
	@printf '    help            Show this help and exit\n'
	@printf '    help-body       Show this help without the pager\n'
	@printf '    help-ref        Show reference documentation links\n'
	@printf '    version         Show the version of each scoped extension\n'
	@printf '    setup           Setup the development environment (idempotent)\n'
	@printf '    check           Run code check (honors cargo features)\n'
	@printf '    build           Build the workspace (honors cargo features)\n'
	@printf '    clean           Clean build artifacts\n'
	@printf '    test            Run the suite: cargo tests + TS units + dockerized e2e\n'
	@printf '    lint            Lint, spellcheck, rustdoc, script checks, shellcheck (fix=1 to auto-fix)\n'
	@printf '    doc-lint        Check rustdoc with -D warnings\n'
	@printf '    spellcheck      Spellcheck the repository with cspell\n'
	@printf '    format-scripts  Check the format and lint of the .mjs and .mts repo scripts (fix=1 to auto-fix)\n'
	@printf '    shellcheck      Check every shell script and git hook with shellcheck\n'
	@printf '    wasm            Lint and build the browser client for wasm32\n'
	@printf '    client          Build the published client packages\n'
	@printf '    sbom            Generate the client software bill of materials\n'
	@printf '    smoke           Smoke-load the built client package exports\n'
	@printf '    pack            Assert npm pack contents\n'
	@printf '    doc             Build documentation (all features; -D warnings)\n'
	@printf '    audit           Security audit: cargo audit + npm audit (fix=1 for npm fixes)\n'
	@printf '    ci              Full pipeline: lint + build + test + wasm + client + smoke + pack\n'
	@printf '    release         Release or yank the one named extension, forward only (see OPTIONS)\n'
	@printf '    check-yanked    Check if the version of the named extension has been yanked\n\n'
	@printf 'OPTIONS / VARIABLES:\n'
	@printf '    <project>       Scope the target to the named project(s): %s\n' '$(PROJECTS)'
	@printf '    fix             If set (e.g., fix=1), apply lint/audit fixes; rustdoc still denies warnings\n'
	@printf '    debug           If set (e.g., debug=1), RUST_LOG=debug + verbose e2e reporter\n'
	@printf '    features        Comma-separated Cargo feature list passed as --features\n'
	@printf '    no-default      If set (e.g., 1), passes --no-default-features to Cargo\n'
	@printf '    version         Release version (e.g., version=v0.2.0), no lower than the latest release. Prompted if absent\n'
	@printf '    ext             The extension of a release, in place of a project name\n'
	@printf '    dry-run         If set (e.g., dry-run=1), preview release without changes\n'
	@printf '    allow-staged    If set (e.g., allow-staged=1), include staged files in release\n'
	@printf '    yank            If set (e.g., yank=1), yank a published version\n'
	@printf '    ui              If set (e.g., ui=1), run the e2e suite in Playwright UI mode\n'
	@printf '    trace           If set (e.g., trace=1), force Playwright traces\n'
	@printf '    wasm_opt        If set (e.g., wasm_opt=1), keep wasm-opt during make test (default: skip)\n'
	@printf '    NPM_INSTALL_FLAGS  Extra flags for npm install/ci (e.g. --ignore-scripts)\n'
	@printf '    CI              If set (CI=true), setup.sh uses npm ci\n\n'
	@printf 'EXAMPLES:\n'
	@printf '    make setup\n'
	@printf '    make test ws\n'
	@printf '    make lint pubsub fix=1\n'
	@printf '    make test debug=1\n'
	@printf '    make build features="testing"\n'
	@printf '    make audit fix=1\n'
	@printf '    make version ws\n'
	@printf '    make release ws version=v0.2.0\n'
	@printf '    make release ws version=v0.2.0 dry-run=1\n'
	@printf '    make release ws yank=1\n\n'
	@printf 'EXIT STATUS:\n'
	@printf '    0    Success\n'
	@printf '    >0   Error occurred\n\n'

help-ref:
	@printf 'REFERENCES:\n'
	@printf '    GNU CLI Guidelines: https://www.gnu.org/prep/standards/html_node/Command_002dLine-Interfaces.html\n'
	@printf '    POSIX Utility Syntax: https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html\n'
	@printf '    GNU Make Goals: https://www.gnu.org/software/make/manual/html_node/Goals.html\n\n'

version:
	@./scripts/version.sh $(SCOPE)

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
	@$(MAKE) format-scripts
	@$(MAKE) shellcheck

# Rustdoc has no cargo --fix path for intra-doc or private-link warnings, so
# lint and doc both deny them, and CI and local builds fail the same way.
doc-lint: setup
	@echo "Checking rustdoc (RUSTDOCFLAGS=-D warnings)..."
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# The repo scripts belong to no npm project, so the tools of the tooling project check them here.
SCRIPT_SOURCES := "scripts/**/*.{mjs,mts}"
PRETTIER := $(TOOLING_ROOT)/node_modules/.bin/prettier \
	--config $(TOOLING_ROOT)/node_modules/@wahidgroup/lint-rules/prettier.mjs
ESLINT := TOOLING_ROOT="$(CURDIR)/$(TOOLING_ROOT)" $(TOOLING_ROOT)/node_modules/.bin/eslint \
	--config scripts/eslint.config.mjs

format-scripts:
	@$(MAKE) setup SCOPE="$(TOOLING_ROOT)"
	@echo "Checking script formatting and lint..."
	$(PRETTIER) $(if $(filter fix,$(LINT_MODE)),--write,--check) $(SCRIPT_SOURCES)
	$(ESLINT) $(if $(filter fix,$(LINT_MODE)),--fix) $(SCRIPT_SOURCES)

# Every shell script of the repo: the root scripts, the scripts of each project, and the git hooks.
SHELL_SCRIPTS := $(wildcard scripts/*.sh scripts/lib/*.sh */scripts/*.sh) $(wildcard .husky/*[!_])

shellcheck:
	@echo "Checking shell scripts..."
	shellcheck -x $(SHELL_SCRIPTS)

# cspell is installed under TOOLING_ROOT. Always set that project up,
# even when lint/ci is scoped to another extension.
spellcheck:
	@$(MAKE) setup SCOPE="$(TOOLING_ROOT)"
	@echo "Checking spelling..."
	$(TOOLING_ROOT)/node_modules/.bin/cspell "**/*" --no-progress

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
	$(MAKE) test SCOPE="$(SCOPE)" wasm_opt=1
	$(MAKE) wasm SCOPE="$(SCOPE)"
	$(MAKE) client SCOPE="$(SCOPE)"
	$(MAKE) smoke SCOPE="$(SCOPE)"
	$(MAKE) pack SCOPE="$(SCOPE)"

release: setup
	@version="$$(REPO_ROOT='$(CURDIR)' bash -c '. scripts/lib/extension.sh && $(RELEASE_GATE)' release '$(RELEASE_EXT)' '$(version)')" && \
		EXT="$(RELEASE_EXT)" \
		DRY_RUN="$(if $(filter 1,$(dry-run)),1,)" \
		ALLOW_STAGED="$(if $(filter 1,$(allow-staged)),1,)" \
		YANK="$(if $(filter 1,$(yank)),1,)" \
		./scripts/release.sh "$$version"

check-yanked:
	@./scripts/check-yanked.sh "$(NAMED)"
