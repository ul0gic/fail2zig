# fail2zig — top-level Makefile.
#
# Thin wrapper around `zig build` subcommands. The authoritative build graph
# lives in `build.zig`; this file exists so contributors can type `make test`
# without thinking about Zig flags, and so CI can invoke canonical targets
# by name.
#
# Run `make help` for a summary of every target.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

# Default optimisation mode used by `make release` and `make cross`.
# Override with `make release OPT=ReleaseSmall` if you need a size-optimised
# binary for an embedded target.
OPT ?= ReleaseSafe

# Targets that `make cross` produces. `x86_64-linux-musl` and
# `aarch64-linux-musl` are the two arches v0.1.0 ships for. armv7 + mips
# are gated on SYS-009.
CROSS_TARGETS := x86_64-linux-musl aarch64-linux-musl

# Install prefix for `make install`. Matches scripts/install.sh defaults.
PREFIX ?= /usr/local

# CI shells out to `install` a lot; keep the resolved path stable.
INSTALL ?= install

.DEFAULT_GOAL := help

.PHONY: help build test fmt fmt-check release cross install clean bench fuzz \
        hammer-smoke lint docs-check

help: ## Show this help message
	@awk 'BEGIN { FS = ":.*?## " } \
	     /^[a-zA-Z_-]+:.*?## / { printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2 }' \
	     $(MAKEFILE_LIST) | sort

build: ## Build engine + client (Debug, with safety checks)
	zig build

test: ## Run the full test suite (unit, integration, fuzz corpora)
	zig build test

fmt: ## Apply `zig fmt` to all tracked Zig source trees
	zig fmt engine/ client/ shared/ tests/

fmt-check: ## Verify `zig fmt` is a no-op (used by CI)
	zig fmt --check engine/ client/ shared/ tests/

release: ## Build ReleaseSafe static binaries for the native target
	zig build -Doptimize=$(OPT)

cross: ## Cross-compile ReleaseSafe binaries for every shipped target
	@for t in $(CROSS_TARGETS); do \
	  echo ">>> cross-compiling $$t"; \
	  zig build -Dtarget=$$t -Doptimize=$(OPT); \
	  mkdir -p zig-out/$$t/bin; \
	  cp zig-out/bin/fail2zig        zig-out/$$t/bin/fail2zig; \
	  cp zig-out/bin/fail2zig-client zig-out/$$t/bin/fail2zig-client; \
	done

install: release ## Install native release binaries into $(PREFIX)/bin (root)
	$(INSTALL) -d -o root -g root -m 0755 $(PREFIX)/bin
	$(INSTALL) -o root -g root -m 0755 zig-out/bin/fail2zig        $(PREFIX)/bin/fail2zig
	$(INSTALL) -o root -g root -m 0755 zig-out/bin/fail2zig-client $(PREFIX)/bin/fail2zig-client
	@echo "installed to $(PREFIX)/bin — run scripts/install.sh for full system setup"

clean: ## Remove build artifacts and caches
	rm -rf zig-out .zig-cache

bench: ## Run Phase 7 performance benchmarks (sets FAIL2ZIG_RUN_BENCH=1)
	zig build test -Dbench=true

fuzz: ## Run the fuzz corpus targets
	zig build test --test-filter fuzz

hammer-smoke: ## Run the lab-box attack smoke test (ssh_brute). Only useful on the lab host.
	scripts/hammer/reset.sh
	scripts/hammer/ssh_brute.sh

lint: fmt-check ## Static analysis: zig fmt --check, shellcheck, yamllint
	shellcheck -S warning scripts/hammer/*.sh scripts/install.sh
	yamllint -c .yamllint .github/workflows/

docs-check: ## Run the documentation quality gate (owned by DOC team; 8.1.6)
	@if [ -x scripts/docs-check.sh ]; then \
	  scripts/docs-check.sh; \
	else \
	  echo "docs-check.sh not present yet — DOC agent delivers in Phase 8.1.6"; \
	  exit 0; \
	fi
