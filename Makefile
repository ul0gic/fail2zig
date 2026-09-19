SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

RELEASE_TARGET ?= native
RELEASE_TARGETS := x86_64-linux-musl aarch64-linux-musl arm-linux-musleabihf mips-linux-musleabi mipsel-linux-musleabi
RELEASE_OPT := ReleaseSafe
ZIG_JOBS ?= 2

PREFIX ?= /usr/local

INSTALL ?= install

.DEFAULT_GOAL := help

.PHONY: help build test fmt fmt-check release release-all install clean fuzz \
        harness-smoke lint

help:
	@printf '  \033[36m%-14s\033[0m %s\n' \
		build 'Build the fail2zig executable (Debug, with safety checks)' \
		clean 'Remove build artifacts and caches' \
		fmt 'Apply `zig fmt` to all tracked Zig source trees' \
		fmt-check 'Verify `zig fmt` is a no-op (used by CI)' \
		fuzz 'Run bounded fuzz corpus cases' \
		harness-smoke 'Run the lab-box attack smoke test (ssh_brute). Only useful on the lab host.' \
		help 'Show this help message' \
		install 'Install the native release executable into $$(PREFIX)/bin (root)' \
		lint 'Static analysis: zig fmt --check, shellcheck, yamllint' \
		release 'Build a stripped ReleaseSafe executable (RELEASE_TARGET)' \
		release-all 'Build all five release architectures into separate prefixes' \
		test 'Run maintained CI component, integration and bounded fuzz suites'

build:
	zig build

test:
	zig build test-ci-components-a -Doptimize=ReleaseSafe -j$(ZIG_JOBS)
	zig build test-ci-components-b -Doptimize=ReleaseSafe -j$(ZIG_JOBS)
	zig build test-ci-assembled -Doptimize=ReleaseSafe -j$(ZIG_JOBS)
	zig build test-ci-fuzz -Doptimize=ReleaseSafe -j$(ZIG_JOBS)

fmt:
	zig fmt build.zig build.zig.zon engine/ client/ shared/ tests/

fmt-check:
	zig fmt --check build.zig build.zig.zon engine/ client/ shared/ tests/

release:
	zig build -Dtarget=$(RELEASE_TARGET) -Doptimize=$(RELEASE_OPT) -Dstrip=true $(if $(filter mips%,$(RELEASE_TARGET)),-Dcpu=mips32r2)

release-all:
	@for target in $(RELEASE_TARGETS); do \
		cpu=(); case "$$target" in mips*) cpu=(-Dcpu=mips32r2);; esac; \
		zig build -Dtarget="$$target" "$${cpu[@]}" -Doptimize=$(RELEASE_OPT) -Dstrip=true --cache-dir ".zig-cache/release/$$target" --prefix "zig-out/release/$$target"; \
	done

install: release
	$(INSTALL) -d -o root -g root -m 0755 $(PREFIX)/bin
	$(INSTALL) -o root -g root -m 0755 zig-out/bin/fail2zig $(PREFIX)/bin/fail2zig
	@echo "installed to $(PREFIX)/bin — run scripts/install.sh for full system setup"

clean:
	rm -rf zig-out .zig-cache

fuzz:
	zig build test-ci-fuzz -Doptimize=ReleaseSafe -j$(ZIG_JOBS)

harness-smoke:
	tests/harness/reset.sh
	tests/harness/ssh_brute.sh

lint: fmt-check
	shellcheck -S warning tests/harness/*.sh tests/e2e/*.sh scripts/install.sh .github/scripts/*.sh
	yamllint -c .yamllint .github/workflows/
	yamllint -d '{extends: .yamllint, rules: {line-length: disable}}' .github/ISSUE_TEMPLATE/
