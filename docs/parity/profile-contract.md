# Reference and dependency profiles

Status: P0 selection for qualification; no profile is certified by this document.
The primary semantics reference is fail2ban 1.1.1 at
`f60978618a101427b06924fc932b44350fec2b63`. The secondary upstream source is 1.1.0 at
`61799e15e1dd4389dea0cc7595da0a287835a177`. Both annotated tags verified against the
maintainer's published key; that records the verification basis, not an independent
web-of-trust assertion. Source hashes and GPL license notices accompany the evidence.

## Selected environments

| Profile | Selected userland/source | Qualification purpose |
|---|---|---|
| Primary development reference | Actual Debian 13 x86_64 host, Python 3.13.5, SQLite 3.46.1, Zig 0.14.1, kernel 6.12.107+deb13-amd64 | Existing isolated config/matcher/contract probes; host fingerprints are not a container image |
| Debian 12 | Official bookworm-slim Linux amd64 image, immutable platform digest | Older Python/backend and packaged fail2ban differences |
| Debian 13 | Official trixie-slim Linux amd64 image, immutable platform digest | Primary new disposable-userland baseline |
| Ubuntu 22.04 | Official 22.04 Linux amd64 image, immutable platform digest | LTS Python 3.10 and older distribution semantics |
| Ubuntu 24.04 | Official 24.04 Linux amd64 image, immutable platform digest | LTS Python 3.12 and distribution semantics |
| Enterprise Linux 9 | Official Rocky Linux 9-minimal Linux amd64 image, immutable platform digest | RPM/EPEL, SELinux and systemd qualification |
| OpenWrt/musl | Fixed historical OpenWrt 24.10.0 x86_64 rootfs and SHA256 | musl/procd/native packaging feasibility; not a current deployment recommendation |
| Published lab baseline | Existing f2z-target Debian 13 host, fail2zig 0.3.0 | Future separately isolated kernel/enforcement checks; do not replace automatically |

P0 downloaded and hashed the five OCI manifest/config/layer chains, inspected regular-file
OS/package metadata without extracting an executable root or starting a container, and
recorded 477 installed package identities. OpenWrt's rootfs metadata records 129 packages.
These counts describe selected userlands; they are not fail2zig dependencies or successful
test cases. Container files do not supply a running guest kernel or init system.

Repository metadata also selects exact source-package candidates: Debian 12 fail2ban
1.0.2-2, Debian 13 1.1.0-8, Ubuntu 22.04 0.11.2-6, Ubuntu 24.04 1.0.2-3 and EPEL 9
1.1.0-6.el9, with archive checksums and related package records. These are recorded
repository inputs, **not installed, dependency-complete recipes**. In particular, Ubuntu
base-suite libc candidates differ from newer libraries already in the chosen images.
Provisioning must select explicit updates/security pockets and solve a compatible lock;
it must not force a list of older repository candidates onto an image.

Primary metadata origins are the [Docker official-image registry](https://hub.docker.com/_/debian),
[Debian repository](https://deb.debian.org/debian/dists/),
[Ubuntu repository](https://archive.ubuntu.com/ubuntu/dists/),
[EPEL 9 repository](https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/repodata/repomd.xml)
and [OpenWrt 24.10.0 rootfs index](https://downloads.openwrt.org/releases/24.10.0/targets/x86/64/).
The local P0 evidence retains exact URLs, digests, package versions, manifest bytes and
metadata hashes. HTTPS/digest integrity was checked; OCI/rootfs publisher signatures and
repository signature trust are separate provisioning checks. Source tag signature
verification is recorded separately and must not be inferred for these image publishers.

## Native and full compatibility profiles

The native profile keeps the compiled matcher/native netlink fast paths where their
effective semantics are verified. nftables netlink needs kernel capability, not an nft
executable. Journald requires the selected journal reader/runtime; current native ingestion
uses journalctl. iptables/ipset backends require their exact executable/dependency closure.
The absence of Python in a native workload does not qualify that workload as full parity.

The full profile selects the [runtime contract](runtime-contract.md): pinned CPython
matching/date/codec and trusted expression semantics, separately activated action service,
and versioned SQLite WAL/FULL state storage. Migration uses an optional read-only SQLite
export helper and the version-specific source adapter. Include all helper processes,
libraries, cgroups, credentials and external commands in qualification and performance
accounting. No zero-runtime-dependency claim applies to this profile.

Every activated workload produces a dependency lock with the base image/source pin,
interpreter/module closure, backend bindings, SQLite library, external executables,
action assets, locale/timezone/services database and provider API/account scope. Source
config is extensible: arbitrary administrator-owned actions can introduce dependencies.
Do not pretend one finite stock package list enumerates all future custom imports.
Missing dependencies or unavailable privileges are explicit activation/qualification
blockers. Inspect/plan never executes imported expressions or extensions to discover them.

The exact Python version is part of the semantics profile, including optional SMTP
libraries and available regex/date behavior. The reference backend list is pyinotify,
polling and systemd. Record availability/fallback from actual bindings; the native
`gamin` compatibility alias is not evidence of an upstream 1.1.1 gamin backend.

## Platform and provider applicability

Linux-readable log/filter data stays applicable even when a service or sample originated
on another operating system. Native BSD/macOS/Solaris firewall actions need that platform's
own kernel acceptance and remain explicitly platform-qualified. Linux-hosted remote
provider/notification integrations remain applicable when configured; unavailable test
accounts do not make them not-applicable. Original local API/mail recorders establish
request semantics only, never real provider success.

Select systemd for Debian/Ubuntu/Rocky qualification, procd for OpenWrt, and an explicit
OpenRC service-contract fixture profile. Image metadata alone cannot verify any init
behavior. Record actual booted kernel/build/config, namespaces/capabilities, firewall
tools, systemd/journal versions, cgroup v2 delegation, locale and clock settings before
running environment-dependent cases. Missing booted-platform capacity remains visible.

The 137 tracked-file differences between upstream 1.1.0 and 1.1.1 now have 568 hunk
records, symbol/option associations, assessed behavioral or non-runtime roles and named
acceptance specifications. Packaging/documentation changes stay distinct from runtime changes.

P0 also inspected the selected source archives and distribution packaging: 53 patch
artifacts, comprising 48 active and five inactive patches, plus 47 packaging behavior
contracts. Four Debian/Ubuntu binary archives were downloaded and their checksums/control
versions verified; the enterprise profile has source-RPM/spec evidence, not inspected
binary RPM bytes. Patch presence does not imply application. Package build rules that
ignore test failures cannot establish passing reference behavior. None of these source
audits executes patches, builds, maintainer scripts or sample records.

Distribution source patches/defaults now have separate source-assessed acceptance rows;
their actual behavior still requires comparison before that source profile is certified.
Pin changes produce a reviewed
profile delta; they never silently change the oracle for existing evidence.

## Provisioning and certification gates

P0 selects and inventories profiles. P1 builds disposable runners and produces
solver-complete, publisher-verified locks for each selected execution environment; it
records unavailable environments explicitly. P2–P7 provide behavior evidence, and P8
certifies kernels/backends, recovery, whole-process performance and soak behavior.
The full profile's required behavior remains blocked if an interpreter/extension/source
handover constraint cannot be satisfied. A selected image, package candidate, cross-build
or successful version command cannot close those gates.
