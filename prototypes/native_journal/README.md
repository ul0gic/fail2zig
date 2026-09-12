# Isolated embedded journal experiment

N1 feasibility only. No daemon integration, source replacement, dependency adoption or
release qualification follows from this experiment. Application/probe code is Zig 0.14.1.
No Python code or new build framework was added or executed for this experiment.

The x86_64 glibc experiment passed four fixture variants in an isolated root containing
two probe executables and four original synthetic journal files, with no installed libraries
or helpers inside it. For each variant the probe checks three exact record bodies, closes
and reopens a saved cursor, and selects the two records matching F2Z_KIND=deny.

| Link variant | Uncompressed | XZ | LZ4 | Zstandard |
|---|---|---|---|---|
| Unmodified packaged static libsystemd plus libcap | Pass | Field read fails | Field read fails | Field read fails |
| Same reader with statically linked codecs and experimental loader wrappers | Pass | Pass | Pass | Pass |

Each compressed fixture contains three actually compressed DATA objects. This was checked
from the generated object flags, not inferred solely from its filename/header. The final
reader traces show fixture opens and an unsuccessful /proc/self/exe lookup, with no subsequent
process creation or shared-library opens. ELF inspection shows no interpreter/dynamic section.
This result applies to the exercised file-reader paths; it does not qualify every libsystemd API.

## Components and limits

The experiment uses extracted Debian packages, not a new source build or production vendor
directory. No packages were installed on the host. Linked archives: libsystemd, libcap,
liblzma, liblz4, libzstd and libxxhash, plus glibc facilities and Zig compiler runtime.
These are the experiment's components, not a proven minimal production dependency set.
Package hashes and license inventories are retained in local planning evidence.

static_codecs.zig intercepts the archive's dlopen/dlsym/dlclose/dlerror calls at link time.
It provides a closed table of embedded codec symbols and refuses other dynamic libraries.
This is a feasibility adaptation for prebuilt objects, not an approved production loader.
A production source build should make static codec linkage explicit and review every retained
path. The GNU linker also warns about glibc account lookup facilities elsewhere in the archive;
passing these isolated file tests does not settle those unexercised paths.

Reusing these glibc-built archives in a musl link failed on glibc-specific symbols. This does
not prove upstream source cannot target musl. A reproducible source build, selected target
matrix, exact source/patch/license inventory and full source lifecycle testing remain open.
No glibc compatibility shim was written to force that link. Upstream's documented build uses
Meson/Python; this experiment did not adopt it as project tooling. A future source-build
approach must explicitly resolve the project's build/tooling constraints.

The fixture producer was the previously extracted Debian systemd-journal-remote executable,
used offline against an original export file; journalctl inspected fixture headers. Those are
test setup tools, absent from the isolated reader environment. No live journals, system
configuration, services, lab hosts or firewall state were changed.

## Reproduction

This receipt's temporary work directory is /tmp/f2z-n1-journal.EGsjgY; it may be removed by
the host. Durable local evidence is .project/parity/evidence/n1-journal, including an archive
of the exact fixtures. The adjacent JSON receipt identifies package/source/binary hashes.
For a new run, use a fresh scratch directory and extract the recorded development packages
with dpkg-deb -x. Do not install them or add their archives to the main build.

From the repository root, compile the two objects (replace WORK with that scratch directory):

```sh
zig build-obj prototypes/native_journal/probe.zig -O ReleaseSafe -lc -fcompiler-rt -femit-bin=WORK/probe.o
zig build-obj prototypes/native_journal/static_codecs.zig -O ReleaseSafe -lc -femit-bin=WORK/static_codecs.o
```

From WORK, with extracted packages under extracted/:

```sh
cc -static -o journal-probe-baseline probe.o -L extracted/usr/lib/x86_64-linux-gnu -lsystemd -lcap -lm -lpthread -ldl
cc -static -o journal-probe-static probe.o static_codecs.o -L extracted/usr/lib/x86_64-linux-gnu -Wl,--wrap=dlopen,--wrap=dlsym,--wrap=dlclose,--wrap=dlerror -Wl,--start-group -lsystemd -lcap -llzma -llz4 -lzstd -lxxhash -lm -lpthread -ldl -Wl,--end-group
```

Copy only those binaries and the extracted fixture journals into empty-root/. For each codec
(none, XZ, LZ4, ZSTD), run both variants with the following command, substituting their names:

```sh
strace -f -e trace=file,process -o run.trace unshare --user --map-root-user --mount /usr/sbin/chroot empty-root /journal-probe-static /XZ.journal
```

This requires unprivileged user namespaces. Inspect trace entries after the probe execve;
the host's unshare/chroot setup naturally uses host libraries before entering the empty root.
Do not count setup activity as reader activity or treat a failed isolation command as a
reader failure. All static-codec variants must return zero; baseline compressed variants
must return one with FieldFailed. The baseline uncompressed variant must return zero.

The fixture archive is sufficient to repeat the reader test. To regenerate fixtures, produce
three export records with F2Z_SEQUENCE=1/2/3, F2Z_KIND=deny/allow/deny and MESSAGE=fixture-N-
followed by 4096 X characters. Use stable increasing realtime/monotonic timestamps and one
boot ID. Run systemd-journal-remote with --split-mode=none --seal=no, setting
SYSTEMD_JOURNAL_COMPRESS to XZ/LZ4/ZSTD for compressed variants and --compress=no for none.
Always inspect actual compression flags before reporting codec coverage.
