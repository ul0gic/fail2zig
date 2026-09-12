# Original journal fixtures

`fixtures.tar.gz` contains three benign synthetic records in each of four journal files:
uncompressed, XZ, LZ4 and Zstandard. It also contains the original input export.
Messages contain a sequence label and 4,096 `X` bytes; sequence 1 and 3 are marked `deny`,
and sequence 2 is marked `allow`. Timestamps are exact integer microseconds.

Generated offline using systemd-journal-remote 257.13-1~deb13u1 for the project's earlier
reader experiment. This is an unchanged copy of the original fixture archive, reused to
qualify the now-accepted host journalctl integration. No customer logs are included.

Archive SHA-256: `717fd00ed439b816379165bef030158de18db75e31cac057e39e6bfec1594f76`.
The Zig tests unpack it into disposable directories. Tests read only these files and never
read or modify the host's live journal. Host journalctl with the fixture codecs is required;
its absence is a visible test skip, not a support pass. No regeneration tool is needed.

`legacy-fixtures.tar.gz` adds the same original export in non-compact journal format,
for older journalctl versions. Generated offline with the same extracted 257.13 producer,
`SYSTEMD_JOURNAL_COMPACT=0`, `--split-mode=none --seal=no`, and
`SYSTEMD_JOURNAL_COMPRESS=no|XZ|LZ4|ZSTD`. Header inspection confirms the four selected
compression modes and absence of the COMPACT flag. The original archive is unchanged.

Legacy archive SHA-256: `6d30b4e99457c65e417501d461cc3a087f6181d9ad9ec93be6c02329118f9bca`.

For command-version qualification, the test-only `FAIL2ZIG_TEST_JOURNALCTL` variable selects
an absolute executable path; an explicitly selected missing executable fails rather than
skipping. `FAIL2ZIG_TEST_JOURNAL_FIXTURES` selects an alternate archive. Neither variable
changes daemon configuration. Tests still read only disposable fixture journals. Extracted
OS tools may need their matching shared library path in the test process environment;
they are not installed, linked into fail2zig, or added as application dependencies.

Systemd 249 rejects the compact archive with `Protocol not supported` and passes the five
contract tests using the non-compact archive. Systemd 252/255/257 compatibility results are
recorded separately. Running another distribution's executable and matching systemd library
on the development host qualifies that command/format combination, not a complete booted
distribution, service unit, permissions model or live journal deployment.
