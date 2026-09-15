# fail2ban configuration fixtures

Reference profile: fail2ban 1.1.1 (`jail.conf`, `jail.d/`, `jail.local`, `filter.d/`,
`action.d/` layering and `%(name)s` interpolation as documented in the upstream
`jail.conf` header and the `fail2ban-client`/`jail.conf(5)` manual pages).

All files are original, minimal, hand-written derivations of that documented format.
No file was copied from the upstream fail2ban tree; option names and the `action_`
template stanza follow the public reference layout only. Regex and script paths are
illustrative. Any stanza resembling upstream text is limited to option names and
is used under the AGPL-3.0-or-later terms of this repository.

Every file is under 2 KiB. Trees:

- `supported/` — sshd (journal) and nginx-http-auth (file) enabled, stock filters
  absent, `nftables-allports` banaction, `jail.d` and `jail.local` overrides.
- `operator-change/` — hostname in `ignoreip`, `bantime.increment`, locally edited
  `filter.d/sshd.conf` plus an `sshd.local` overlay.
- `blocker/` — custom filter `myapp`, action with a custom script, `ignorecommand`,
  interpolation cycle between `bantime` and `findtime`.
- `disabled/` — only disabled or implicitly disabled groups, one unknown key.

Secret review: the files contain no credentials, tokens, real hostnames, customer
addresses or private log data. Addresses are loopback and documentation-only names.
Inspection tests read these files and never modify them.

## `stock-1.1.1/` — verbatim upstream files

`jail.conf`, `fail2ban.conf`, `paths-common.conf`, `paths-debian.conf`, `filter.d/sshd.conf`,
`filter.d/common.conf`, `action.d/nftables.conf`, `action.d/nftables-allports.conf` and
`action.d/nftables-multiport.conf` are byte-identical copies from the pinned fail2ban 1.1.1
reference tree (`/tmp/fail2ban-parity-reference-1.1.1/config`, upstream GPL-2.0-or-later,
Copyright the Fail2Ban authors). They are retained unmodified so the stock-asset SHA-256 table
in `engine/migration/inspect.zig` can be exercised against real bytes; any edit to them is a
test of the "modified" path and must be made on a temporary copy. `jail.d/lab.conf` is an
original minimal override (polling backend, nftables banaction, sshd enabled on a documentation
path) mirroring the lab rehearsal. No secrets, hostnames or private log data are included.
