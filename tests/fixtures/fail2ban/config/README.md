# fail2ban configuration fixtures

Configuration trees in the fail2ban format, read by the migration tests. Every
hand-written file is under 2 KiB. Inspection tests read these files and never
modify them.

- `supported/`: sshd (journal) and nginx-http-auth (file) enabled, no filter
  files, `nftables-allports` banaction, `jail.d` and `jail.local` overrides.
- `operator-change/`: a hostname in `ignoreip`, `bantime.increment`, a locally
  edited `filter.d/sshd.conf` and an `sshd.local` overlay.
- `blocker/`: a custom filter `myapp`, an action with a custom script,
  `ignorecommand`, and an interpolation cycle between `bantime` and `findtime`.
- `cutover/`: sshd on the polling backend with `/var/log/auth.log` and the
  `nftables` banaction, declared in `jail.conf` and enabled by `jail.d/lab.conf`;
  no filter or action files.

The files contain no credentials, tokens, real hostnames, customer addresses or
private log data. Addresses are loopback or documentation ranges.
