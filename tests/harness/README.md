# System harness

Use [independent acceptance modules](acceptance/README.md) for current daemon,
firewall, migration, restart and load qualification. Select one module with an
explicit candidate hash and a new work directory. These tests run in owned
namespaces and do not modify the installed service.

`load_repro/` contains the retained BUG-075 incident generator and raw kernel
oracle. It is investigative material; the acceptance runner is the entry point
for new checks.

The superseded reset, injection, observation and measurement chain was removed.
Its reset command stopped the installed service and cleared state and firewall
rules, so it is no longer a Makefile entry. `ssh_brute.sh` remains a manual
peer-origin packet-path check that requires an authorized disposable host; the
current namespace modules use local blocked and reachable controls.

Shell files are checked by `make lint`. Python in this directory is harness
tooling only and is not part of the fail2zig executable.
