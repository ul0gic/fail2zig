#!/usr/bin/env python3
"""Independent kernel/text/TCP and SQLite assertions for retained B6 scenario."""
import ipaddress
import json
from pathlib import Path
import shlex
import socket
import sqlite3
import sys
import time

mode, *args = sys.argv[1:]
subjects = {'198.18.0.1', '198.18.0.2', '198.18.0.3'}

def require(value, message):
    if not value:
        raise SystemExit(message)

def owners(db):
    with sqlite3.connect(Path(db).as_uri() + '?mode=ro', uri=True) as c:
        return [list(r) for r in c.execute('SELECT hex(scope_key),jail,lease_kind,deadline_us FROM effect_owners ORDER BY 1,2')]

if mode == 'listen':
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('198.19.0.254', 0))
        server.listen(32)
        Path(args[0]).write_text(str(server.getsockname()[1]))
        while True:
            conn, _ = server.accept()
            conn.close()
elif mode == 'tcp':
    port = int(Path(args[0]).read_text())
    for source in sorted(subjects) + ['198.19.0.1']:
        with socket.socket() as probe:
            probe.settimeout(0.5)
            probe.bind((source, 0))
            try:
                probe.connect(('198.19.0.254', port))
                reachable = True
            except (socket.timeout, ConnectionRefusedError, OSError):
                reachable = False
        expected = args[1] == 'open' or source not in subjects
        require(reachable == expected, f'TCP {source}: reachable={reachable}, expected={expected}')
elif mode == 'members':
    backend, path, wanted = args
    seen = []
    for line in Path(path).read_text().splitlines():
        words = shlex.split(line)
        value = None
        if backend == 'nftables' and words[:1] == ['elem']:
            value = words[1]
        elif backend == 'iptables' and words[:1] == ['-A'] and '-s' in words and '-j' in words:
            if words[words.index('-j') + 1] == 'DROP':
                value = words[words.index('-s') + 1]
        elif backend == 'ipset' and words[:1] == ['add']:
            value = words[2]
        if value:
            network = ipaddress.ip_network(value, strict=False)
            require(network.version == 4 and network.prefixlen == 32, 'unexpected non-host IPv4 membership')
            seen.append(str(network.network_address))
    expected = subjects if wanted == 'present' else set()
    require(set(seen) == expected and len(seen) == len(expected), f'kernel members {seen}; expected {sorted(expected)}')
elif mode == 'status':
    data = json.loads(Path(args[0]).read_text())
    require(data.get('storage') == 'healthy' and data.get('protection') == 'active', 'unhealthy status/protection')
elif mode == 'snapshot':
    snapshot = owners(args[0])
    require(len(snapshot) == 3 and all(r[3] is not None for r in snapshot), 'expected three finite owner deadlines')
    require(min(r[3] for r in snapshot) > time.time_ns() // 1000 + 15_000_000, 'insufficient remaining lifetime for restart qualification')
    Path(args[1]).write_text(json.dumps(snapshot))
elif mode == 'deadlines':
    snapshot = json.loads(Path(args[1]).read_text())
    require(owners(args[0]) == snapshot, 'restart changed owners/original deadlines')
    require(min(r[3] for r in snapshot) > time.time_ns() // 1000, 'restart finished after original expiry')
elif mode == 'expiry_end':
    snapshot = json.loads(Path(args[0]).read_text())
    end = max(r[3] for r in snapshot) // 1_000_000 + 1
    require(end < time.time() + 360, 'expiry wait exceeds scenario budget')
    print(end)
else:
    raise SystemExit('unknown check mode')
