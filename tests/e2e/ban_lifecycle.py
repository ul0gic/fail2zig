#!/usr/bin/env python3

import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary_dir = pathlib.Path(sys.argv[1]).resolve()
backend = sys.argv[2] if len(sys.argv) > 2 else "nftables"
work = pathlib.Path(tempfile.mkdtemp(prefix="f2z-acceptance-"))
print(f"evidence_dir={work}", flush=True)
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
subprocess.run(["ip", "address", "add", "192.0.2.42/32", "dev", "lo"], check=True)
subprocess.run(["ip", "-6", "address", "add", "2001:db8::42/128", "dev", "lo", "nodad"], check=True)
log = work / "auth.log"
log.touch()
(work / "other.log").touch()
config = work / "config.toml"
config.write_text(f'''[global]
socket_path = "{work}/daemon.sock"
state_file = "{work}/state.bin"
metrics_enabled = false
firewall = "{backend}"
[defaults]
maxretry = 3
findtime = 60
bantime = 30
[jails.sshd]
enabled = true
filter = "sshd"
source = "file"
logpath = ["{log}"]
bantime = 5
[jails.other]
enabled = true
filter = "sshd"
source = "file"
logpath = ["{work}/other.log"]
bantime = 7
''')
config.chmod(0o600)
server = socket.socket()
server.bind(("127.0.0.1", 18081))
server.listen()

def serve(listener):
    while True:
        try:
            peer, _ = listener.accept()
            peer.close()
        except OSError:
            return

threading.Thread(target=serve, args=(server,), daemon=True).start()
server6 = socket.socket(socket.AF_INET6)
server6.bind(("::1", 18081))
server6.listen()
threading.Thread(target=serve, args=(server6,), daemon=True).start()

def connects():
    with socket.socket() as peer:
        peer.settimeout(0.3)
        peer.bind(("192.0.2.42", 0))
        try:
            peer.connect(("127.0.0.1", 18081))
            return True
        except socket.timeout:
            return False

def connects6():
    with socket.socket(socket.AF_INET6) as peer:
        peer.settimeout(0.3)
        peer.bind(("2001:db8::42", 0))
        try:
            peer.connect(("::1", 18081))
            return True
        except socket.timeout:
            return False


def client(*args):
    result = subprocess.run([str(binary_dir / "fail2zig-client"), "--socket", str(work / "daemon.sock"), "--output", "json", *args], capture_output=True, text=True, timeout=6)
    print(json.dumps({"command": args, "code": result.returncode, "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}), flush=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)

def wait_for(check, limit=8):
    end = time.monotonic() + limit
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.1)
    return False

with (work / "daemon.log").open("w") as output:
    daemon = subprocess.Popen([str(binary_dir / "fail2zig"), "--foreground", "--config", str(config)], stdout=output, stderr=output)
    try:
        assert wait_for(lambda: (work / "daemon.sock").exists()), "daemon did not start"
        assert connects(), "baseline connectivity"
        print("PASS baseline TCP connectivity", flush=True)
        client("version")
        client("status")
        with log.open("a") as fixture:
            for port in (40001, 40002, 40003):
                fixture.write(f"Failed password for fixture-user from 192.0.2.42 port {port} ssh2\n")
        assert wait_for(lambda: not connects(), 3), "automatic ban did not block packets"
        print("PASS automatic fixture ban blocks TCP", flush=True)
        assert len(client("list")) == 1
        assert len(client("list", "--jail", "sshd")) == 1
        client("status")
        assert wait_for(connects), "automatic expiry did not restore connectivity"
        print("PASS automatic expiry restores TCP", flush=True)
        client("list")
        client("ban", "192.0.2.42", "--jail", "sshd", "--duration", "3")
        assert not connects(), "manual ban did not block packets"
        print("PASS explicit-duration manual ban blocks TCP", flush=True)
        assert len(client("list")) == 1
        assert client("status")["active_bans"] == 1
        assert wait_for(connects), "manual expiry did not restore connectivity"
        print("PASS explicit-duration manual expiry restores TCP", flush=True)
        assert client("ban", "192.0.2.42", "--jail", "sshd")["duration"] == 5
        assert not connects()
        client("unban", "192.0.2.42", "--jail", "sshd")
        assert connects()
        print("PASS manual jail default and unban", flush=True)
        client("ban", "192.0.2.42", "--jail", "sshd", "--duration", "2")
        client("ban", "192.0.2.42", "--jail", "other", "--duration", "10")
        client("ban", "192.0.2.42", "--jail", "other", "--duration", "10")
        assert len(client("list")) == 2
        assert client("status")["active_bans"] == 2
        time.sleep(3)
        assert not connects(), "short expiry removed longer ownership"
        assert len(client("list")) == 1
        daemon.terminate()
        daemon.wait(timeout=5)
        daemon = subprocess.Popen([str(binary_dir / "fail2zig"), "--foreground", "--config", str(config)], stdout=output, stderr=output)
        assert wait_for(lambda: (work / "daemon.sock").exists())
        assert len(client("list", "--jail", "other")) == 1
        assert not connects()
        client("unban", "192.0.2.42", "--jail", "other")
        assert connects()
        assert client("status")["active_bans"] == 0
        print("PASS overlapping ownership, duplicate apply, restart and final unban", flush=True)
        assert connects6()
        client("ban", "2001:db8::42", "--jail", "sshd", "--duration", "2")
        assert not connects6()
        assert len(client("list", "--jail", "sshd")) == 1
        assert wait_for(connects6)
        print("PASS IPv6 manual ban, listing and expiry", flush=True)
        with socket.socket() as metrics_probe:
            metrics_probe.settimeout(0.3)
            assert metrics_probe.connect_ex(("127.0.0.1", 9100)) != 0
        print("PASS metrics disabled: no listener", flush=True)
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()
        server.close()
        server6.close()
        print((work / "daemon.log").read_text(), flush=True)
