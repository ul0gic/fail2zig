#!/usr/bin/env -S python3 -I
# Usage: grafana-save.py ENV_FILE FROM_MS TO_MS OUT_DIR  — PNG of the overview dashboard, or its panel data as JSON without a renderer.
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request

GRAFANA = "http://172.16.150.252:3000"
DASHBOARD = "f2z-target-overview"


def env(path):
    values = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def main(env_file, start, end, out):
    e = env(env_file)
    auth = "Basic " + base64.b64encode(f"{e['GRAFANA_ADMIN_USER']}:{e['GRAFANA_ADMIN_PASSWORD']}".encode()).decode()

    def call(path, body=None):
        req = urllib.request.Request(GRAFANA + path, data=json.dumps(body).encode() if body else None,
                                     headers={"Authorization": auth, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()

    os.makedirs(out, exist_ok=True)
    link = f"{GRAFANA}/d/{DASHBOARD}?from={start}&to={end}"
    try:
        call("/api/plugins/grafana-image-renderer/settings")
        renderer = True
    except urllib.error.HTTPError:
        renderer = False
    if renderer:
        png = call(f"/render/d/{DASHBOARD}?from={start}&to={end}&width=1600&height=2400&kiosk=true")
        open(os.path.join(out, "overview.png"), "wb").write(png)
        print(f"grafana: rendered overview.png ({len(png)} bytes); {link}")
        return
    dashboard = json.loads(call(f"/api/dashboards/uid/{DASHBOARD}"))["dashboard"]
    saved = []
    for panel in dashboard.get("panels", []):
        targets = panel.get("targets")
        if not targets:
            continue
        queries = []
        for target in targets:
            q = dict(target)
            q.setdefault("datasource", panel.get("datasource"))
            q.update({"intervalMs": 5000, "maxDataPoints": 1000})
            queries.append(q)
        name = f"{panel['id']:02d}-{re.sub(r'[^a-z0-9]+', '-', panel.get('title', '').lower()).strip('-')[:48]}.json"
        try:
            data = call("/api/ds/query", {"from": str(start), "to": str(end), "queries": queries})
        except urllib.error.HTTPError as err:
            data = json.dumps({"error": err.code, "body": err.read()[:500].decode(errors="replace")}).encode()
        open(os.path.join(out, name), "wb").write(data)
        saved.append(name)
    print(f"grafana: no image renderer; saved data of {len(saved)} panels as JSON; {link}")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit("usage: grafana-save.py ENV_FILE FROM_MS TO_MS OUT_DIR")
    main(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
