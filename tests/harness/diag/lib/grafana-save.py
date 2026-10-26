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


def response_summary(data, http_status=None, transport_error=None):
    summary = {"http_status": http_status, "frames": 0, "rows": 0}
    if transport_error is not None:
        summary.update({"result": "datasource_error", "error": str(transport_error)[:240]})
        return summary
    if http_status is not None:
        summary["result"] = "http_error"
        return summary
    try:
        payload = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        summary["result"] = "unrecognized_response"
        return summary

    if isinstance(payload, dict) and payload.get("error"):
        summary.update({"result": "datasource_error", "error": str(payload["error"])[:240]})
        return summary
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, dict):
        summary["result"] = "unrecognized_response"
        return summary
    if not results:
        summary["result"] = "empty_response"
        return summary

    has_frames_field = False
    for result in results.values():
        if not isinstance(result, dict):
            continue
        if result.get("error"):
            summary.update({"result": "datasource_error", "error": str(result["error"])[:240]})
            return summary
        frames = result.get("frames")
        if not isinstance(frames, list):
            continue
        has_frames_field = True
        summary["frames"] += len(frames)
        for frame in frames:
            values = frame.get("data", {}).get("values", []) if isinstance(frame, dict) else []
            if isinstance(values, list):
                summary["rows"] += max((len(column) for column in values if isinstance(column, list)), default=0)

    if summary["frames"] and summary["rows"]:
        summary["result"] = "frames_with_rows"
    elif has_frames_field:
        summary["result"] = "empty_response"
    else:
        summary["result"] = "unrecognized_response"
    return summary


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
    panel_results = []
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
            result = response_summary(data)
        except urllib.error.HTTPError as err:
            data = err.read()
            result = response_summary(data, http_status=err.code)
        except urllib.error.URLError as err:
            data = json.dumps({"transport_error": str(err.reason)}).encode()
            result = response_summary(data, transport_error=err.reason)
        open(os.path.join(out, name), "wb").write(data)
        saved.append(name)
        panel_results.append({"panel_id": panel["id"], "title": panel.get("title", ""), "file": name, **result})
    summary_path = os.path.join(out, "panel-results.json")
    with open(summary_path, "w") as summary_file:
        json.dump(panel_results, summary_file, indent=2)
        summary_file.write("\n")
    print(f"grafana: no image renderer; saved data of {len(saved)} panels as JSON; panel results in panel-results.json; {link}")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit("usage: grafana-save.py ENV_FILE FROM_MS TO_MS OUT_DIR")
    main(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
