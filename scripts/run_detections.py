#!/usr/bin/env python3
"""Run every detections/*.spl search against Splunk and print the hits.

Each .spl file is sent as-is (its ``` comment blocks are valid SPL comments),
over all time, via the REST export endpoint.

Usage: python3 scripts/run_detections.py [detections-dir ...] [--check tests/expected_results.json]
"""
import base64
import json
import pathlib
import ssl
import sys
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def load_env():
    env = {}
    for line in (ROOT / ".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def search(env, spl):
    auth = base64.b64encode(f"admin:{env['SPLUNK_PASSWORD']}".encode()).decode()
    body = urllib.parse.urlencode({
        "search": "search " + spl if not spl.lstrip().startswith(("|", "search")) else spl,
        "output_mode": "json", "earliest_time": "0", "latest_time": "now",
    }).encode()
    req = urllib.request.Request("https://127.0.0.1:8089/services/search/v2/jobs/export", body,
                                 headers={"Authorization": f"Basic {auth}"})
    rows, messages = [], []
    with urllib.request.urlopen(req, context=CTX, timeout=300) as r:
        for line in r:
            if not line.strip():
                continue
            obj = json.loads(line)
            if obj.get("result"):
                rows.append(obj["result"])
            messages += [m.get("text") for m in obj.get("messages", []) if m.get("type") in ("ERROR", "FATAL")]
    return rows, messages


def main():
    args = sys.argv[1:]
    expected = {}
    if "--check" in args:
        i = args.index("--check")
        expected = json.loads(pathlib.Path(args[i + 1]).read_text())
        del args[i:i + 2]

    env = load_env()
    dirs = [pathlib.Path(d) for d in args] or [ROOT / "detections"]
    failures = []
    for spl_file in sorted(p for d in dirs for p in d.glob("*.spl")):
        rows, errors = search(env, spl_file.read_text())
        print(f"\n=== {spl_file.name}: {len(rows)} result(s) ===")
        for e in errors:
            print(f"  SPL ERROR: {e}")
            failures.append(f"{spl_file.name}: SPL error")
        for row in rows[:10]:
            print("  " + json.dumps(row)[:300])
        want = expected.get(spl_file.stem)
        if want is not None and len(rows) < want:
            failures.append(f"{spl_file.name}: expected at least {want} result(s), got {len(rows)}")

    if failures:
        print("\nFAILED:\n  " + "\n  ".join(failures))
        sys.exit(1)
    if expected:
        print("\nAll detections met their expected minimum result counts.")


if __name__ == "__main__":
    main()
