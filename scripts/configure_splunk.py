#!/usr/bin/env python3
"""One-time Splunk setup for the lab. Safe to re-run.

- Creates the winlogs index
- Lets the HEC token write to it
- Opts out of Splunk's product usage telemetry (on by default)

Usage: python3 scripts/configure_splunk.py
"""
import base64
import pathlib
import ssl
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
INDEX = "winlogs"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # Splunk's default self-signed cert; localhost only


def load_env():
    env = {}
    for line in (ROOT / ".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def post(env, path, data):
    auth = base64.b64encode(f"admin:{env['SPLUNK_PASSWORD']}".encode()).decode()
    req = urllib.request.Request(f"https://127.0.0.1:8089{path}", urllib.parse.urlencode(data).encode(),
                                 headers={"Authorization": f"Basic {auth}"})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def main():
    env = load_env()
    status = post(env, "/services/data/indexes", {"name": INDEX})
    print(f"index {INDEX}: " + ("created" if status == 201 else "already exists" if status == 409 else f"HTTP {status}"))

    status = post(env, "/servicesNS/nobody/splunk_httpinput/data/inputs/http/splunk_hec_token",
                  {"indexes": f"main,{INDEX}", "index": INDEX})
    print(f"HEC token allowed indexes: HTTP {status}")

    status = post(env, "/servicesNS/nobody/splunk_instrumentation/admin/telemetry/general", {
        "sendAnonymizedUsage": "false",
        "sendAnonymizedWebAnalytics": "false",
        "sendLicenseUsage": "false",
        "sendSupportUsage": "false",
        "precheckSendAnonymizedUsage": "false",
        "precheckSendLicenseUsage": "false",
        "precheckSendSupportUsage": "false",
        "showOptInModal": "false",
        "optInVersionAcknowledged": "4",
    })
    print(f"telemetry opt-out: HTTP {status}")


if __name__ == "__main__":
    main()
