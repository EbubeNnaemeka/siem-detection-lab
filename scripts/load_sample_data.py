#!/usr/bin/env python3
"""Load converted Windows event logs (JSON lines) into Splunk via HEC.

Input: one JSON object per line, as produced by scripts/convert_evtx.py.
Adds the field names the Splunk Add-on for Windows would normally extract
(Account_Name, src_ip, Service_Name, Ticket_Encryption_Type) so the
detections in detections/ can run unchanged against sample data.

Run scripts/configure_splunk.py first (creates the index, enables HEC for it).

Usage: python3 scripts/load_sample_data.py events.json
"""
import datetime
import json
import pathlib
import ssl
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
INDEX = "winlogs"
BATCH = 500

# Splunk's default certs are self-signed; only ever talk to localhost.
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


def ta_fields(ev):
    """Approximate the Windows add-on's field aliases."""
    if ev.get("TargetUserName"):
        ev["Account_Name"] = ev["TargetUserName"]
    if ev.get("IpAddress"):
        ev["src_ip"] = ev["IpAddress"].removeprefix("::ffff:")
    if ev.get("EventCode") == "4769" and ev.get("ServiceName"):
        ev["Service_Name"] = ev["ServiceName"]
    if ev.get("TicketEncryptionType"):
        ev["Ticket_Encryption_Type"] = ev["TicketEncryptionType"]
    return ev


def to_hec(ev):
    ts = datetime.datetime.fromisoformat(ev.pop("_time").replace("Z", "+00:00")).timestamp()
    return {
        "time": ts,
        "host": ev.get("host") or "unknown",
        "source": ev.get("Channel") or "unknown",
        "sourcetype": "_json",
        "index": INDEX,
        "event": ev,
    }


def send(env, batch):
    body = "\n".join(json.dumps(e) for e in batch).encode()
    req = urllib.request.Request("https://127.0.0.1:8088/services/collector/event", body,
                                 headers={"Authorization": f"Splunk {env['SPLUNK_HEC_TOKEN']}"})
    with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
        return json.load(r)


def main():
    env = load_env()

    batch, sent = [], 0
    with open(sys.argv[1]) as f:
        for line in f:
            batch.append(to_hec(ta_fields(json.loads(line))))
            if len(batch) == BATCH:
                send(env, batch); sent += len(batch); batch = []
    if batch:
        send(env, batch); sent += len(batch)
    print(f"sent {sent} events to index={INDEX}")


if __name__ == "__main__":
    main()
