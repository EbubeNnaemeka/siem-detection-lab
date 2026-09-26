#!/usr/bin/env python3
"""Convert a folder of .evtx files into JSON lines for load_sample_data.py.

Keeps System/EventID, Computer, TimeCreated and Channel, plus every named
EventData field. Records the originating file in sample_file so each alert
can be traced back to the attack it came from.

Requires: pip install python-evtx
Usage: python3 scripts/convert_evtx.py <evtx-folder> <out.json>
"""
import json
import pathlib
import sys
import xml.etree.ElementTree as ET

import Evtx.Evtx as evtx

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def records(path):
    with evtx.Evtx(str(path)) as log:
        for rec in log.records():
            try:
                yield ET.fromstring(rec.xml())
            except ET.ParseError:
                continue


def main():
    src, dest = pathlib.Path(sys.argv[1]), sys.argv[2]
    count = 0
    with open(dest, "w") as out:
        for path in sorted(src.rglob("*.evtx")):
            try:
                for root in records(path):
                    system = root.find(NS + "System")
                    ev = {
                        "EventCode": system.findtext(NS + "EventID"),
                        "host": system.findtext(NS + "Computer"),
                        "_time": system.find(NS + "TimeCreated").get("SystemTime"),
                        "Channel": system.findtext(NS + "Channel"),
                        "sample_file": str(path.relative_to(src)),
                    }
                    for d in root.iter(NS + "Data"):
                        if d.get("Name"):
                            ev[d.get("Name")] = d.text
                    out.write(json.dumps(ev) + "\n")
                    count += 1
            except Exception as exc:  # a few samples are truncated/corrupt
                print(f"skipped {path.name}: {exc}", file=sys.stderr)
    print(f"wrote {count} events to {dest}")


if __name__ == "__main__":
    main()
