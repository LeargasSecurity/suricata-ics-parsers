#!/usr/bin/env python3
"""Merge the plugin's EVE schema into Suricata's core EVE schema.

Suricata's etc/schema.json rejects unknown top-level keys, so EVE output that
contains s7comm, iec104 or mms records never validates against it. This writes
a combined schema that suricata-verify's check-eve.py can use:

    scripts/eve-schema.py $SURICATA_SRC/etc/schema.json > /tmp/eve-merged.json
    suricata-verify/check-eve.py OUTDIR -s /tmp/eve-merged.json
"""

import argparse
import json
import os
import sys

PLUGIN_SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "schema", "eve-ics.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("core", help="Suricata's etc/schema.json")
    parser.add_argument("--plugin", default=PLUGIN_SCHEMA, help="plugin schema (default: schema/eve-ics.json)")
    args = parser.parse_args()

    with open(args.core) as f:
        core = json.load(f)
    with open(args.plugin) as f:
        plugin = json.load(f)

    for section in ("properties", "$defs"):
        target = core.setdefault(section, {})
        for key, value in plugin.get(section, {}).items():
            if key in target:
                sys.exit("error: {} '{}' is already defined by the core schema".format(section, key))
            target[key] = value

    json.dump(core, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
