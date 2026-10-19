"""
  witnessory check example.org [--json]     one site's post-quantum readiness, signed
  witnessory verify result.json             check a saved result's signatures (needs `cryptography`)
  witnessory headline                       the observatory's headline figures by layer
  witnessory probes                         the probe map
  witnessory status                         the services' status, and the checker's own state
  witnessory pricing                        what is paid, and the prices
  witnessory mcp                            run as an MCP server on stdin/stdout, for agents
"""

import argparse
import json
import sys

from . import VERSION, api


def out(obj):
    print(json.dumps(obj, indent=1, ensure_ascii=False))


def main(argv=None):
    p = argparse.ArgumentParser(prog="witnessory", description="Witnessory from the command line")
    p.add_argument("--version", action="version", version=f"witnessory {VERSION}")
    p.add_argument("--key", help="a paid plan's key (or the environment variable WITNESSORY_KEY)")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="one site's post-quantum readiness")
    c.add_argument("domain")
    c.add_argument("--json", action="store_true", help="the whole signed result, not the summary")
    v = sub.add_parser("verify", help="check a saved result's signatures")
    v.add_argument("file")
    for name in ("headline", "probes", "status", "pricing", "mcp"):
        sub.add_parser(name)
    a = p.parse_args(argv)
    try:
        if a.cmd == "check":
            r = api.check(a.domain, a.key)
            if a.json:
                out(r)
            else:
                print(r.get("summary") or r["record"].get("level"))
                if r.get("cached"):
                    print(f"(a result from the last 10 minutes; fresh checks with a key: {r['offers']['pricing']})")
        elif a.cmd == "verify":
            with open(a.file, encoding="utf-8") as f:
                result = json.load(f)
            checks = api.verify(result)
            out(checks)
            return 0 if all(checks.values()) else 1
        elif a.cmd == "headline":
            out(api.headline())
        elif a.cmd == "probes":
            out(api.probes())
        elif a.cmd == "status":
            out({"services": api.service_status(), "checker": api.status()})
        elif a.cmd == "pricing":
            out(api.pricing())
        elif a.cmd == "mcp":
            from . import mcp
            mcp.serve()
    except api.WitnessoryError as e:
        print(f"witnessory: {e}" + (f" (code {e.code})" if e.code else "") + (f"; try again in {e.retry_after} s" if e.retry_after else ""),
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
