"""
  witnessory check example.org [--json]     one site's post-quantum readiness, signed
  witnessory verify result.json             check a saved result's signatures (needs `cryptography`)
  witnessory headline                       the observatory's headline figures by layer
  witnessory probes                         the probe map
  witnessory status                         the services' status, and the checker's own state
  witnessory pricing                        what is paid, and the prices
  witnessory mcp                            run as an MCP server on stdin/stdout, for agents
  witnessory pay address                    the paying wallet's address (WITNESSORY_PAY_KEY; pip install "witnessory[pay]")
  witnessory pay check example.org          $0.01: one fresh, signed check, paid from that wallet
  witnessory pay key api-developer          $19: a key for 2,000 fresh checks in 31 days
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
    pp = sub.add_parser("pay", help="pay per request from your own wallet (x402)")
    pp.add_argument("what", choices=["address", "check", "key"])
    pp.add_argument("target", nargs="?", help="the domain to check, or the plan (api-developer, api-pro)")
    pp.add_argument("--network", help="eip155:8453 (Base, default) or eip155:84532 (test network)")
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
        elif a.cmd == "pay":
            from . import pay
            if a.what == "address":
                print(pay.address())
            elif a.what == "check":
                if not a.target:
                    p.error("pay check needs a domain")
                body, settlement = pay.check(a.target, network=a.network)
                print(body.get("summary") or body["record"].get("level"))
                if settlement:
                    print(f"(paid {body.get('payment', {}).get('amount_usd')} USD on {settlement.get('network')}, transaction {settlement.get('transaction')})")
            else:
                body, settlement = pay.buy_key(a.target or "api-developer", network=a.network)
                out(body)
    except api.WitnessoryError as e:
        print(f"witnessory: {e}" + (f" (code {e.code})" if e.code else "") + (f"; try again in {e.retry_after} s" if e.retry_after else ""),
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
