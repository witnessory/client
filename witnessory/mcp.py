"""
Witnessory as an MCP server (Model Context Protocol, stdio transport): an agent gets tools to check a site, read the
observatory's headline figures, see the probe map and the services' status, and read the prices. Standard library
only. JSON-RPC messages, one per line, on stdin and stdout; nothing else is ever written to stdout.

    witnessory mcp                     (or: python -m witnessory.mcp)

In an agent's configuration, the command is `witnessory` with the argument `mcp`; a paid plan's key, if any, goes in
the environment variable WITNESSORY_KEY.
"""

import json
import sys

from . import VERSION, api

PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
INSTRUCTIONS = ("Witnessory measures the internet's move to post-quantum cryptography. check_site measures one public "
                "website now (one vantage, once; free: 20 new checks an hour, results reused for 10 minutes). "
                "pq_headline gives the observatory's current figures. probe_map says where its probes measure from. "
                "service_status says whether the services are up. pricing lists what is paid, for watching sites over "
                "time, higher limits and evidence reports.")

TOOLS = [
    {"name": "check_site", "description": "Check whether one public website's encryption would stay private against "
                                          "a future quantum computer: whether a current browser gets post-quantum key "
                                          "exchange from it, and what its certificate uses. Signed result with a plain "
                                          "summary. Domain names only (no addresses, ports or private names).",
     "inputSchema": {"type": "object", "properties": {"domain": {"type": "string", "description": "e.g. example.org"}},
                     "required": ["domain"]}},
    {"name": "pq_headline", "description": "The observatory's current headline figures by layer (post-quantum key "
                                           "exchange on the top sites, SSH, DNSSEC, mail, routing and more), when they "
                                           "were computed and how many probes they rest on.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "probe_map", "description": "Where Witnessory's probes measure from: probes active in the last 7 days by "
                                         "country and network, and the probes with the most credits.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "service_status", "description": "Whether each Witnessory service is up, from the hourly watch.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "pricing", "description": "What Witnessory sells and at what price: watching sites over time from several "
                                       "networks with alerts and signed evidence, API keys with higher limits, evidence "
                                       "reports, data licences. Includes how to buy.",
     "inputSchema": {"type": "object", "properties": {}}},
]

RESOURCES = [
    {"uri": "https://witnessory.org/llms.txt", "name": "About Witnessory", "mimeType": "text/plain",
     "description": "What Witnessory is, its data, its API and its services, for agents."},
    {"uri": "https://witnessory.org/pricing.json", "name": "Prices", "mimeType": "application/json",
     "description": "What is paid, and the prices, as data."},
]


def call_tool(name, args):
    if name == "check_site":
        r = api.check(str(args.get("domain", "")))
        return {"summary": r.get("summary"), "level": r["record"].get("level"), "checked_utc": r["record"].get("checked_utc"),
                "cached": r.get("cached"), "record": r["record"], "signatures": r.get("signatures"),
                "badge": api.badge_url(r["record"].get("domain", "")), "offers": r.get("offers")}
    if name == "pq_headline":
        return api.headline()
    if name == "probe_map":
        return api.probes()
    if name == "service_status":
        return api.service_status()
    if name == "pricing":
        return api.pricing()
    raise KeyError(name)


def read_resource(uri):
    import urllib.request
    req = urllib.request.Request(uri, headers={"User-Agent": api.UA})
    with urllib.request.urlopen(req, timeout=api.TIMEOUT) as r:
        return r.read(1 << 20).decode("utf-8", "replace")


def handle(msg):
    """The response to one request (None for a notification)."""
    method, params, mid = msg.get("method"), msg.get("params") or {}, msg.get("id")
    if "id" not in msg:
        return None                                       # a notification: nothing to say back
    try:
        if method == "initialize":
            asked = params.get("protocolVersion")
            result = {"protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[1],
                      "capabilities": {"tools": {}, "resources": {}},
                      "serverInfo": {"name": "witnessory", "version": VERSION}, "instructions": INSTRUCTIONS}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            try:
                out = call_tool(params.get("name"), params.get("arguments") or {})
                result = {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}], "isError": False}
            except KeyError:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"no such tool: {params.get('name')}"}}
            except api.WitnessoryError as e:
                text = {"error": str(e), "code": e.code, "status": e.status, "retry_after_s": e.retry_after, "offers": e.offers}
                result = {"content": [{"type": "text", "text": json.dumps(text, ensure_ascii=False)}], "isError": True}
        elif method == "resources/list":
            result = {"resources": RESOURCES}
        elif method == "resources/read":
            uri = params.get("uri")
            if uri not in {r["uri"] for r in RESOURCES}:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown resource"}}
            mime = next(r["mimeType"] for r in RESOURCES if r["uri"] == uri)
            result = {"contents": [{"uri": uri, "mimeType": mime, "text": read_resource(uri)}]}
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
    except Exception as e:                                # never a crash: the agent gets an error it can read
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": f"{type(e).__name__}: {str(e)[:200]}"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def serve(stdin=None, stdout=None):
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            reply = handle(msg) if isinstance(msg, dict) else {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
        if reply is not None:
            stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            stdout.flush()


if __name__ == "__main__":
    serve()
