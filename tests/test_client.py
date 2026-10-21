#!/usr/bin/env python3
"""The client against local stand-ins for the services: the functions, the command line and the MCP server."""

import base64
import http.server
import json
import os
import subprocess
import sys
import threading
import unittest

RECORD = {"type": "nullius.site_check", "domain": "site.example", "name_checked": "site.example", "level": "ready",
          "checked_utc": "2026-10-20T08:00:00Z", "checker_version": "test", "notes": [], "certificate": None,
          "key_exchange": {"browser": {"group_name": "X25519MLKEM768", "tls_version": "1.3"}}}
OFFERS = {"note": "more", "services": "https://witnessory.org/services.html", "pricing": "https://witnessory.org/pricing.json"}
PEMS, SIGS = {}, {}
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    _k = ed25519.Ed25519PrivateKey.generate()
    PEMS["ed25519"] = _k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    SIGS["ed25519"] = base64.b64encode(_k.sign(json.dumps(RECORD, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())).decode()
except ImportError:
    pass


PAY_TO = "0x3984Dd1799AD2697A5F097c96Ed6372552A30Fc6"
ACCEPT = {"scheme": "exact", "network": "eip155:84532", "amount": "10000", "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
          "payTo": PAY_TO, "maxTimeoutSeconds": 300, "extra": {"name": "USDC", "version": "2"}}


class Stub(http.server.BaseHTTPRequestHandler):
    seen = []
    paid = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Stub.seen.append((self.path, self.headers.get("User-Agent"), self.headers.get("Authorization")))
        if self.path.startswith("/pay/check?domain="):
            return self.paid_route()
        if self.path.startswith("/api/check?domain=limited"):
            return self.send(429, {"error": "too many", "code": "rate_limited", "retry_after_s": 7, "offers": OFFERS}, {"Retry-After": "7"})
        if self.path.startswith("/api/check?domain="):
            return self.send(200, {"record": RECORD, "signatures": SIGS, "summary": "site.example: ready", "cached": False, "offers": OFFERS})
        table = {"/keys": {"public_keys": PEMS}, "/status": {"service": "witnessory-checker", "counts": {}, "offers": OFFERS},
                 "/view.json": {"params": {"as_of_utc": "2026-10-20T07:00:00Z"}, "published": {"probes": 4, "networks": 4},
                                "view_sha256": "ab" * 32, "layers": {"keys": {"headline": {"pq_negotiation_rate": {"median": 0.55}}}, "ssh": {"probes": []}}},
                 "/probes.json": {"probes": 1, "countries": 1, "networks": 1, "by_country": {"XA": 1}}, "/status.json": {"all_ok": True, "services": []},
                 "/pricing.json": {"products": [{"id": "api-developer", "price_month_usd": 19}]}, "/llms.txt": "# Witnessory\n"}
        if self.path in table:
            body = table[self.path]
            if isinstance(body, str):
                data = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                return self.wfile.write(data)
            return self.send(200, body)
        self.send(404, {"error": "not found", "code": "not_found"})

    def paid_route(self):
        """A stand-in for the paid route: 402 with requirements; with a signature, verify it recovers to `from`."""
        sig = self.headers.get("PAYMENT-SIGNATURE")
        req = {"x402Version": 2, "resource": {"url": "http://x/pay/check?domain=site.example"}, "accepts": [ACCEPT]}
        if not sig:
            return self.send(402, {"error": "payment required"}, {"PAYMENT-REQUIRED": base64.b64encode(json.dumps(req).encode()).decode()})
        payload = json.loads(base64.b64decode(sig))
        auth = payload["payload"]["authorization"]
        from eth_account import Account
        from eth_account.messages import encode_typed_data
        import witnessory.pay as wp
        domain = {"name": "USDC", "version": "2", "chainId": 84532, "verifyingContract": ACCEPT["asset"]}
        msg = {"from": auth["from"], "to": auth["to"], "value": int(auth["value"]), "validAfter": int(auth["validAfter"]),
               "validBefore": int(auth["validBefore"]), "nonce": bytes.fromhex(auth["nonce"][2:])}
        who = Account.recover_message(encode_typed_data(domain, wp.TYPES, msg), signature=bytes.fromhex(payload["payload"]["signature"][2:]))
        ok = who == auth["from"] and auth["to"] == PAY_TO and auth["value"] == "10000" and payload["accepted"]["network"] == "eip155:84532"
        Stub.paid.append((who, ok, payload))
        if not ok:
            return self.send(402, {"error": "payment not accepted: invalid_exact_evm_signature"})
        settlement = base64.b64encode(json.dumps({"success": True, "transaction": "0xtx", "network": "eip155:84532", "payer": who}).encode()).decode()
        return self.send(200, {"record": RECORD, "signatures": SIGS, "summary": "site.example: ready", "payment": {"amount_usd": "0.01", "transaction": "0xtx"}},
                         {"PAYMENT-RESPONSE": settlement})

    def send(self, code, obj, headers=None):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


class Client(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        for var in ("WITNESSORY_CHECK_URL", "WITNESSORY_SITE_URL", "WITNESSORY_COORDINATOR_URL", "WITNESSORY_PAY_URL"):
            os.environ[var] = cls.base
        os.environ.pop("WITNESSORY_KEY", None)
        import importlib
        import witnessory.api
        importlib.reload(witnessory.api)
        cls.api = witnessory.api
        import witnessory.pay
        importlib.reload(witnessory.pay)
        cls.pay = witnessory.pay

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_functions(self):
        api = self.api
        r = api.check("site.example")
        self.assertEqual((r["summary"], r["offers"]["pricing"]), ("site.example: ready", OFFERS["pricing"]))
        self.assertTrue(Stub.seen[-1][1].startswith("witnessory/"))     # announces itself as the client
        api.check("site.example", key="wk_test")
        self.assertEqual(Stub.seen[-1][2], "Bearer wk_test")
        with self.assertRaises(api.WitnessoryError) as c:
            api.check("limited.example")
        self.assertEqual((c.exception.status, c.exception.code, c.exception.retry_after), (429, "rate_limited", 7))
        self.assertEqual(c.exception.offers["pricing"], OFFERS["pricing"])
        h = api.headline()
        self.assertEqual((h["probes"], h["layers"]["keys"]["pq_negotiation_rate"]["median"], list(h["layers"])), (4, 0.55, ["keys"]))
        self.assertEqual(api.probes()["probes"], 1)
        self.assertEqual(api.pricing()["products"][0]["id"], "api-developer")
        self.assertTrue(api.service_status()["all_ok"])
        self.assertTrue(api.badge_url("a.example").endswith("/badge/a.example.svg"))

    @unittest.skipUnless(PEMS, "cryptography not installed")
    def test_verify(self):
        r = self.api.check("site.example")
        self.assertEqual(self.api.verify(r), {"ed25519": True})
        r["record"]["level"] = "not_yet"
        self.assertEqual(self.api.verify(r), {"ed25519": False})

    def test_paying_signs_what_the_402_asks_and_verifies(self):
        try:
            from eth_account import Account
        except ImportError:
            self.skipTest("eth-account not installed")
        key = "0x" + "11" * 32
        self.assertEqual(self.pay.address(key), Account.from_key(key).address)
        body, settlement = self.pay.check("site.example", private_key=key)
        self.assertEqual((body["summary"], settlement["success"], settlement["transaction"]), ("site.example: ready", True, "0xtx"))
        who, ok, payload = Stub.paid[-1]
        self.assertTrue(ok)
        self.assertEqual((payload["x402Version"], payload["accepted"]["amount"], who), (2, "10000", Account.from_key(key).address))
        self.assertEqual(len(bytes.fromhex(payload["payload"]["authorization"]["nonce"][2:])), 32)
        with self.assertRaises(self.api.WitnessoryError):
            self.pay.check("site.example", private_key=key, network="eip155:1")        # not offered
        os.environ.pop("WITNESSORY_PAY_KEY", None)
        with self.assertRaises(self.api.WitnessoryError):
            self.pay.check("site.example")                                             # no wallet configured

    def run_cli(self, *args, env=None):
        return subprocess.run([sys.executable, "-m", "witnessory.cli", *args], capture_output=True, text=True, timeout=60,
                              env={**os.environ, **(env or {})})

    def test_command_line(self):
        r = self.run_cli("check", "site.example")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "site.example: ready"))
        r = self.run_cli("check", "limited.example")
        self.assertEqual(r.returncode, 2)
        self.assertIn("try again in 7 s", r.stderr)
        self.assertEqual(json.loads(self.run_cli("pricing").stdout)["products"][0]["price_month_usd"], 19)

    def test_mcp_server(self):
        lines = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}},
                 {"jsonrpc": "2.0", "method": "notifications/initialized"},
                 {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                 {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "check_site", "arguments": {"domain": "site.example"}}},
                 {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "check_site", "arguments": {"domain": "limited.example"}}},
                 {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "pricing", "arguments": {}}},
                 {"jsonrpc": "2.0", "id": 6, "method": "resources/read", "params": {"uri": "https://witnessory.org/pricing.json"}},
                 {"jsonrpc": "2.0", "id": 7, "method": "nope"},
                 "not json"]
        proc = subprocess.run([sys.executable, "-m", "witnessory.mcp"], input="\n".join(json.dumps(x) if not isinstance(x, str) else x for x in lines) + "\n",
                              capture_output=True, text=True, timeout=60, env=dict(os.environ))
        replies = [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]
        by_id = {r.get("id"): r for r in replies}
        self.assertEqual(by_id[1]["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(by_id[1]["result"]["serverInfo"]["name"], "witnessory")
        self.assertEqual([t["name"] for t in by_id[2]["result"]["tools"]][:2], ["check_site", "pq_headline"])
        self.assertIn("pay_check", [t["name"] for t in by_id[2]["result"]["tools"]])
        called = json.loads(by_id[3]["result"]["content"][0]["text"])
        self.assertEqual((called["level"], called["summary"], by_id[3]["result"]["isError"]), ("ready", "site.example: ready", False))
        limited = json.loads(by_id[4]["result"]["content"][0]["text"])
        self.assertEqual((by_id[4]["result"]["isError"], limited["code"], limited["retry_after_s"]), (True, "rate_limited", 7))
        self.assertEqual(json.loads(by_id[5]["result"]["content"][0]["text"])["products"][0]["id"], "api-developer")
        self.assertEqual(by_id[7]["error"]["code"], -32601)
        self.assertEqual(by_id[None]["error"]["code"], -32700)
        self.assertEqual(len(replies), 8)                                 # the notification got no reply
        self.assertEqual(proc.stderr, "")


if __name__ == "__main__":
    unittest.main()
