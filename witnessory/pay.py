"""
Paying per request from your own wallet (HTTP 402, the x402 protocol, version 2, "exact" scheme: a signed USDC transfer
authorisation that a facilitator settles on chain). Needs the signing library: pip install "witnessory[pay]".

    export WITNESSORY_PAY_KEY=0x...          # the paying wallet's private key (USDC on Base, plus nothing else needed)
    witnessory pay address                   # where to send USDC so this wallet can pay
    witnessory pay check example.org         # $0.01: one fresh, signed check
    witnessory pay key api-developer         # $19: a key for 2,000 fresh checks in 31 days

    import witnessory.pay as pay
    pay.check("example.org")                 # the same, from code

The 402 carries everything the signature needs (the token contract, its signing domain, the amount, the address to pay);
nothing is hard-coded here. By default the first offered network is used (Base); WITNESSORY_PAY_NETWORK picks another
(for example eip155:84532, the test network).
"""

import base64
import json
import os
import secrets
import time
import urllib.error
import urllib.request

from . import api

TYPES = {"TransferWithAuthorization": [
    {"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "value", "type": "uint256"},
    {"name": "validAfter", "type": "uint256"}, {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"}]}
PAY = os.environ.get("WITNESSORY_PAY_URL", "https://api.witnessory.org")


def _account(private_key=None):
    try:
        from eth_account import Account
    except ImportError:
        raise api.WitnessoryError('paying needs the signing library: pip install "witnessory[pay]"') from None
    key = private_key or os.environ.get("WITNESSORY_PAY_KEY")
    if not key:
        raise api.WitnessoryError("no paying wallet: set WITNESSORY_PAY_KEY to the wallet's private key")
    return Account, Account.from_key(key)


def address(private_key=None):
    """The paying wallet's address (send USDC on Base here so it can pay)."""
    return _account(private_key)[1].address


def _request(url, method, headers, data=None):
    req = urllib.request.Request(url, method=method, data=data, headers={"User-Agent": api.UA, "Accept": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(4 << 20)
    except urllib.error.HTTPError as e:
        with e:
            return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(1 << 20)
    except urllib.error.URLError as e:
        raise api.WitnessoryError(f"could not reach {url}: {e.reason}") from None


def _decode(header):
    return json.loads(base64.b64decode(header))


def sign(accept, resource, private_key=None, now=None, extensions=None):
    """The PaymentPayload for one `accepts` entry of a 402: a signed EIP-3009 transfer authorisation."""
    Account, acct = _account(private_key)
    now = int(now or time.time())
    chain_id = int(str(accept["network"]).split(":")[1])
    domain = {"name": accept["extra"]["name"], "version": accept["extra"]["version"], "chainId": chain_id, "verifyingContract": accept["asset"]}
    nonce = secrets.token_bytes(32)
    message = {"from": acct.address, "to": accept["payTo"], "value": int(accept["amount"]), "validAfter": now - 600,
               "validBefore": now + int(accept.get("maxTimeoutSeconds") or 300), "nonce": nonce}
    signed = Account.sign_typed_data(acct.key, domain, TYPES, message)
    authorization = {k: (str(v) if isinstance(v, int) else v) for k, v in message.items() if k != "nonce"}
    authorization["nonce"] = "0x" + nonce.hex()
    sig = signed.signature.hex()
    return {"x402Version": 2, "resource": resource, "accepted": accept,
            "payload": {"signature": sig if sig.startswith("0x") else "0x" + sig, "authorization": authorization},
            "extensions": extensions or {}}                         # echoed, so facilitators can catalogue the resource


def pay(url, method="GET", private_key=None, network=None):
    """Ask for `url`; if it costs something, pay once and ask again. Returns (body, settlement); settlement is None
    when nothing was charged. Raises WitnessoryError when the payment is refused."""
    status, headers, raw = _request(url, method, {})
    if status != 402:
        if status >= 400:
            raise api.WitnessoryError(json.loads(raw or b"{}").get("error") or f"HTTP {status}", status)
        return json.loads(raw), None
    if "payment-required" not in headers:
        raise api.WitnessoryError("402 without payment requirements", 402)
    req = _decode(headers["payment-required"])
    want = network or os.environ.get("WITNESSORY_PAY_NETWORK")
    accepts = [a for a in req.get("accepts", []) if a.get("scheme") == "exact" and (not want or a.get("network") == want)]
    if not accepts:
        raise api.WitnessoryError(f"no acceptable way to pay (offered: {[a.get('network') for a in req.get('accepts', [])]})", 402)
    payload = sign(accepts[0], req.get("resource"), private_key, extensions=req.get("extensions"))
    token = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    status, headers, raw = _request(url, method, {"PAYMENT-SIGNATURE": token})
    settlement = _decode(headers["payment-response"]) if headers.get("payment-response") else None
    body = json.loads(raw or b"{}")
    if status != 200:
        raise api.WitnessoryError(body.get("error") or f"HTTP {status}", status, body.get("code"), offers=body.get("offers"))
    return body, settlement


def check(domain, private_key=None, network=None):
    """One fresh, signed check, paid per request ($0.01)."""
    return pay(f"{PAY}/pay/check?domain={urllib.parse.quote(str(domain).strip())}", "GET", private_key, network)


def buy_key(plan="api-developer", private_key=None, network=None):
    """A plan's key, paid for now (api-developer: 2,000 checks in 31 days; api-pro: 25,000)."""
    return pay(f"{PAY}/pay/key?plan={urllib.parse.quote(plan)}", "POST", private_key, network)


import urllib.parse  # noqa: E402  (used above; kept after the functions for readability of the module's story)
