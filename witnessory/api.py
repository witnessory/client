"""
The Witnessory services, as functions. Standard library only; `verify` uses `cryptography` if it is installed.

    import witnessory
    r = witnessory.check("example.org")          # a signed result; r["summary"] says it in a sentence
    witnessory.headline()                        # the observatory's headline figures, by layer
    witnessory.probes()                          # the probe map: where the network measures from

Every call sends `witnessory/<version>` as its user agent. A paid plan's key goes in `key=` or the environment
variable WITNESSORY_KEY. Errors from the services raise WitnessoryError with the service's own code and, for limits,
how long to wait.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from . import VERSION

CHECK = os.environ.get("WITNESSORY_CHECK_URL", "https://check.witnessory.org")
SITE = os.environ.get("WITNESSORY_SITE_URL", "https://witnessory.org")
COORDINATOR = os.environ.get("WITNESSORY_COORDINATOR_URL", "https://coordinator.witnessory.org")
UA = f"witnessory/{VERSION} (+https://witnessory.org/llms.txt)"
TIMEOUT = 60


class WitnessoryError(Exception):
    """A service said no: `status` (HTTP), `code` (the service's stable code), `retry_after` (seconds, or None)."""

    def __init__(self, message, status=None, code=None, retry_after=None, offers=None):
        super().__init__(message)
        self.status, self.code, self.retry_after, self.offers = status, code, retry_after, offers


def _get(url, key=None, timeout=TIMEOUT):
    headers = {"User-Agent": UA, "Accept": "application/json"}
    key = key or os.environ.get("WITNESSORY_KEY")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read(4 << 20))
    except urllib.error.HTTPError as e:
        with e:
            raw = e.read(1 << 16)
        try:
            body = json.loads(raw)
        except ValueError:
            body = {}
        retry = e.headers.get("Retry-After")
        raise WitnessoryError(body.get("error") or f"HTTP {e.code}", e.code, body.get("code"),
                              int(retry) if retry and retry.isdigit() else None, body.get("offers")) from None
    except urllib.error.URLError as e:
        raise WitnessoryError(f"could not reach {url}: {e.reason}") from None


def check(domain, key=None):
    """One site's post-quantum readiness, signed: `record` (what was measured), `signatures`, `summary`, `cached`,
    `offers`. Free: 20 new checks an hour from one address, results reused for 10 minutes. With a key: fresh."""
    return _get(f"{CHECK}/api/check?domain={urllib.parse.quote(str(domain).strip())}", key)


def badge_url(domain):
    """The SVG badge of a site's latest result, for a page."""
    return f"{CHECK}/badge/{urllib.parse.quote(str(domain).strip())}.svg"


def status():
    """The checker's own state and counts (no visitor data), and the offers."""
    return _get(f"{CHECK}/status")


def keys():
    """The checker's public keys (PEM), to verify results."""
    return _get(f"{CHECK}/keys")["public_keys"]


def view():
    """The observatory's current view: every layer's figures, refreshed hourly (large)."""
    return _get(f"{SITE}/view.json")


def headline(v=None):
    """The headline figures by layer, with when the view was computed and how many probes it rests on."""
    v = v or view()
    layers = v.get("layers") or {}
    out = {"as_of_utc": (v.get("params") or {}).get("as_of_utc"), "probes": (v.get("published") or {}).get("probes"),
           "networks": (v.get("published") or {}).get("networks"), "view_sha256": v.get("view_sha256"), "layers": {}}
    for name, layer in layers.items():
        if isinstance(layer, dict) and layer.get("headline"):
            out["layers"][name] = layer["headline"]
    return out


def probes():
    """The probe map: probes active in the last 7 days by country and network, and the probes with the most credits."""
    return _get(f"{COORDINATOR}/probes.json")


def probe(probe_id):
    """One probe's public page as data: since, last seen, results, credits, network, country."""
    return _get(f"{COORDINATOR}/p/{urllib.parse.quote(str(probe_id))}.json")


def service_status():
    """Whether each Witnessory service is up, from the hourly watch."""
    return _get(f"{COORDINATOR}/status.json")


def pricing():
    """What is paid, and the prices, as data."""
    return _get(f"{SITE}/pricing.json")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify(result, public_keys=None):
    """Check a result's signatures against the checker's public keys: {"ed25519": True/False, "mldsa65": True/False}.
    Needs `cryptography` (48 or later for ML-DSA); a signature it cannot check is reported as None."""
    try:
        import base64
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError:
        return {alg: None for alg in result.get("signatures", {})}
    public_keys = public_keys or keys()
    body = canonical(result["record"])
    out = {}
    for alg, sig in result.get("signatures", {}).items():
        pem = public_keys.get(alg)
        if not pem:
            out[alg] = None
            continue
        try:
            load_pem_public_key(pem.encode()).verify(base64.b64decode(sig), body)
            out[alg] = True
        except Exception:
            out[alg] = False
    return out
