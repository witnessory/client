# Witnessory client

[Witnessory](https://witnessory.org/) measures how far the internet has moved to post-quantum cryptography. This is
the client: the services as Python functions, a command line, and an MCP server so an agent can use them as tools.
Standard library only; Apache 2.0.

```
pip install https://github.com/witnessory/client/releases/download/v0.2.0/witnessory-0.2.0-py3-none-any.whl
```

## From the command line

```
witnessory check example.org          # one site's post-quantum readiness, in a sentence
witnessory check example.org --json   # the whole signed result
witnessory headline                   # the observatory's headline figures, by layer
witnessory probes                     # where the probes measure from
witnessory status                     # whether every service is up
witnessory pricing                    # what is paid, and the prices
```

## From Python

```python
import witnessory
r = witnessory.check("example.org")
print(r["summary"])                   # "example.org: a current browser gets post-quantum key exchange ..."
witnessory.verify(r)                  # {"ed25519": True, "mldsa65": True}  (needs: pip install "witnessory[verify]")
witnessory.headline()["layers"]["keys"]
```

## As an MCP server, for agents

Command `witnessory`, argument `mcp`. For example, in a client's configuration:

```json
{"mcpServers": {"witnessory": {"command": "witnessory", "args": ["mcp"]}}}
```

Tools: `check_site`, `pq_headline`, `probe_map`, `service_status`, `pricing`. Resources: Witnessory's `llms.txt` and
`pricing.json`. Messages are JSON-RPC, one per line, on stdin and stdout.

## Limits and keys

A free check is one vantage, once: 20 new checks an hour from one address, results reused for 10 minutes. A paid
plan's key (`WITNESSORY_KEY`, or `--key`) makes checks fresh and counted per month instead of per address. Every
answer carries `offers`: what more there is and where the prices are (https://witnessory.org/pricing.json). Watching
your own sites over time from several networks, with alerts and signed evidence, is a separate product on the same
page.

## Paying per request, as an agent

No account is needed: `GET https://api.witnessory.org/pay/check?domain=example.org` answers 402 with what to pay
(x402 v2; USDC on Base), and any x402-capable client pays and resends. This client can pay too:

```
pip install "witnessory[pay]"
export WITNESSORY_PAY_KEY=0x...          # a wallet holding a little USDC on Base
witnessory pay address                   # where to send the USDC
witnessory pay check example.org         # $0.01, one fresh signed check
witnessory pay key api-developer         # $19, a key for 2,000 fresh checks in 31 days -> WITNESSORY_KEY
```

From code: `witnessory.pay.check("example.org")` and `witnessory.pay.buy_key("api-developer")`. As an MCP tool:
`pay_check`. Index of what is sold: https://api.witnessory.org/pay.

Terms: https://witnessory.org/terms.html. Privacy: https://witnessory.org/privacy.html. Contact:
security@witnessory.org.
