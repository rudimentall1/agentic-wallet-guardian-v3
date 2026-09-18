"""Read-only Arc mainnet sanity check. No key, signing, or transaction."""
import json
import urllib.request

RPC = "https://rpc.mainnet.arc.io"
USDC = "0x3600000000000000000000000000000000000000"

def rpc(method, params):
    data = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(RPC, data=data, headers={"Content-Type":"application/json","User-Agent":"agentic-wallet-guardian/3.2"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read())
    if "error" in payload:
        raise RuntimeError(payload["error"])
    return payload["result"]

chain_id = int(rpc("eth_chainId", []), 16)
block = int(rpc("eth_blockNumber", []), 16)
gas_price = int(rpc("eth_gasPrice", []), 16)
decimals = int(rpc("eth_call", [{"to":USDC,"data":"0x313ce567"}, "latest"]), 16)

assert chain_id == 5042, chain_id
assert decimals == 6, decimals
print(json.dumps({
    "chain_id": chain_id,
    "block_number": block,
    "gas_price_gwei": gas_price / 1_000_000_000,
    "usdc_address": USDC,
    "usdc_decimals": decimals,
    "rpc": RPC,
}, indent=2))
