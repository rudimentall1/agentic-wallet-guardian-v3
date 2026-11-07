# Verigate-gated Arc USDC execution

This integration makes Verigate a mandatory authorization and one-time execution-consume gate for the Guardian Arc browser demo.

## Request path

1. Guardian evaluates the transfer with its existing risk engine. A non-ALLOW result releases no transaction.
2. Guardian constructs the exact Arc USDC ERC-20 transfer and signs a Verigate ActionIntent with the configured Ed25519 agent key.
3. Guardian calls `POST /v1/integrations/arc/authorize`. Verigate validates the registered identity, capability, signed intent, Arc chain/token metadata, and exact sender/recipient/amount calldata.
4. Guardian releases only Verigate's returned wallet transaction, while retaining Guardian's RPC gas estimate.
5. On the user's explicit **Sign & send** click, the browser calls Guardian `POST /arc/consume`.
6. Guardian forwards the exact execution authorization to Verigate `POST /v1/execution/consume`. Only `execute=true` allows the browser to request wallet signing/broadcast.

Any Verigate/network/configuration error fails closed. There is no Guardian-only fallback.

## Required environment

Configure these on the Guardian service; never commit the private key or API key:

- `VERIGATE_URL`: base URL of the Verigate API.
- `VERIGATE_API_KEY`: optional only if the Verigate API is intentionally open; use a dedicated API key in production.
- `VERIGATE_AGENT_ID`: agent identifier registered in Verigate.
- `VERIGATE_IDENTITY_ID`: fingerprint/key ID of the registered Ed25519 public key.
- `VERIGATE_CAPABILITY_ID`: active capability allowing the Arc USDC payment action, network, asset, recipient scope and amount.
- `VERIGATE_AGENT_PRIVATE_KEY_PATH`: path to the matching Ed25519 PEM private key.

The Verigate identity and capability must already exist in the Verigate authority store. The capability should be narrowly scoped to the demo wallet, Arc, USDC and a small amount limit.

## Evidence and security boundary

The Verigate execution authorization is one-time and bound to the exact action. A replayed consume must be rejected by Verigate. The transaction broadcast remains non-custodial: the connected wallet signs it.

Important limitation: this is an application/client execution gate, not an on-chain account guard. A wallet owner can always bypass a browser application and submit a separate transaction directly from the wallet or another RPC client. Do not claim that Verigate currently prevents such out-of-band wallet activity. A stronger enforcement claim requires a smart-account/guard contract that verifies Verigate authorization on-chain.

## Deployment checklist

- Register the agent Ed25519 public key in Verigate and verify its identity ID.
- Register and activate a narrow Arc USDC payment capability.
- Set the six environment values above on Guardian.
- Restart only the Guardian service during a planned deployment window.
- Verify a policy-denied transfer releases no wallet transaction.
- Verify a permitted transfer receives a Verigate execution authorization.
- Verify first consume returns `execute=true` and replay returns `execute=false`.
- Only then perform a low-value real Arc payment after the operator confirms sender, recipient and amount.
- Save the Verigate authorization/decision receipt and Arc transaction receipt together as judge evidence.

No live transaction is executed by this code change.
