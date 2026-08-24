"""Central configuration, read once from the environment.

Guardian is designed to run with **zero configuration** in demo/dev mode
(everything defaults to the mock providers, in-memory storage, no auth) and
to become a real self-hosted deployment purely by setting environment
variables - no code changes required anywhere else in the codebase.

This is the one file that should know about ``os.environ``. Every other
module receives a ``GuardianConfig`` instance (or one of its sub-configs)
instead of reading the environment itself, so the rest of the codebase
stays trivially testable.

Set these in a ``.env`` file (see ``.env.example``) or your process
manager / container orchestrator - never commit real secrets.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Optional

from dotenv import load_dotenv

# Loads a .env file from the current working directory (or the nearest
# parent that has one) into the real process environment, if present.
# Silently does nothing if there is no .env file - so this is safe to run
# unconditionally, including in production where config comes from the
# process manager / container orchestrator instead. Must run before any
# GuardianConfig field is read, which is why this sits at module import
# time rather than inside a function.
load_dotenv()

TRUE_VALUES = {"1", "true", "yes", "on"}


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in TRUE_VALUES


def _agent_api_keys_from_env() -> Dict[str, str]:
    """Parses ``GUARDIAN_AGENT_API_KEYS="agent_id:key,agent_id2:key2"``.

    Empty/unset (the default) means "no per-agent binding configured" -
    Guardian falls back to the single global ``GUARDIAN_API_KEY``, exactly
    as before this existed. That default is a real, known gap: with only
    a shared key, any caller holding it can put *any* ``agent_id`` in the
    request body and inherit that agent_id's accumulated reputation and
    capability grants - there is no way to prove a request claiming to be
    e.g. "trading-agent-001" actually came from that agent, since nothing
    cryptographically ties the identity in the payload to the credential
    that authenticated the request. Setting this makes each agent_id's
    Authorization key its own - a caller can no longer act as an agent it
    doesn't hold the key for. See ``api/security.check_agent_bound_key``
    for how this is enforced; ``GUARDIAN_API_KEY`` keeps working as a
    master key that can still act as any agent, for admin/tooling use.
    """
    raw = os.environ.get("GUARDIAN_AGENT_API_KEYS", "")
    if not raw.strip():
        return {}
    pairs: Dict[str, str] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            raise ValueError(
                f"GUARDIAN_AGENT_API_KEYS entry {entry!r} is not in 'agent_id:key' format"
            )
        agent_id, key = entry.split(":", 1)
        agent_id, key = agent_id.strip(), key.strip()
        if not agent_id or not key:
            raise ValueError(f"GUARDIAN_AGENT_API_KEYS entry {entry!r} has an empty agent_id or key")
        pairs[agent_id] = key
    return pairs


def _rpc_urls_from_env() -> Dict[str, str]:
    """Reads ``GUARDIAN_RPC_<CHAIN>`` for every supported chain.

    No defaults are baked in on purpose: public RPC endpoints change, get
    rate-limited, or get deprecated, and shipping a hardcoded list would
    silently rot. Point these at your own node or a provider you trust
    (Alchemy, Infura, QuickNode, a public endpoint from chainlist.org...).
    """
    from guardian.decision.rules import SUPPORTED_CHAINS

    urls: Dict[str, str] = {}
    for chain in SUPPORTED_CHAINS:
        env_name = f"GUARDIAN_RPC_{chain.upper()}"
        url = os.environ.get(env_name)
        if url:
            urls[chain] = url
    return urls


@dataclass
class GuardianConfig:
    # --- Data providers: "mock" keeps the zero-config demo behavior; ---
    # --- switch to a real provider for a genuine self-hosted deployment. ---
    wallet_provider: str = field(default_factory=lambda: os.environ.get("GUARDIAN_WALLET_PROVIDER", "mock"))
    contract_provider: str = field(default_factory=lambda: os.environ.get("GUARDIAN_CONTRACT_PROVIDER", "mock"))
    token_provider: str = field(default_factory=lambda: os.environ.get("GUARDIAN_TOKEN_PROVIDER", "mock"))
    simulation_provider: str = field(default_factory=lambda: os.environ.get("GUARDIAN_SIMULATION_PROVIDER", "null"))
    tx_builder_provider: str = field(default_factory=lambda: os.environ.get("GUARDIAN_TX_BUILDER", "null"))
    decimals_provider: str = field(default_factory=lambda: os.environ.get("GUARDIAN_DECIMALS_PROVIDER", "null"))

    rpc_urls: Dict[str, str] = field(default_factory=_rpc_urls_from_env)
    estimate_wallet_age: bool = field(default_factory=lambda: _bool("GUARDIAN_RPC_ESTIMATE_AGE", False))

    blockscout_base_url: str = field(
        default_factory=lambda: os.environ.get("GUARDIAN_BLOCKSCOUT_BASE_URL", "https://eth.blockscout.com")
    )
    dexscreener_base_url: str = field(
        default_factory=lambda: os.environ.get("GUARDIAN_DEXSCREENER_BASE_URL", "https://api.dexscreener.com")
    )
    provider_timeout_seconds: float = field(
        default_factory=lambda: float(os.environ.get("GUARDIAN_PROVIDER_TIMEOUT_SECONDS", "5"))
    )
    goplus_api_key: Optional[str] = field(default_factory=lambda: os.environ.get("GOPLUS_API_KEY") or None)

    # --- Storage ---
    storage_backend: str = field(default_factory=lambda: os.environ.get("GUARDIAN_STORAGE_BACKEND", "memory"))
    sqlite_path: str = field(default_factory=lambda: os.environ.get("GUARDIAN_SQLITE_PATH", "data/guardian.db"))
    postgres_dsn: str = field(default_factory=lambda: os.environ.get("GUARDIAN_POSTGRES_DSN", ""))

    # --- Threat / contract lists (local, operator-maintained files) ---
    sanctioned_addresses_path: str = field(
        default_factory=lambda: os.environ.get(
            "GUARDIAN_SANCTIONED_LIST_PATH", "data/threat_lists/sanctioned_addresses.json"
        )
    )
    malicious_contracts_path: str = field(
        default_factory=lambda: os.environ.get(
            "GUARDIAN_MALICIOUS_CONTRACTS_PATH", "data/threat_lists/malicious_contracts.json"
        )
    )
    verified_contracts_path: str = field(
        default_factory=lambda: os.environ.get(
            "GUARDIAN_VERIFIED_CONTRACTS_PATH", "data/threat_lists/verified_contracts.json"
        )
    )

    # --- API security ---
    api_key: Optional[str] = field(default_factory=lambda: os.environ.get("GUARDIAN_API_KEY") or None)
    agent_api_keys: Dict[str, str] = field(default_factory=_agent_api_keys_from_env)
    rate_limit_per_minute: int = field(
        default_factory=lambda: int(os.environ.get("GUARDIAN_RATE_LIMIT_PER_MINUTE", "60"))
    )

    @property
    def auth_enabled(self) -> bool:
        return bool(self.api_key) or bool(self.agent_api_keys)


_config: Optional[GuardianConfig] = None


def get_config() -> GuardianConfig:
    """Process-wide config singleton, read from the environment once.

    Call ``reload_config()`` (tests do this) if environment variables
    change after import time.
    """
    global _config
    if _config is None:
        _config = GuardianConfig()
    return _config


def reload_config() -> GuardianConfig:
    global _config
    _config = GuardianConfig()
    return _config
