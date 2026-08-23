"""Pluggable memory backend.

``InMemoryStorage`` is the default (process-local dict) so Guardian runs
with zero external dependencies out of the box. Implement the same
interface against Redis/Postgres/etc. for a real multi-instance
deployment — ``DecisionHistory`` only depends on this interface, nothing
else in the codebase needs to change.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Protocol


class MemoryBackend(Protocol):
    def append(self, key: str, value: dict) -> None: ...

    def get(self, key: str, limit: Optional[int] = None) -> List[dict]: ...

    def get_since(self, key: str, since_timestamp: float) -> List[dict]:
        """Records for `key` with a `"t"` field greater than
        `since_timestamp`. Used by CapabilityRegistry for its persistent
        daily-spend window (see policy/capabilities.py) - a genuine
        time-window query, not a "most recent N" one, so it must not
        silently undercount when an agent has made more than some fixed
        row-count of transactions within the window. Optional on this
        Protocol (checked with hasattr() by callers) so a custom backend
        only needs it if it actually wants persistent capability
        tracking; every built-in backend here implements it.
        """
        ...


class InMemoryStorage:
    def __init__(self) -> None:
        self._data: Dict[str, List[dict]] = {}

    def append(self, key: str, value: dict) -> None:
        self._data.setdefault(key, []).append(value)

    def get(self, key: str, limit: Optional[int] = None) -> List[dict]:
        records = self._data.get(key, [])
        if limit is not None:
            records = records[-limit:]
        return list(records)

    def get_since(self, key: str, since_timestamp: float) -> List[dict]:
        return [r for r in self._data.get(key, []) if r.get("t", 0) > since_timestamp]
