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
