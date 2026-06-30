"""
agent.py -- Simulated agent that emits action intents through the adapter.

The agent has NO direct reference to the store.  Every action MUST go
through the adapter, which is the sole enforcement seam.  This models the
real constraint: a governed agent is physically unable to bypass the adapter.

Exports a sequence of intents used by demo.py for the 5 scenarios.
"""

from __future__ import annotations

from typing import List


class MockAgent:
    """
    A simulated content-management agent.

    It knows only about the adapter -- never the store directly.
    """

    def __init__(self, adapter) -> None:
        self._adapter = adapter

    # ------------------------------------------------------------------
    # Agent actions -- each calls adapter.apply(intent) and returns result
    # ------------------------------------------------------------------

    def read_post(self, post_id: int, environment: str = "production") -> dict:
        """Read a single post (benign read, should allow)."""
        return self._adapter.apply({
            "op": "get",
            "id": post_id,
            "environment": environment,
        })

    def delete_post(
        self,
        post_id: int,
        environment: str = "production",
        force: bool = False,
        approved: bool = False,
    ) -> dict:
        """Delete a single post (soft by default, irreversible if force=True)."""
        return self._adapter.apply({
            "op": "delete",
            "id": post_id,
            "environment": environment,
            "force_delete": force,
            "approved": approved,
        })

    def bulk_delete_posts(
        self,
        ids: List[int],
        environment: str = "production",
        force: bool = False,
        approved: bool = False,
    ) -> dict:
        """Bulk delete a list of posts."""
        return self._adapter.apply({
            "op": "bulk_delete",
            "ids": ids,
            "environment": environment,
            "force_delete": force,
            "approved": approved,
        })

    def update_post(
        self,
        post_id: int,
        fields: dict,
        environment: str = "production",
    ) -> dict:
        """Update fields on a single post."""
        return self._adapter.apply({
            "op": "update",
            "id": post_id,
            "fields": fields,
            "environment": environment,
        })
