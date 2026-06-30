"""
store.py -- Simulated in-memory backend store for the mock adapter demo.

Represents a simple "posts" content backend with real operations that
actually mutate state. The agent NEVER touches this directly -- all
access goes through adapter.py, which is the enforcement point.

Zero PII: all post data is fully synthetic.
"""

from __future__ import annotations

import threading
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Synthetic seed data (zero PII, fully fictional)
# ---------------------------------------------------------------------------

_SEED_POSTS: List[dict] = [
    {"id": i, "title": f"Synthetic Post {i}", "status": "published",
     "author": "agent:demo-writer", "body": f"Content of synthetic post number {i}."}
    for i in range(1, 101)   # posts 1..100
]


# ---------------------------------------------------------------------------
# Store class
# ---------------------------------------------------------------------------

class PostStore:
    """
    Thread-safe in-memory store of synthetic posts.

    All mutating operations return the new state so callers can read-back
    and confirm the mutation took (or did not take) effect.
    """

    def __init__(self, seed: Optional[List[dict]] = None) -> None:
        self._lock = threading.Lock()
        src = seed if seed is not None else _SEED_POSTS
        self._posts: Dict[int, dict] = {p["id"]: dict(p) for p in src}

    # ------------------------------------------------------------------
    # Read operations (no state change)
    # ------------------------------------------------------------------

    def get(self, post_id: int) -> Optional[dict]:
        """Return the post record or None if absent."""
        with self._lock:
            rec = self._posts.get(post_id)
            return dict(rec) if rec else None

    def list(self) -> List[dict]:
        """Return a shallow-copy list of all current posts."""
        with self._lock:
            return [dict(v) for v in self._posts.values()]

    def count(self) -> int:
        """Return the current post count."""
        with self._lock:
            return len(self._posts)

    def ids(self) -> List[int]:
        """Return sorted list of current post IDs."""
        with self._lock:
            return sorted(self._posts.keys())

    # ------------------------------------------------------------------
    # Mutating operations -- only called AFTER adapter gets allow
    # ------------------------------------------------------------------

    def delete(self, post_id: int) -> bool:
        """Delete a single post. Returns True if it existed."""
        with self._lock:
            existed = post_id in self._posts
            self._posts.pop(post_id, None)
            return existed

    def bulk_delete(self, ids: List[int]) -> int:
        """Delete multiple posts. Returns count actually removed."""
        with self._lock:
            removed = 0
            for pid in ids:
                if pid in self._posts:
                    del self._posts[pid]
                    removed += 1
            return removed

    def update(self, post_id: int, fields: dict) -> Optional[dict]:
        """
        Update fields on an existing post. Returns the updated record,
        or None if the post does not exist.
        """
        with self._lock:
            if post_id not in self._posts:
                return None
            self._posts[post_id].update(fields)
            return dict(self._posts[post_id])

    # ------------------------------------------------------------------
    # Convenience for demo read-back proofs
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[int, dict]:
        """Return a full copy of the store (for before/after comparison)."""
        with self._lock:
            return {k: dict(v) for k, v in self._posts.items()}
