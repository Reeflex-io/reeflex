"""
reeflex-litellm -- the Reeflex governance seat inside an LLM gateway.

A LiteLLM post-call guardrail that rules on every tool call the models behind
the proxy propose: allow / deny / require_approval, on the same Action Envelope
and the same reeflex-core `/v1/decide` every other Reeflex adapter uses.

What this seat guarantees and what it does not is in README.md, and the short
version belongs here too, because it is the thing most easily overclaimed:
a gateway sees a tool call PROPOSED, not EXECUTED.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
