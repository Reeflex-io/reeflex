"""reeflex-mcp -- the Reeflex MCP gateway.

A transparent MCP proxy that governs any MCP upstream: it sits in the MCP
path, intercepts `tools/call`, normalizes the call into a Reeflex Action
Envelope (reeflex-spec/SPEC.md section 2), asks reeflex-core `POST
/v1/decide`, and (in enforce mode) applies the verdict -- everything else
passes through untouched.

See design/MCP-GATEWAY-DESIGN.md (v1 + addenda) for the full design; this
package implements Track 2 (the core proxy): scaffold, config, the fail-closed
core client, the multi-upstream registry, the dual-transport gateway front,
and a minimal heuristic normalizer. Declarative per-server mappings, full
enforcement (hold/resubmission), and setup/doctor tooling are later tracks.
"""

from __future__ import annotations

__version__ = "0.1.0"
