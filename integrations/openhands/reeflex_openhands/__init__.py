"""reeflex-openhands: a Reeflex gate as an OpenHands security analyzer.

    from reeflex_openhands import ReeflexSecurityAnalyzer, run_governed

    analyzer = ReeflexSecurityAnalyzer("https://core.example", os.environ["REEFLEX_CORE_TOKEN"])
    analyzer.attach(conversation)        # analyzer + ReeflexConfirmationPolicy
    conversation.send_message("...")
    run_governed(conversation)           # denies rejected, holds resolved in the portal
"""

from .analyzer import ReeflexSecurityAnalyzer
from .policy import (
    ReeflexConfirmationPolicy,
    console_confirm,
    pending_actions,
    resolve_holds,
    resolve_pending,
    run_governed,
)

__version__ = "0.1.0"

__all__ = [
    "ReeflexSecurityAnalyzer",
    "ReeflexConfirmationPolicy",
    "console_confirm",
    "pending_actions",
    "resolve_holds",
    "resolve_pending",
    "run_governed",
    "__version__",
]
