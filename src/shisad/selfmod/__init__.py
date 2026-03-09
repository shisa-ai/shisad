"""Admin self-modification artifact management."""

from .manager import (
    SelfModificationApplyResult,
    SelfModificationManager,
    SelfModificationProposal,
    SelfModificationRollbackResult,
)

__all__ = [
    "SelfModificationApplyResult",
    "SelfModificationManager",
    "SelfModificationProposal",
    "SelfModificationRollbackResult",
]
