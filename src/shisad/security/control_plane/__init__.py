"""M5 injection-proof control-plane package."""

from shisad.security.control_plane.audit import ControlPlaneAuditLog
from shisad.security.control_plane.consensus import (
    ActionMonitorVoter,
    ConsensusDecision,
    ConsensusPolicy,
    ConsensusVotingSystem,
    VoterDecision,
)
from shisad.security.control_plane.differential import (
    DifferentialExecutionAnalyzer,
    DifferentialSignal,
)
from shisad.security.control_plane.engine import ControlPlaneEngine, ControlPlaneEvaluation
from shisad.security.control_plane.history import ActionHistoryRecord, SessionActionHistoryStore
from shisad.security.control_plane.network import (
    BaselineDatabase,
    NetworkIntelligenceMonitor,
    NetworkMetadata,
    NetworkMonitorDecision,
    ThreatIntelStub,
)
from shisad.security.control_plane.resource import ResourceAccessMonitor, ResourceFinding
from shisad.security.control_plane.schema import (
    ActionKind,
    ControlDecision,
    ControlPlaneAction,
    Origin,
    RiskTier,
    build_action,
)
from shisad.security.control_plane.sequence import BehavioralSequenceAnalyzer, SequenceFinding
from shisad.security.control_plane.trace import (
    CommittedPlan,
    ExecutionTraceVerifier,
    PlanVerificationResult,
)

__all__ = [
    "ActionHistoryRecord",
    "ActionKind",
    "ActionMonitorVoter",
    "BaselineDatabase",
    "BehavioralSequenceAnalyzer",
    "CommittedPlan",
    "ConsensusDecision",
    "ConsensusPolicy",
    "ConsensusVotingSystem",
    "ControlDecision",
    "ControlPlaneAction",
    "ControlPlaneAuditLog",
    "ControlPlaneEngine",
    "ControlPlaneEvaluation",
    "DifferentialExecutionAnalyzer",
    "DifferentialSignal",
    "ExecutionTraceVerifier",
    "NetworkIntelligenceMonitor",
    "NetworkMetadata",
    "NetworkMonitorDecision",
    "Origin",
    "PlanVerificationResult",
    "ResourceAccessMonitor",
    "ResourceFinding",
    "RiskTier",
    "SequenceFinding",
    "SessionActionHistoryStore",
    "ThreatIntelStub",
    "VoterDecision",
    "build_action",
]
