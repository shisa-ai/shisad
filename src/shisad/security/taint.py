"""Taint labeling and propagation utilities."""

from __future__ import annotations

from dataclasses import dataclass

from shisad.core.tools.names import canonical_tool_name
from shisad.core.types import TaintLabel
from shisad.security.firewall.secrets import detect_ingress_secrets

EGRESS_SINK_TOOLS = {
    "http.request",
    "web.fetch",
    "web.search",
    "send_email",
    "send_message",
    "post_to_webhook",
    "upload_file",
}

WRITE_TOOLS = {
    "file.write",
    "fs.write",
    "update_calendar",
    "create_event",
    "send_email",
    "send_message",
}

SENSITIVE_LABELS = {
    TaintLabel.SENSITIVE_EMAIL,
    TaintLabel.SENSITIVE_FILE,
    TaintLabel.SENSITIVE_CALENDAR,
}


@dataclass(frozen=True)
class TaintSinkDecision:
    block: bool
    require_confirmation: bool
    reason: str = ""


def label_ingress(text: str) -> set[TaintLabel]:
    """Label incoming untrusted content."""
    labels: set[TaintLabel] = {TaintLabel.UNTRUSTED}
    if detect_ingress_secrets(text):
        labels.add(TaintLabel.USER_CREDENTIALS)
    return labels


def label_retrieval(collection: str) -> set[TaintLabel]:
    """Assign taint labels based on retrieval collection trust tier."""
    mapping: dict[str, set[TaintLabel]] = {
        "user_curated": set(),
        "project_docs": {TaintLabel.UNTRUSTED},
        "external_web": {TaintLabel.UNTRUSTED},
        "tool_outputs": {TaintLabel.UNTRUSTED},
    }
    return mapping.get(collection, {TaintLabel.UNTRUSTED})


def normalize_retrieval_taints(
    *,
    taint_labels: set[TaintLabel] | list[TaintLabel] | None,
    collection: str,
) -> set[TaintLabel]:
    """Normalize retrieval taints to at least UNTRUSTED across all retrieval paths."""
    normalized = set(taint_labels or label_retrieval(collection))
    normalized.add(TaintLabel.UNTRUSTED)
    return normalized


def label_tool_output(tool_name: str) -> set[TaintLabel]:
    """Label tool output by trust characteristics."""
    canonical_name = canonical_tool_name(tool_name)
    external_tools = {
        "http.request",
        "web.search",
        "web.fetch",
        "retrieve_rag",
        "realitycheck.search",
        "realitycheck.read",
    }
    if canonical_name in external_tools:
        return {TaintLabel.UNTRUSTED}
    return set()


def propagate_taint(*label_sets: set[TaintLabel]) -> set[TaintLabel]:
    """Propagate taint by worst-case union semantics."""
    merged: set[TaintLabel] = set()
    for label_set in label_sets:
        merged.update(label_set)
    return merged


def sink_decision_for_tool(tool_name: str, labels: set[TaintLabel]) -> TaintSinkDecision:
    """Evaluate taint labels against sink rules for a proposed tool call."""
    canonical_name = canonical_tool_name(tool_name)
    if TaintLabel.USER_CREDENTIALS in labels:
        return TaintSinkDecision(block=True, require_confirmation=False, reason="credential_taint")

    if canonical_name in EGRESS_SINK_TOOLS and SENSITIVE_LABELS.intersection(labels):
        return TaintSinkDecision(
            block=True,
            require_confirmation=False,
            reason="sensitive_data_to_egress",
        )

    if canonical_name in WRITE_TOOLS and TaintLabel.UNTRUSTED in labels:
        return TaintSinkDecision(
            block=False,
            require_confirmation=True,
            reason="untrusted_data_to_write_sink",
        )

    return TaintSinkDecision(block=False, require_confirmation=False, reason="")
