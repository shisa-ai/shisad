"""Retrieval taint normalization regressions."""

from __future__ import annotations

from shisad.core.types import TaintLabel
from shisad.security.taint import normalize_retrieval_taints


def test_m1_h0_normalize_retrieval_taints_defaults_to_untrusted() -> None:
    labels = normalize_retrieval_taints(taint_labels=None, collection="user_curated")
    assert labels == {TaintLabel.UNTRUSTED}


def test_m1_h0_normalize_retrieval_taints_preserves_existing_labels() -> None:
    labels = normalize_retrieval_taints(
        taint_labels={TaintLabel.USER_CREDENTIALS},
        collection="project_docs",
    )
    assert labels == {TaintLabel.USER_CREDENTIALS}
