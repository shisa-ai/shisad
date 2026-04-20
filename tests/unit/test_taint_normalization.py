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
    assert labels == {TaintLabel.UNTRUSTED, TaintLabel.USER_CREDENTIALS}


def test_m1_h0_normalize_retrieval_taints_adds_untrusted_for_explicit_empty_set() -> None:
    labels = normalize_retrieval_taints(
        taint_labels=set(),
        collection="project_docs",
    )
    assert labels == {TaintLabel.UNTRUSTED}


# PLN-L5: exercise the `collection` parameter across all known collections
# plus an unknown one. When the caller passes `None` / empty labels, the
# `collection` branch in `label_retrieval` is what decides the starting
# taint set — previously the tests always combined truthy labels with
# `project_docs`, so a regression that broke `label_retrieval` for
# specific collections would have passed silently.


def test_normalize_retrieval_taints_user_curated_stays_untrusted_only_when_unspecified() -> None:
    # user_curated is the only trusted-tier collection; even so, the
    # normalization contract promises at least UNTRUSTED.
    labels = normalize_retrieval_taints(taint_labels=None, collection="user_curated")
    assert labels == {TaintLabel.UNTRUSTED}


def test_normalize_retrieval_taints_external_web_stays_untrusted() -> None:
    labels = normalize_retrieval_taints(taint_labels=None, collection="external_web")
    assert labels == {TaintLabel.UNTRUSTED}


def test_normalize_retrieval_taints_tool_outputs_stays_untrusted() -> None:
    labels = normalize_retrieval_taints(taint_labels=None, collection="tool_outputs")
    assert labels == {TaintLabel.UNTRUSTED}


def test_normalize_retrieval_taints_unknown_collection_falls_back_to_untrusted() -> None:
    # `label_retrieval` defaults to {UNTRUSTED} for an unrecognized
    # collection. Pin that default so a regression that relaxed the
    # fallback (e.g. `mapping.get(collection, set())`) would fail.
    labels = normalize_retrieval_taints(
        taint_labels=None,
        collection="brand-new-unknown-collection",
    )
    assert labels == {TaintLabel.UNTRUSTED}


def test_normalize_retrieval_taints_collection_is_irrelevant_once_labels_provided() -> None:
    # When the caller supplies labels, `collection` has no effect on the
    # starting set; UNTRUSTED is still always added. Pinning this invariant
    # across two distinct collections catches a regression that
    # accidentally conflated the two branches.
    user_curated = normalize_retrieval_taints(
        taint_labels={TaintLabel.USER_REVIEWED},
        collection="user_curated",
    )
    external_web = normalize_retrieval_taints(
        taint_labels={TaintLabel.USER_REVIEWED},
        collection="external_web",
    )
    assert user_curated == external_web == {TaintLabel.USER_REVIEWED, TaintLabel.UNTRUSTED}
