"""Scope-layered policy compiler and explainer primitives (M4.9)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from itertools import pairwise
from typing import Any

from pydantic import BaseModel, Field

from shisad.governance.merge import (
    PolicyMerge,
    PolicyMergeError,
    PolicyPatch,
    ToolExecutionPolicy,
)


class ScopeLevel(StrEnum):
    ORG = "org"
    TEAM = "team"
    WORKSPACE = "workspace"
    USER = "user"
    SESSION = "session"
    TASK = "task"


class DelegationGrant(BaseModel):
    """Bounded delegation grants from parent to child scope."""

    allow_domain_suffixes: list[str] = Field(default_factory=list)
    allow_network_toggle: bool = False
    allow_sandbox_downgrade: bool = False


class ScopedPolicy(BaseModel):
    level: ScopeLevel
    constraints: ToolExecutionPolicy
    defaults: dict[str, Any] = Field(default_factory=dict)
    preferences: dict[str, Any] = Field(default_factory=dict)
    delegation: DelegationGrant = Field(default_factory=DelegationGrant)

    def constraints_as_patch(self) -> PolicyPatch:
        data = self.constraints.model_dump(mode="json")
        return PolicyPatch.model_validate(data)


@dataclass(slots=True)
class CompiledPolicy:
    effective: ToolExecutionPolicy
    defaults: dict[str, Any]
    preferences: dict[str, Any]
    contributors: dict[str, ScopeLevel] = field(default_factory=dict)


class ScopedPolicyCompiler:
    """Compile org->...->task policies with non-weakening guarantees."""

    @staticmethod
    def compile_chain(policies: list[ScopedPolicy]) -> CompiledPolicy:
        if not policies:
            raise ValueError("at least one scoped policy is required")

        ordered = list(policies)
        effective = ordered[0].constraints
        defaults = dict(ordered[0].defaults)
        preferences = dict(ordered[0].preferences)
        contributors: dict[str, ScopeLevel] = {}
        _record_contributors(
            contributors,
            old=None,
            new=effective,
            level=ordered[0].level,
        )

        for parent, child in pairwise(ordered):
            _enforce_delegation(parent=parent, child=child)
            merged = PolicyMerge.merge(server=effective, caller=child.constraints_as_patch())
            _record_contributors(
                contributors,
                old=effective,
                new=merged,
                level=child.level,
            )
            effective = merged
            defaults = _merge_defaults(defaults, child.defaults, constraints=effective)
            preferences = _merge_preferences(preferences, child.preferences)

        return CompiledPolicy(
            effective=effective,
            defaults=defaults,
            preferences=preferences,
            contributors=contributors,
        )

    @staticmethod
    def explain(compiled: CompiledPolicy, *, field_name: str) -> str:
        contributor = compiled.contributors.get(field_name)
        if contributor is None:
            return f"{field_name}: inherited from base scope"
        return f"{field_name}: constrained by {contributor.value} scope"


def _merge_defaults(
    parent_defaults: dict[str, Any],
    child_defaults: dict[str, Any],
    *,
    constraints: ToolExecutionPolicy,
) -> dict[str, Any]:
    merged = dict(parent_defaults)
    for key, value in child_defaults.items():
        if key == "network.allowed_domains":
            allowed = set(constraints.network.allowed_domains)
            narrowed = [item for item in value if item in allowed]
            merged[key] = narrowed
            continue
        if key == "sandbox_type":
            if str(value) == constraints.sandbox_type.value:
                merged[key] = value
            continue
        merged[key] = value
    return merged


def _merge_preferences(
    parent_preferences: dict[str, Any],
    child_preferences: dict[str, Any],
) -> dict[str, Any]:
    merged = dict(parent_preferences)
    merged.update(child_preferences)
    return merged


def _record_contributors(
    contributors: dict[str, ScopeLevel],
    *,
    old: ToolExecutionPolicy | None,
    new: ToolExecutionPolicy,
    level: ScopeLevel,
) -> None:
    new_dump = new.model_dump(mode="json")
    if old is None:
        for key in new_dump:
            contributors[key] = level
        return
    old_dump = old.model_dump(mode="json")
    for key, value in new_dump.items():
        if value != old_dump.get(key):
            contributors[key] = level


def _enforce_delegation(*, parent: ScopedPolicy, child: ScopedPolicy) -> None:
    grant = parent.delegation
    if not grant.allow_sandbox_downgrade:
        parent_rank = _sandbox_rank(parent.constraints.sandbox_type.value)
        child_rank = _sandbox_rank(child.constraints.sandbox_type.value)
        if child_rank < parent_rank:
            raise PolicyMergeError("delegation blocked sandbox downgrade")

    if (
        not grant.allow_network_toggle
        and child.constraints.network.allow_network
        and not parent.constraints.network.allow_network
    ):
        raise PolicyMergeError("delegation blocked allow_network elevation")

    if grant.allow_domain_suffixes:
        allowed_suffixes = [suffix.lower() for suffix in grant.allow_domain_suffixes]
        for domain in child.constraints.network.allowed_domains:
            normalized = domain.lower()
            if any(normalized.endswith(suffix) for suffix in allowed_suffixes):
                continue
            if normalized in parent.constraints.network.allowed_domains:
                continue
            raise PolicyMergeError(f"delegation blocked domain extension: {domain}")


def _sandbox_rank(value: str) -> int:
    if value == "vm":
        return 3
    if value == "nsjail":
        return 2
    if value == "container":
        return 1
    return 0
