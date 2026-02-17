"""Skill handler implementations."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from shisad.core.events import SkillInstalled, SkillProfiled, SkillReviewRequested, SkillRevoked
from shisad.daemon.handlers._mixin_typing import HandlerMixinBase


class SkillsImplMixin(HandlerMixinBase):
    async def do_skill_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        _ = params
        skills = [item.model_dump(mode="json") for item in self._skill_manager.list_installed()]
        return {"skills": skills, "count": len(skills)}

    async def do_skill_review(self, params: Mapping[str, Any]) -> dict[str, Any]:
        skill_path = Path(str(params.get("skill_path", "")).strip())
        if not skill_path.exists():
            raise ValueError(f"skill path not found: {skill_path}")
        result = self._skill_manager.review(skill_path)
        manifest = self._load_skill_manifest(skill_path)
        findings = [item for item in result.get("findings", []) if isinstance(item, dict)]
        signature_status = str(result.get("signature", ""))
        reputation = self._skill_reputation(
            manifest=manifest,
            signature_status=signature_status,
            findings=findings,
        )
        result["reputation"] = reputation
        manifest_payload = result.get("manifest", {})
        if not isinstance(manifest_payload, dict):
            manifest_payload = {}
        await self._event_bus.publish(
            SkillReviewRequested(
                session_id=None,
                actor="skill_manager",
                skill_name=str(manifest_payload.get("name", "")),
                version=str(manifest_payload.get("version", "")),
                source_repo=str(manifest_payload.get("source_repo", "")),
                signature_status=signature_status,
                findings_count=len(findings),
            )
        )
        return cast(dict[str, Any], result)

    async def do_skill_install(self, params: Mapping[str, Any]) -> dict[str, Any]:
        skill_path = Path(str(params.get("skill_path", "")).strip())
        if not skill_path.exists():
            raise ValueError(f"skill path not found: {skill_path}")
        manifest = self._load_skill_manifest(skill_path)
        author_id = str(getattr(manifest, "author", "")).strip() or "unknown"
        if not self._reputation_scorer.can_submit(author_id=author_id):
            manifest_hash = manifest.manifest_hash() if manifest is not None else ""
            reputation = self._skill_reputation(
                manifest=manifest,
                signature_status="unknown",
                findings=[],
            )
            payload = {
                "allowed": False,
                "status": "review",
                "reason": "submission_rate_limited",
                "findings": [],
                "summary": "Submission temporarily rate-limited for this author.",
                "artifact_state": "review",
                "reputation": reputation,
            }
            await self._event_bus.publish(
                SkillInstalled(
                    session_id=None,
                    actor="skill_manager",
                    skill_name=str(getattr(manifest, "name", "")),
                    version=str(getattr(manifest, "version", "")),
                    source_repo=str(getattr(manifest, "source_repo", "")),
                    manifest_hash=manifest_hash,
                    status="rate_limited",
                    allowed=False,
                    signature_status="unknown",
                    findings_count=0,
                    artifact_state="review",
                )
            )
            return payload

        decision = await self._skill_manager.install(
            skill_path,
            approve_untrusted=bool(params.get("approve_untrusted", False)),
        )
        self._reputation_scorer.record_submission(author_id=author_id)
        payload = decision.model_dump(mode="json")
        raw_findings = payload.get("findings")
        findings = [
            item for item in raw_findings if isinstance(item, dict)
        ] if isinstance(raw_findings, list) else []
        reputation = self._skill_reputation(
            manifest=manifest,
            signature_status="trusted" if decision.allowed else "unknown",
            findings=findings,
        )
        payload["reputation"] = reputation
        manifest_hash = manifest.manifest_hash() if manifest is not None else ""
        await self._event_bus.publish(
            SkillInstalled(
                session_id=None,
                actor="skill_manager",
                skill_name=str(getattr(manifest, "name", "")),
                version=str(getattr(manifest, "version", "")),
                source_repo=str(getattr(manifest, "source_repo", "")),
                manifest_hash=manifest_hash,
                status=str(payload.get("status", "")),
                allowed=bool(payload.get("allowed", False)),
                signature_status="trusted" if decision.allowed else "unknown",
                findings_count=len(findings),
                artifact_state=str(payload.get("artifact_state", "")),
            )
        )
        return cast(dict[str, Any], payload)

    async def do_skill_profile(self, params: Mapping[str, Any]) -> dict[str, Any]:
        skill_path = Path(str(params.get("skill_path", "")).strip())
        if not skill_path.exists():
            raise ValueError(f"skill path not found: {skill_path}")
        profile = self._skill_manager.profile(skill_path)
        payload = profile.profile.to_json()
        manifest = self._load_skill_manifest(skill_path)

        def _extract_capabilities(
            values: Any,
            *,
            legacy_key: str,
        ) -> list[str]:
            if not isinstance(values, list):
                return []
            extracted: list[str] = []
            for value in values:
                if isinstance(value, str):
                    item = value
                elif isinstance(value, dict):
                    item = str(value.get(legacy_key, ""))
                else:
                    item = ""
                if item:
                    extracted.append(item)
            return extracted

        await self._event_bus.publish(
            SkillProfiled(
                session_id=None,
                actor="skill_manager",
                skill_name=str(getattr(manifest, "name", "")),
                version=str(getattr(manifest, "version", "")),
                capabilities={
                    "network": _extract_capabilities(
                        payload.get("network_domains", payload.get("network", [])),
                        legacy_key="domain",
                    ),
                    "filesystem": _extract_capabilities(
                        payload.get("filesystem_paths", payload.get("filesystem", [])),
                        legacy_key="path",
                    ),
                    "shell": _extract_capabilities(
                        payload.get("shell_commands", payload.get("shell", [])),
                        legacy_key="command",
                    ),
                    "environment": _extract_capabilities(
                        payload.get("environment_vars", payload.get("environment", [])),
                        legacy_key="var",
                    ),
                },
            )
        )
        return cast(dict[str, Any], payload)

    async def do_skill_revoke(self, params: Mapping[str, Any]) -> dict[str, Any]:
        skill_name = str(params.get("skill_name", "")).strip()
        if not skill_name:
            raise ValueError("skill_name is required")
        reason = str(params.get("reason", "security_revoke")).strip() or "security_revoke"
        existing = next(
            (item for item in self._skill_manager.list_installed() if item.name == skill_name),
            None,
        )
        if existing is None:
            return {"revoked": False, "skill_name": skill_name, "reason": "not_found"}
        updated = self._skill_manager.revoke(skill_name=skill_name, reason=reason)
        if updated is None:
            return {"revoked": False, "skill_name": skill_name, "reason": "not_found"}
        await self._event_bus.publish(
            SkillRevoked(
                session_id=None,
                actor="skill_manager",
                skill_name=skill_name,
                reason=reason,
                previous_state=existing.state.value,
            )
        )
        return {
            "revoked": True,
            "skill_name": skill_name,
            "reason": reason,
            "state": updated.state.value,
        }
