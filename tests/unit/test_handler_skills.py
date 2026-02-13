"""Unit checks for skill handler wrappers."""

from __future__ import annotations

import pytest

from shisad.core.api.schema import NoParams, SkillInstallParams, SkillRevokeParams
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers.skills import SkillHandlers


class _StubImpl:
    async def do_skill_list(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"skills": [{"name": "skill-a"}], "count": 1}

    async def do_skill_review(self, payload: dict[str, object]) -> dict[str, object]:
        return {"skill_path": str(payload["skill_path"]), "allowed": True}

    async def do_skill_install(self, payload: dict[str, object]) -> dict[str, object]:
        return {"status": "installed", "skill_path": str(payload["skill_path"])}

    async def do_skill_profile(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"network": [], "filesystem": [], "shell": []}

    async def do_skill_revoke(self, payload: dict[str, object]) -> dict[str, object]:
        return {"revoked": True, "skill_name": str(payload["skill_name"]), "reason": "manual"}


@pytest.mark.asyncio
async def test_skill_list_and_install_wrappers() -> None:
    handlers = SkillHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    listing = await handlers.handle_skill_list(NoParams(), RequestContext())
    installed = await handlers.handle_skill_install(
        SkillInstallParams(skill_path="/tmp/skill"),
        RequestContext(),
    )
    assert listing.count == 1
    assert installed.model_dump(mode="json")["status"] == "installed"


@pytest.mark.asyncio
async def test_skill_revoke_wrapper() -> None:
    handlers = SkillHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    revoked = await handlers.handle_skill_revoke(
        SkillRevokeParams(skill_name="skill-a"),
        RequestContext(),
    )
    assert revoked.revoked is True
