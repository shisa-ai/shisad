"""Approval language is reviewed; target membership remains structural."""

import asyncio
import json

import pytest

from shisad.core.approval_intent import ApprovalIntentReviewer, parse_approval_command
from shisad.core.providers.base import Message, ProviderResponse
from shisad.security.firewall import ContentFirewall

REQUEST = "Approve the pending fetch of https://www.iana.org/help/example-domains."
PENDING = [
    {
        "confirmation_id": "c-fetch",
        "index": 1,
        "tool_name": "web.fetch",
        "arguments": {"url": "https://www.iana.org/help/example-domains"},
    }
]


class Provider:
    def __init__(self, payload):
        self.payload = payload
        self.messages = []

    async def complete(self, messages, tools=None):
        assert tools is None
        self.messages = messages
        if isinstance(self.payload, Exception):
            raise self.payload
        return ProviderResponse(message=Message(role="assistant", content=json.dumps(self.payload)))


def decision(**overrides):
    return {
        "decision": "confirm",
        "target": "c-fetch",
        "scope": "one",
        "quote": REQUEST,
        **overrides,
    }


async def review(provider, **kwargs):
    return await ApprovalIntentReviewer(provider=provider, firewall=ContentFirewall()).review(
        user_request=kwargs.get("user_request", REQUEST), pending=kwargs.get("pending", PENDING)
    )


@pytest.mark.asyncio
async def test_fresh_review_binds_current_user_quote_and_known_id():
    provider = Provider(decision())
    result = await review(provider)
    assert result.decision == "confirm"
    assert result.target == "c-fetch"
    assert len(provider.messages) == 2
    assert REQUEST not in provider.messages[0].content
    assert json.loads(provider.messages[1].content)["user_request"] == REQUEST


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        decision(target="other"),
        decision(quote="Approve everything"),
        decision(quote=""),
        decision(scope="all"),
        decision(decision="none"),
        {**decision(), "extra": True},
        RuntimeError("provider failed"),
    ],
)
async def test_unbound_or_invalid_review_cannot_authorize(payload):
    assert (await review(Provider(payload))).decision == "unresolved"


@pytest.mark.asyncio
async def test_pending_text_cannot_supply_user_approval_quote():
    assert (
        await review(Provider(decision()), user_request="What is pending?")
    ).decision == "unresolved"


@pytest.mark.asyncio
async def test_none_reject_and_explicit_all_results():
    assert (
        await review(Provider(decision(decision="none", target="", quote="")))
    ).decision == "none"
    assert (await review(Provider(decision(decision="reject")))).decision == "reject"
    assert (await review(Provider(decision(target="all", scope="all")))).scope == "all"


@pytest.mark.asyncio
async def test_missing_provider_and_oversized_packet_are_unresolved():
    assert (await review(None)).decision == "unresolved"
    provider = Provider(decision())
    assert (await review(provider, user_request="x" * 65000)).decision == "unresolved"
    assert not provider.messages


@pytest.mark.asyncio
async def test_timeout_is_unresolved():
    class Slow:
        async def complete(self, messages, tools=None):
            await asyncio.sleep(1)

    result = await ApprovalIntentReviewer(
        provider=Slow(), firewall=ContentFirewall(), timeout_seconds=0.001
    ).review(user_request=REQUEST, pending=PENDING)
    assert result.decision == "unresolved"


@pytest.mark.parametrize(
    "text",
    [
        "confirm 1 please",
        "Do not confirm 1",
        "confirm 1?",
        "Approve the pending fetch",
        "yes",
        "confirm unrelated",
    ],
)
def test_prose_is_not_parsed_as_command(text):
    assert parse_approval_command(text, ("c-fetch",)) is None


@pytest.mark.parametrize(
    ("text", "target", "scope"),
    [
        ("confirm 1", "1", "one"),
        ("reject c-fetch", "c-fetch", "one"),
        ("confirm all", "all", "all"),
    ],
)
def test_exact_command_grammar(text, target, scope):
    result = parse_approval_command(text, ("c-fetch",))
    assert result.target == target
    assert result.scope == scope


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["tool_call", "truncated", "oversized"])
async def test_nonfinal_or_tool_bearing_review_cannot_authorize(fault):
    class InvalidProvider(Provider):
        async def complete(self, messages, tools=None):
            response = await super().complete(messages, tools)
            if fault == "tool_call":
                response.message.tool_calls = [
                    {
                        "id": "bad",
                        "type": "function",
                        "function": {"name": "confirm", "arguments": "{}"},
                    }
                ]
            elif fault == "truncated":
                response.finish_reason = "length"
            else:
                response.message.content = "x" * 8001
            return response

    assert (await review(InvalidProvider(decision()))).decision == "unresolved"
