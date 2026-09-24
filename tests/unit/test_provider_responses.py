"""Responses protocol translation and routed-provider contracts."""

import json

import pytest

from shisad.core.config import ModelConfig
from shisad.core.providers.base import Message, OpenAICompatibleProvider
from shisad.core.providers.capabilities import EndpointFamily, RequestParameters
from shisad.core.providers.request_profiles import apply_request_profile
from shisad.core.providers.responses import OpenAIResponsesProvider
from shisad.core.providers.routed_openai import RoutedOpenAIProvider
from shisad.core.providers.routing import ModelComponent, ModelRouter


def output(*items, status="completed"):
    return {"status": status, "model": "gpt-6-luna", "output": list(items)}


def message(text="Hello"):
    return {
        "type": "message",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": text}],
    }


def call(call_id="call-a", **overrides):
    return {
        "type": "function_call",
        "call_id": call_id,
        "name": "fs_read",
        "arguments": '{"path":"README.md"}',
        "status": "completed",
        **overrides,
    }


def provider(monkeypatch, response, **kwargs):
    captured = {}

    def post(self, url, payload):
        captured.update(url=url, payload=payload)
        return response

    monkeypatch.setattr(OpenAICompatibleProvider, "_post_json", post)
    return OpenAIResponsesProvider(
        base_url="https://api.example.com/v1", model_id="gpt-6-luna", **kwargs
    ), captured


@pytest.mark.asyncio
async def test_text_reasoning_json_and_usage_translation(monkeypatch):
    data = output({"type": "reasoning", "summary": [{"text": "private reasoning"}]}, message())
    data["usage"] = {
        "input_tokens": 10,
        "output_tokens": 5,
        "total_tokens": 15,
        "output_tokens_details": {"reasoning_tokens": 3},
    }
    client, captured = provider(
        monkeypatch,
        data,
        force_json_response=True,
        request_parameters=RequestParameters(reasoning_effort="medium", max_completion_tokens=100),
    )
    response = await client.complete(
        [Message(role="system", content="Return JSON"), Message(role="user", content="hello")]
    )
    assert captured["url"] == "https://api.example.com/v1/responses"
    payload = captured["payload"]
    assert payload["input"] == [
        {"role": "system", "content": "Return JSON"},
        {"role": "user", "content": "hello"},
    ]
    assert payload["reasoning"] == {"effort": "medium"}
    assert payload["max_output_tokens"] == 100
    assert payload["text"] == {"format": {"type": "json_object"}}
    assert payload["store"] is False
    assert "previous_response_id" not in payload
    assert "tools" not in payload and "messages" not in payload
    assert response.message.content == "Hello"
    assert response.finish_reason == "stop"
    assert response.usage == {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}


@pytest.mark.asyncio
async def test_function_schema_calls_and_results_preserve_ids_and_optional_parameters(monkeypatch):
    client, captured = provider(monkeypatch, output(call(), call("call-b")))
    schema = {
        "type": "function",
        "function": {
            "name": "fs_read",
            "description": "Read",
            "parameters": {"type": "object", "properties": {"path": {"type": "string"}}},
        },
    }
    response = await client.complete([Message(role="user", content="Read files")], [schema])
    assert captured["payload"]["tools"] == [
        {"type": "function", **schema["function"], "strict": False}
    ]
    assert "strict" not in schema["function"]
    assert response.finish_reason == "tool_calls"
    assert [c["id"] for c in response.message.tool_calls] == ["call-a", "call-b"]
    response.message.content = "Reading files"
    await client.complete(
        [response.message, Message(role="tool", tool_call_id="call-a", content="file text")]
    )
    assert captured["payload"]["input"] == [
        {"role": "assistant", "content": "Reading files"},
        {
            "type": "function_call",
            "call_id": "call-a",
            "name": "fs_read",
            "arguments": '{"path":"README.md"}',
        },
        {
            "type": "function_call",
            "call_id": "call-b",
            "name": "fs_read",
            "arguments": '{"path":"README.md"}',
        },
        {"type": "function_call_output", "call_id": "call-a", "output": "file text"},
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "data",
    [
        output(call(), status="incomplete"),
        output(call(), status="failed"),
        output(call(), status="in_progress"),
        output(call(status="incomplete")),
        output(call(arguments={"path": "README.md"})),
        output(call(call_id="")),
        output(call(name="")),
        output(call(), call()),
        output({"type": "web_search_call"}),
        output({"type": "message", "role": "assistant", "content": "bad"}),
        {"status": "completed"},
        output(),
        output(123),
    ],
)
async def test_unusable_response_never_exposes_executable_calls(monkeypatch, data):
    client, _ = provider(monkeypatch, data)
    with pytest.raises(RuntimeError):
        await client.complete([Message(role="user", content="test")])


@pytest.mark.asyncio
async def test_refusal_is_visible_but_cannot_carry_tool_calls(monkeypatch):
    refusal = {
        "type": "message",
        "role": "assistant",
        "content": [{"type": "refusal", "refusal": "I cannot do that."}],
    }
    client, _ = provider(monkeypatch, output(refusal, call()))
    result = await client.complete([Message(role="user", content="test")])
    assert result.message.content == "I cannot do that."
    assert not result.message.tool_calls
    assert result.finish_reason == "content_filter"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tools,messages",
    [
        ([{"type": "web_search"}], [Message(role="user", content="test")]),
        (None, [Message(role="tool", content="orphan result")]),
        (None, [Message(role="system", content="test", tool_calls=[{"id": "a"}])]),
    ],
)
async def test_unsupported_inputs_fail_before_transport(monkeypatch, tools, messages):
    client, captured = provider(monkeypatch, output(message()))
    with pytest.raises(ValueError):
        await client.complete(messages, tools)
    assert captured == {}


@pytest.mark.parametrize(
    "params",
    [
        {"frequency_penalty": 1},
        {"presence_penalty": 1},
        {"reasoning": {"budget_tokens": 10}},
        {"max_tokens": 10, "max_completion_tokens": 20},
    ],
)
def test_responses_rejects_incompatible_parameters(params):
    with pytest.raises(ValueError):
        apply_request_profile(
            profile_name="openai_responses",
            endpoint_family=EndpointFamily.RESPONSES,
            model_id="gpt-6-luna",
            request_parameters=RequestParameters(**params),
        )


@pytest.mark.asyncio
async def test_config_router_and_monitor_use_responses_with_existing_auth(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    config = ModelConfig(
        planner_provider_preset="openai_default",
        monitor_provider_preset="openai_default",
        planner_model_id="gpt-6-luna",
        monitor_model_id="gpt-6-luna",
        planner_endpoint_family="responses",
        monitor_endpoint_family="responses",
        planner_request_parameters={"reasoning_effort": "medium"},
        monitor_request_parameters={"reasoning_effort": "medium"},
    )
    router = ModelRouter(config)
    route = router.route_for(ModelComponent.PLANNER)
    assert route.request_parameter_profile == "openai_responses"
    assert route.effective_request_payload == {"reasoning": {"effort": "medium"}}

    class HttpResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return json.dumps(output(message('{"ok": true}'))).encode()

    captured = []

    def open_http(req, timeout):
        assert req.full_url == "https://api.openai.com/v1/responses"
        assert req.get_header("Authorization") == "Bearer test-key"
        captured.append(json.loads(req.data))
        return HttpResponse()

    monkeypatch.setattr("shisad.core.providers.base._open_no_redirect", open_http)
    routed = RoutedOpenAIProvider(router=router)
    assert (await routed.complete([Message(role="user", content="hello")])).model == "gpt-6-luna"
    assert (
        await routed.monitor_complete([Message(role="user", content="Return JSON")])
    ).finish_reason == "stop"
    assert "text" not in captured[0]
    assert captured[1]["text"]["format"]["type"] == "json_object"


@pytest.mark.asyncio
async def test_responses_preserves_private_endpoint_blocking(monkeypatch):
    client = OpenAIResponsesProvider(base_url="https://10.0.0.1/v1", model_id="gpt-6-luna")
    monkeypatch.setattr(
        "shisad.core.providers.base._open_no_redirect",
        lambda *args, **kwargs: pytest.fail("must not connect"),
    )
    with pytest.raises(RuntimeError, match="blocked"):
        await client.complete([Message(role="user", content="test")])


@pytest.mark.parametrize(
    "family,profile",
    [
        (EndpointFamily.RESPONSES, "openai_chat_general"),
        (EndpointFamily.CHAT_COMPLETIONS, "openai_responses"),
    ],
)
def test_endpoint_profile_mismatch_fails_configuration(family, profile):
    with pytest.raises(ValueError, match="responses"):
        apply_request_profile(
            profile_name=profile,
            endpoint_family=family,
            model_id="test",
            request_parameters=RequestParameters(),
        )


def test_responses_profile_maps_legacy_limit_and_reasoning_mode():
    result = apply_request_profile(
        profile_name="openai_responses",
        endpoint_family=EndpointFamily.RESPONSES,
        model_id="test",
        request_parameters=RequestParameters(
            max_tokens=100,
            max_completion_tokens=100,
            reasoning_effort="medium",
            reasoning={"mode": "standard"},
            temperature=0.5,
            top_p=0.9,
        ),
    )
    assert result.payload == {
        "max_output_tokens": 100,
        "reasoning": {"mode": "standard", "effort": "medium"},
        "temperature": 0.5,
        "top_p": 0.9,
    }
    assert set(result.mapped_fields) == {
        "max_tokens->max_output_tokens",
        "max_completion_tokens->max_output_tokens",
        "reasoning_effort->reasoning.effort",
    }


def test_embeddings_cannot_select_responses():
    with pytest.raises(ValueError, match="embeddings_endpoint_family"):
        ModelRouter(ModelConfig(embeddings_endpoint_family="responses")).all_routes()
