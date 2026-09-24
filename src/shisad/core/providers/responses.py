"""Stateless Responses API adapter for text and application-owned function tools."""

from __future__ import annotations

import asyncio
from typing import Any

from shisad.core.providers.base import Message, OpenAICompatibleProvider, ProviderResponse
from shisad.core.providers.capabilities import EndpointFamily
from shisad.core.providers.request_profiles import PROFILE_OPENAI_RESPONSES, apply_request_profile


class OpenAIResponsesProvider(OpenAICompatibleProvider):
    """Translate the existing provider contract while retaining its HTTP safeguards."""

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        parameters = apply_request_profile(
            profile_name=PROFILE_OPENAI_RESPONSES,
            endpoint_family=EndpointFamily.RESPONSES,
            model_id=self._model_id,
            request_parameters=self._request_parameters,
        )
        payload: dict[str, Any] = {
            "model": self._model_id,
            "input": self._responses_input(messages),
            "store": False,
            **parameters.payload,
        }
        if self._force_json_response:
            payload["text"] = {"format": {"type": "json_object"}}
        if tools:
            payload["tools"] = [self._responses_tool(tool) for tool in tools]
        data = await asyncio.to_thread(self._post_json, self._build_endpoint("responses"), payload)
        return self._responses_output(data)

    @staticmethod
    def _responses_tool(tool: dict[str, Any]) -> dict[str, Any]:
        function = tool.get("function")
        if tool.get("type") != "function" or not isinstance(function, dict):
            raise ValueError("Responses supports application function tools only")
        if not isinstance(function.get("name"), str) or not function["name"].strip():
            raise ValueError("Responses function tool requires a name")
        if not set(function) <= {"name", "description", "parameters", "strict"}:
            raise ValueError("Unsupported Responses function definition fields")
        # Responses otherwise attempts strict normalization, changing optional fields.
        return {"type": "function", "strict": False, **function}

    @staticmethod
    def _responses_input(messages: list[Message]) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for message in messages:
            if message.role == "tool":
                if not message.tool_call_id or message.tool_calls:
                    raise ValueError("Responses tool result requires a call ID and no calls")
                items.append(
                    {
                        "type": "function_call_output",
                        "call_id": message.tool_call_id,
                        "output": message.content,
                    }
                )
                continue
            if message.role not in {"system", "developer", "user", "assistant"}:
                raise ValueError("Unsupported Responses message role")
            if message.tool_call_id is not None or (
                message.tool_calls and message.role != "assistant"
            ):
                raise ValueError("Responses function calls require an assistant message")
            if message.content or not message.tool_calls:
                items.append({"role": message.role, "content": message.content})
            for call in message.tool_calls:
                function = call.get("function")
                if (
                    call.get("type") != "function"
                    or not isinstance(function, dict)
                    or not isinstance(call.get("id"), str)
                    or not call["id"].strip()
                    or not isinstance(function.get("name"), str)
                    or not function["name"].strip()
                    or not isinstance(function.get("arguments"), str)
                ):
                    raise ValueError("Invalid Responses function call history")
                items.append(
                    {
                        "type": "function_call",
                        "call_id": call["id"],
                        "name": function["name"],
                        "arguments": function["arguments"],
                    }
                )
        return items

    def _responses_output(self, data: dict[str, Any]) -> ProviderResponse:
        # Never execute a partial batch, even if some calls happen to contain valid JSON.
        if data.get("status") != "completed" or data.get("error") is not None:
            raise RuntimeError("Responses provider did not complete the response")
        output = data.get("output")
        if not isinstance(output, list):
            raise RuntimeError("Responses provider output must be an array")
        texts: list[str] = []
        refusals: list[str] = []
        calls: list[dict[str, Any]] = []
        call_ids: set[str] = set()
        for item in output:
            if not isinstance(item, dict) or item.get("status") not in {None, "completed"}:
                raise RuntimeError("Invalid or incomplete Responses output item")
            kind = item.get("type")
            if kind == "reasoning":
                # Reasoning is neither assistant prose nor an executable action.
                continue
            if kind == "function_call":
                call_id, name, arguments = (
                    item.get("call_id"),
                    item.get("name"),
                    item.get("arguments"),
                )
                if (
                    not isinstance(call_id, str)
                    or not call_id.strip()
                    or call_id in call_ids
                    or not isinstance(name, str)
                    or not name.strip()
                    or not isinstance(arguments, str)
                ):
                    raise RuntimeError("Invalid Responses function call")
                call_ids.add(call_id)
                calls.append(
                    {
                        "id": call_id,
                        "type": "function",
                        "function": {"name": name, "arguments": arguments},
                    }
                )
            elif kind == "message":
                content = item.get("content")
                if item.get("role") != "assistant" or not isinstance(content, list):
                    raise RuntimeError("Invalid Responses assistant message")
                for part in content:
                    if not isinstance(part, dict):
                        raise RuntimeError("Invalid Responses message content")
                    if part.get("type") == "output_text" and isinstance(part.get("text"), str):
                        texts.append(part["text"])
                    elif part.get("type") == "refusal" and isinstance(part.get("refusal"), str):
                        refusals.append(part["refusal"])
                    else:
                        raise RuntimeError("Unsupported Responses message content")
            else:
                raise RuntimeError("Unsupported Responses output item")
        if not texts and not calls and not refusals:
            raise RuntimeError("Responses provider returned no text or function calls")
        usage = self._coerce_usage(data.get("usage"))
        normalized_usage = {
            target: usage[source]
            for source, target in (
                ("input_tokens", "prompt_tokens"),
                ("output_tokens", "completion_tokens"),
                ("total_tokens", "total_tokens"),
            )
            if source in usage
        }
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="\n".join(refusals or texts),
                tool_calls=[] if refusals else calls,
            ),
            model=str(data.get("model", self._model_id)),
            finish_reason="content_filter" if refusals else "tool_calls" if calls else "stop",
            usage=normalized_usage,
        )
