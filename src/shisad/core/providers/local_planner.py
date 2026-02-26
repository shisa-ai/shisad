"""Local fallback provider for daemon planner and embeddings routes."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from typing import Any

from shisad.core.providers.base import EmbeddingResponse, Message, ProviderResponse


class LocalPlannerProvider:
    """Local fallback planner provider for daemon operation."""

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        _ = tools
        user_content = messages[-1].content if messages else ""
        normalized_content = user_content.replace("^", "")
        goal_text = normalized_content
        goal_match = re.search(
            (
                r"=== (?:USER GOAL|USER REQUEST) ===\n"
                r".*?\n"
                r"(.*?)\n\n"
                r"=== (?:EXTERNAL CONTENT[^\n]*|DATA EVIDENCE[^\n]*|END CONTEXT|END PAYLOAD)"
            ),
            normalized_content,
            flags=re.DOTALL,
        )
        if goal_match:
            goal_text = goal_match.group(1).strip()
        goal_lower = goal_text.lower()
        actions: list[dict[str, Any]] = []

        anomaly_triggers = (
            "report anomaly",
            "security incident",
            "possible compromise",
            "suspicious behavior",
        )
        if "retrieve:" in goal_lower or "retrieve evidence" in goal_lower:
            query = goal_text.split(":", 1)[-1].strip() or goal_text[:180]
            actions.append(
                {
                    "action_id": "local-retrieve-1",
                    "tool_name": "retrieve_rag",
                    "arguments": {
                        "query": query,
                        "limit": 5,
                    },
                    "reasoning": "Retrieve supporting evidence for user request",
                    "data_sources": ["memory_index"],
                }
            )

        run_match = re.search(
            r"\b(?:run|execute)\s*:\s*(.+)",
            goal_text,
            flags=re.DOTALL | re.IGNORECASE,
        )
        if run_match:
            command_text = run_match.group(1).strip()
            command_tokens: list[str]
            try:
                command_tokens = shlex.split(command_text)
            except ValueError:
                command_tokens = []
            if command_tokens:
                actions.append(
                    {
                        "action_id": "local-shell-1",
                        "tool_name": "shell.exec",
                        "arguments": {
                            "command": command_tokens,
                        },
                        "reasoning": "Run explicit command requested by user via sandbox runtime",
                        "data_sources": ["user_signal"],
                    }
                )

        if any(token in goal_lower for token in anomaly_triggers):
            actions.append(
                {
                    "action_id": "local-anomaly-1",
                    "tool_name": "report_anomaly",
                    "arguments": {
                        "anomaly_type": "runtime_alert",
                        "description": "User signaled suspicious behavior requiring review.",
                        "recommended_action": "quarantine",
                        "confidence": 0.9,
                    },
                    "reasoning": "Local deterministic safety trigger for anomaly reporting",
                    "data_sources": ["user_signal"],
                }
            )

        tool_calls: list[dict[str, Any]] = []
        for action in actions:
            tool_name = str(action.get("tool_name", "")).strip()
            if not tool_name:
                continue
            action_id = str(action.get("action_id", "")).strip() or (
                f"local-call-{len(tool_calls) + 1}"
            )
            arguments = action.get("arguments", {})
            if not isinstance(arguments, dict):
                arguments = {}
            tool_calls.append(
                {
                    "id": action_id,
                    "type": "function",
                    "function": {
                        "name": tool_name,
                        "arguments": json.dumps(arguments, sort_keys=True),
                    },
                }
            )
        return ProviderResponse(
            message=Message(
                role="assistant",
                content=f"Safe summary: {goal_text[:300]}",
                tool_calls=tool_calls,
            ),
            model="local-fallback",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async def embeddings(
        self,
        input_texts: list[str],
        *,
        model_id: str | None = None,
    ) -> EmbeddingResponse:
        _ = model_id
        vectors: list[list[float]] = []
        for text in input_texts:
            digest = hashlib.sha256(text.encode("utf-8")).digest()
            vectors.append([digest[i] / 255.0 for i in range(12)])
        return EmbeddingResponse(vectors=vectors, model="local-stub", usage={"total_tokens": 0})
