#!/usr/bin/env python3
"""Provider conformance harness for tool-calling behavior."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter
from typing import Any

from shisad.core.events import EventBus
from shisad.core.planner import ActionProposal, Planner
from shisad.core.providers.base import Message, ModelProvider, OpenAICompatibleProvider
from shisad.core.providers.capabilities import ProviderCapabilities
from shisad.core.tools.names import canonical_tool_name
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, tool_definitions_to_openai
from shisad.core.types import ToolName
from shisad.daemon.services import _build_tool_registry
from shisad.security.pep import PEP
from shisad.security.policy import PolicyBundle


@dataclass(frozen=True, slots=True)
class ConformanceCase:
    case_id: str
    prompt: str
    available_tools: list[str]
    expected_behavior: str
    expected_tools: list[str]
    send_tools_payload: bool
    expect_content_extraction: bool
    allow_extra_tools: bool = False


@dataclass(slots=True)
class CaseResult:
    case_id: str
    passed: bool
    expected_behavior: str
    observed_behavior: str
    expected_tools: list[str]
    observed_tools: list[str]
    native_actions: int
    content_actions: int
    latency_ms: int
    finish_reason: str
    assistant_excerpt: str
    errors: list[str]


@dataclass(slots=True)
class ReportSummary:
    total: int
    passed: int
    failed: int
    pass_rate: float


class _NoopProvider(ModelProvider):
    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> Any:
        _ = (messages, tools)
        raise RuntimeError("_NoopProvider.complete should never be called")

    async def embeddings(
        self,
        input_texts: list[str],
        *,
        model_id: str | None = None,
    ) -> Any:
        _ = (input_texts, model_id)
        raise RuntimeError("_NoopProvider.embeddings should never be called")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="OpenAI-compatible endpoint base URL")
    parser.add_argument("--model-id", required=True, help="Model ID to probe")
    parser.add_argument(
        "--api-key-env",
        required=True,
        help="Environment variable name containing API key",
    )
    parser.add_argument(
        "--cases",
        default="tests/fixtures/conformance_cases.json",
        help="Path to conformance case fixture JSON",
    )
    parser.add_argument(
        "--output",
        default="artifacts/conformance-report.json",
        help="Path to JSON output report",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=45.0,
        help="Per-request provider timeout",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="Extra request header in KEY=VALUE form (repeatable)",
    )
    parser.add_argument(
        "--allow-http-localhost",
        action="store_true",
        help="Allow http://localhost endpoints",
    )
    parser.add_argument(
        "--allow-failures",
        action="store_true",
        help="Always exit 0 even when case assertions fail",
    )
    return parser.parse_args()


def _load_cases(path: Path) -> list[ConformanceCase]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Conformance fixture must be a JSON object")
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError("Conformance fixture missing 'cases' array")
    cases: list[ConformanceCase] = []
    for index, item in enumerate(raw_cases, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Case #{index} must be a JSON object")

        case_id_raw = item.get("id")
        prompt_raw = item.get("prompt")
        behavior_raw = item.get("expected_behavior")
        available_tools_raw = item.get("available_tools")
        expected_tools_raw = item.get("expected_tools", [])
        send_tools_payload_raw = item.get("send_tools_payload", True)
        expect_content_extraction_raw = item.get("expect_content_extraction", False)
        allow_extra_tools_raw = item.get("allow_extra_tools", False)

        if not isinstance(case_id_raw, str) or not case_id_raw.strip():
            raise ValueError(f"Case #{index} has invalid 'id'")
        if not isinstance(prompt_raw, str) or not prompt_raw.strip():
            raise ValueError(f"Case #{index} has invalid 'prompt'")
        if behavior_raw not in {"tool_call", "conversational", "either"}:
            raise ValueError(f"Case #{index} has invalid 'expected_behavior': {behavior_raw!r}")
        if not isinstance(available_tools_raw, list) or not all(
            isinstance(tool_name, str) for tool_name in available_tools_raw
        ):
            raise ValueError(f"Case #{index} has invalid 'available_tools' list")
        if not isinstance(expected_tools_raw, list) or not all(
            isinstance(tool_name, str) for tool_name in expected_tools_raw
        ):
            raise ValueError(f"Case #{index} has invalid 'expected_tools' list")
        if not isinstance(send_tools_payload_raw, bool):
            raise ValueError(f"Case #{index} has invalid 'send_tools_payload' flag")
        if not isinstance(expect_content_extraction_raw, bool):
            raise ValueError(f"Case #{index} has invalid 'expect_content_extraction' flag")
        if not isinstance(allow_extra_tools_raw, bool):
            raise ValueError(f"Case #{index} has invalid 'allow_extra_tools' flag")

        available_tools: list[str] = []
        for tool_name in available_tools_raw:
            canonical = canonical_tool_name(tool_name)
            if not canonical:
                raise ValueError(f"Case #{index} has unknown/invalid available tool '{tool_name}'")
            available_tools.append(canonical)
        expected_tools: list[str] = []
        for tool_name in expected_tools_raw:
            canonical = canonical_tool_name(tool_name)
            if not canonical:
                raise ValueError(f"Case #{index} has unknown/invalid expected tool '{tool_name}'")
            expected_tools.append(canonical)
        expected_not_available = sorted(set(expected_tools) - set(available_tools))
        if expected_not_available:
            raise ValueError(
                f"Case #{index} expected_tools not in available_tools: "
                f"{','.join(expected_not_available)}"
            )

        case_id = case_id_raw.strip()
        prompt = prompt_raw.strip()
        expected_behavior = str(behavior_raw)
        cases.append(
            ConformanceCase(
                case_id=case_id,
                prompt=prompt,
                available_tools=sorted(set(available_tools)),
                expected_behavior=expected_behavior,
                expected_tools=sorted(set(expected_tools)),
                send_tools_payload=send_tools_payload_raw,
                expect_content_extraction=expect_content_extraction_raw,
                allow_extra_tools=allow_extra_tools_raw,
            )
        )
    if not cases:
        raise ValueError("No valid conformance cases loaded")
    return cases


def _parse_extra_headers(raw_headers: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in raw_headers:
        key, sep, value = item.partition("=")
        key = key.strip()
        value = value.strip()
        if sep != "=" or not key:
            raise ValueError(f"Invalid --header value '{item}'; expected KEY=VALUE")
        headers[key] = value
    return headers


def _provider_headers(api_key: str, extra_headers: dict[str, str]) -> dict[str, str]:
    headers = dict(extra_headers)
    headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _build_available_tool_payloads(
    *,
    tool_names: list[str],
    tool_index: dict[str, ToolDefinition],
) -> list[dict[str, Any]]:
    tools: list[ToolDefinition] = []
    for tool_name in tool_names:
        definition = tool_index.get(tool_name)
        if definition is not None:
            tools.append(definition)
    return tool_definitions_to_openai(tools)


def _coerce_assistant_excerpt(content: str, *, max_chars: int = 220) -> str:
    flattened = " ".join(content.strip().split())
    if len(flattened) <= max_chars:
        return flattened
    return f"{flattened[:max_chars]}..."


def _validate_action_schema(
    *,
    actions: list[ActionProposal],
    planner_label: str,
    tool_registry: ToolRegistry,
    case_allowed_tools: set[str],
) -> list[str]:
    errors: list[str] = []
    for action in actions:
        tool_name = str(action.tool_name)
        if tool_name not in case_allowed_tools:
            errors.append(f"{planner_label}:tool_not_in_case_allowlist:{tool_name}")
        schema_errors = tool_registry.validate_call(ToolName(tool_name), action.arguments)
        for message in schema_errors:
            errors.append(f"{planner_label}:schema:{tool_name}:{message}")
    return errors


def _case_expectation_passed(
    *,
    case: ConformanceCase,
    observed_behavior: str,
    observed_tools: set[str],
    content_actions: list[ActionProposal],
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if case.expected_behavior == "tool_call" and observed_behavior != "tool_call":
        errors.append(f"expected_tool_call:observed_{observed_behavior}")
    if case.expected_behavior == "conversational" and observed_behavior != "conversational":
        errors.append(f"expected_conversational:observed_{observed_behavior}")
    if case.expected_behavior == "either" and observed_behavior not in {
        "tool_call",
        "conversational",
    }:
        errors.append(f"expected_either:observed_{observed_behavior}")

    if case.expected_tools:
        missing_tools = sorted(set(case.expected_tools) - observed_tools)
        if missing_tools:
            errors.append(f"missing_expected_tools:{','.join(missing_tools)}")
        if not case.allow_extra_tools:
            extra_tools = sorted(observed_tools - set(case.expected_tools))
            if extra_tools:
                errors.append(f"unexpected_tools:{','.join(extra_tools)}")

    if case.expect_content_extraction and not content_actions:
        errors.append("expected_content_extraction")

    return (len(errors) == 0, errors)


async def _run_case(
    *,
    case: ConformanceCase,
    provider: OpenAICompatibleProvider,
    tool_registry: ToolRegistry,
    native_planner: Planner,
    content_planner: Planner,
    tool_index: dict[str, ToolDefinition],
) -> CaseResult:
    tools_payload = _build_available_tool_payloads(
        tool_names=case.available_tools,
        tool_index=tool_index,
    )
    provider_tools = tools_payload if case.send_tools_payload else None
    start = perf_counter()
    response = await provider.complete(
        [Message(role="user", content=case.prompt)],
        tools=provider_tools,
    )
    latency_ms = int((perf_counter() - start) * 1000)

    raw_native_count = sum(
        1
        for call in response.message.tool_calls
        if isinstance(call, dict) and str(call.get("type", "")).strip().lower() == "function"
    )
    # NOTE(M3.R1.1): private-API coupling is intentional for this dev harness.
    # Promote extraction helpers to a stable public interface if harness becomes CI-gated.
    native_actions = native_planner._extract_tool_calls(response.message.tool_calls)
    content_actions = content_planner._extract_content_tool_calls(
        response.message.content,
        tools_payload=tools_payload,
    )

    errors: list[str] = []
    if raw_native_count > 0 and len(native_actions) < raw_native_count:
        errors.append(
            f"native_tool_calls_dropped:parsed={len(native_actions)} raw={raw_native_count}"
        )

    case_allowed_tools = set(case.available_tools)
    errors.extend(
        _validate_action_schema(
            actions=native_actions,
            planner_label="native",
            tool_registry=tool_registry,
            case_allowed_tools=case_allowed_tools,
        )
    )
    errors.extend(
        _validate_action_schema(
            actions=content_actions,
            planner_label="content",
            tool_registry=tool_registry,
            case_allowed_tools=case_allowed_tools,
        )
    )

    observed_tools = sorted(
        {str(action.tool_name) for action in [*native_actions, *content_actions]}
    )
    has_tool_actions = bool(observed_tools)
    assistant_text = response.message.content.strip()
    if has_tool_actions:
        observed_behavior = "tool_call"
    elif assistant_text:
        observed_behavior = "conversational"
    else:
        observed_behavior = "empty"
        errors.append("empty_assistant_response")

    expectation_passed, expectation_errors = _case_expectation_passed(
        case=case,
        observed_behavior=observed_behavior,
        observed_tools=set(observed_tools),
        content_actions=content_actions,
    )
    errors.extend(expectation_errors)
    passed = expectation_passed and not errors

    return CaseResult(
        case_id=case.case_id,
        passed=passed,
        expected_behavior=case.expected_behavior,
        observed_behavior=observed_behavior,
        expected_tools=case.expected_tools,
        observed_tools=observed_tools,
        native_actions=len(native_actions),
        content_actions=len(content_actions),
        latency_ms=latency_ms,
        finish_reason=response.finish_reason,
        assistant_excerpt=_coerce_assistant_excerpt(assistant_text),
        errors=errors,
    )


async def _run_harness(args: argparse.Namespace) -> int:
    api_key = str(os.environ.get(args.api_key_env, "")).strip()
    if not api_key:
        print(f"ERROR: missing API key in env var {args.api_key_env}", file=sys.stderr)
        return 2

    cases = _load_cases(Path(args.cases))
    extra_headers = _parse_extra_headers(list(args.header))
    headers = _provider_headers(api_key, extra_headers)
    provider = OpenAICompatibleProvider(
        base_url=str(args.base_url),
        model_id=str(args.model_id),
        headers=headers,
        timeout_seconds=float(args.timeout_seconds),
        allow_http_localhost=bool(args.allow_http_localhost),
    )

    tool_registry, _alarm_tool = _build_tool_registry(EventBus())
    tool_index = {str(tool.name): tool for tool in tool_registry.list_tools()}
    noop_provider = _NoopProvider()
    pep = PEP(policy=PolicyBundle(), tool_registry=tool_registry)
    native_planner = Planner(
        provider=noop_provider,
        pep=pep,
        capabilities=ProviderCapabilities(
            supports_tool_calls=True,
            supports_content_tool_calls=False,
        ),
        tool_registry=tool_registry,
    )
    content_planner = Planner(
        provider=noop_provider,
        pep=pep,
        capabilities=ProviderCapabilities(
            supports_tool_calls=False,
            supports_content_tool_calls=True,
        ),
        tool_registry=tool_registry,
    )

    results: list[CaseResult] = []
    for case in cases:
        try:
            result = await _run_case(
                case=case,
                provider=provider,
                tool_registry=tool_registry,
                native_planner=native_planner,
                content_planner=content_planner,
                tool_index=tool_index,
            )
        except Exception as exc:
            result = CaseResult(
                case_id=case.case_id,
                passed=False,
                expected_behavior=case.expected_behavior,
                observed_behavior="error",
                expected_tools=case.expected_tools,
                observed_tools=[],
                native_actions=0,
                content_actions=0,
                latency_ms=0,
                finish_reason="error",
                assistant_excerpt="",
                errors=[f"provider_error:{type(exc).__name__}:{exc}"],
            )
        results.append(result)
        status = "PASS" if result.passed else "FAIL"
        print(
            f"[{status}] {result.case_id} "
            f"observed={result.observed_behavior} "
            f"native={result.native_actions} content={result.content_actions}"
        )
        if result.errors:
            print(f"  errors: {', '.join(result.errors)}")

    passed = sum(1 for item in results if item.passed)
    failed = len(results) - passed
    summary = ReportSummary(
        total=len(results),
        passed=passed,
        failed=failed,
        pass_rate=(passed / len(results)) if results else 0.0,
    )
    print(
        "Summary: "
        f"total={summary.total} passed={summary.passed} failed={summary.failed} "
        f"pass_rate={summary.pass_rate:.2%}"
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report_payload = {
        "target": {
            "base_url": str(args.base_url),
            "model_id": str(args.model_id),
            "api_key_env": str(args.api_key_env),
        },
        "summary": asdict(summary),
        "results": [asdict(item) for item in results],
    }
    output_path.write_text(json.dumps(report_payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote report: {output_path}")

    if failed and not bool(args.allow_failures):
        return 1
    return 0


def main() -> int:
    args = _parse_args()
    return asyncio.run(_run_harness(args))


if __name__ == "__main__":
    raise SystemExit(main())
