"""Typed environment policies for child-process boundaries."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class ChildEnvironmentProfile(StrEnum):
    """Operation families with distinct child-environment requirements."""

    SIDECAR = "sidecar"
    ISOLATION_CONTROL = "isolation_control"
    SIGNATURE = "signature"
    SSH_FORWARD = "ssh_forward"
    MSGVAULT = "msgvault"
    MCP_STDIO = "mcp_stdio"
    CODING_AGENT = "coding_agent"
    GIT = "git"


@dataclass(frozen=True, slots=True)
class _EnvironmentPolicy:
    exact: frozenset[str]
    prefixes: tuple[str, ...] = ()


_PORTABLE_PROCESS_KEYS = frozenset(
    {
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "WINDIR",
    }
)
_USER_CONTEXT_KEYS = frozenset(
    {
        "APPDATA",
        "HOME",
        "LOCALAPPDATA",
        "LOGNAME",
        "USER",
        "USERPROFILE",
    }
)
_SHELL_CONTEXT_KEYS = frozenset({"COMSPEC", "SHELL"})
_TERMINAL_KEYS = frozenset({"COLORTERM", "TERM"})
_TLS_KEYS = frozenset(
    {
        "CURL_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
    }
)
_PROXY_KEYS = frozenset(
    {
        "ALL_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "all_proxy",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)
_MODEL_PROVIDER_AUTH_KEYS = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "SHISA_API_KEY",
    }
)

_POLICIES: dict[ChildEnvironmentProfile, _EnvironmentPolicy] = {
    ChildEnvironmentProfile.SIDECAR: _EnvironmentPolicy(
        exact=(
            _PORTABLE_PROCESS_KEYS
            | _TLS_KEYS
            | _PROXY_KEYS
            | _MODEL_PROVIDER_AUTH_KEYS
            | {"SHISAD_LOG_LEVEL"}
        ),
        prefixes=("LC_", "SHISAD_MODEL_"),
    ),
    ChildEnvironmentProfile.ISOLATION_CONTROL: _EnvironmentPolicy(
        exact=_PORTABLE_PROCESS_KEYS,
        prefixes=("LC_",),
    ),
    ChildEnvironmentProfile.SIGNATURE: _EnvironmentPolicy(
        exact=_PORTABLE_PROCESS_KEYS,
        prefixes=("LC_",),
    ),
    ChildEnvironmentProfile.SSH_FORWARD: _EnvironmentPolicy(
        exact=(
            _PORTABLE_PROCESS_KEYS
            | _USER_CONTEXT_KEYS
            | _TERMINAL_KEYS
            | {"SSH_AGENT_PID", "SSH_AUTH_SOCK"}
        ),
        prefixes=("LC_",),
    ),
    ChildEnvironmentProfile.MSGVAULT: _EnvironmentPolicy(
        exact=_PORTABLE_PROCESS_KEYS | _USER_CONTEXT_KEYS,
        prefixes=("LC_",),
    ),
    ChildEnvironmentProfile.MCP_STDIO: _EnvironmentPolicy(
        exact=(
            _PORTABLE_PROCESS_KEYS
            | _USER_CONTEXT_KEYS
            | _SHELL_CONTEXT_KEYS
            | _TERMINAL_KEYS
            | _TLS_KEYS
            | {"PWD", "VIRTUAL_ENV"}
        ),
        prefixes=("LC_", "XDG_"),
    ),
    ChildEnvironmentProfile.CODING_AGENT: _EnvironmentPolicy(
        exact=(
            _PORTABLE_PROCESS_KEYS
            | _USER_CONTEXT_KEYS
            | _SHELL_CONTEXT_KEYS
            | _TERMINAL_KEYS
            | _TLS_KEYS
            | _PROXY_KEYS
            | {
                "CLOUD_ML_REGION",
                "GOOGLE_APPLICATION_CREDENTIALS",
                "NPM_CONFIG_USERCONFIG",
                "NPM_TOKEN",
                "VIRTUAL_ENV",
            }
        ),
        prefixes=(
            "ANTHROPIC_",
            "AWS_",
            "AZURE_",
            "CLAUDE_CODE_",
            "GEMINI_",
            "GOOGLE_",
            "LC_",
            "OPENAI_",
            "OPENROUTER_",
            "XDG_",
        ),
    ),
    ChildEnvironmentProfile.GIT: _EnvironmentPolicy(
        exact=_PORTABLE_PROCESS_KEYS,
        prefixes=("LC_",),
    ),
}

_GIT_SAFE_FILTER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_GIT_FILTER_CONFIG_SUFFIXES = ("clean", "smudge", "process", "required")
_GIT_CONFIG_LOCATION_KEYS = frozenset(
    {
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "PROGRAMDATA",
        "USERPROFILE",
        "XDG_CONFIG_HOME",
    }
)


class GitSafetyError(RuntimeError):
    """Git repository state could not be inspected without executing helpers."""


class GitSafetyTimeoutError(GitSafetyError):
    """Git repository safety inspection exceeded its bounded runtime."""


class RequiredGitFilterError(GitSafetyError):
    """A selected filter explicitly requires executable conversion."""

    def __init__(self, drivers: Iterable[str]) -> None:
        normalized = tuple(sorted(set(drivers)))
        self.drivers = normalized
        rendered = ", ".join(f"'{driver}'" for driver in normalized)
        super().__init__(
            f"required executable Git filter {rendered} blocks safe checkout; "
            "disable the filter or use a separately audited checkout"
        )


@dataclass(frozen=True, slots=True)
class GitFilterInspection:
    """Selected repository filters and those that require execution."""

    active_drivers: tuple[str, ...] = ()
    required_executable_drivers: tuple[str, ...] = ()


def _git_fixed_environment() -> dict[str, str]:
    return {
        "GCM_INTERACTIVE": "never",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "PAGER": "cat",
    }


def hardened_git_command(
    args: Sequence[str],
    *,
    filter_drivers: Iterable[str] = (),
) -> list[str]:
    """Build Git argv that disables repository-selected executable helpers."""

    config = [
        f"core.hooksPath={os.devnull}",
        "core.fsmonitor=false",
        "core.askPass=",
        f"core.attributesFile={os.devnull}",
        "core.pager=cat",
        "diff.external=",
        "gc.auto=0",
        "maintenance.auto=false",
        "log.showSignature=false",
        "gpg.program=",
        "gpg.openpgp.program=",
        "gpg.ssh.program=",
        "gpg.x509.program=",
    ]
    for driver in sorted(set(filter_drivers)):
        if not _GIT_SAFE_FILTER_NAME_RE.fullmatch(driver):
            raise GitSafetyError("repository selects an unsupported Git filter driver name")
        config.extend(
            [
                f"filter.{driver}.clean=",
                f"filter.{driver}.smudge=",
                f"filter.{driver}.process=",
                f"filter.{driver}.required=false",
            ]
        )
    command = ["git"]
    for value in config:
        command.extend(("-c", value))
    command.extend(args)
    return command


def _git_error_detail(stderr: bytes) -> str:
    first_line = stderr.decode("utf-8", errors="replace").strip().splitlines()
    return first_line[0][:300] if first_line else "unknown Git error"


def _run_git_inspection(
    args: Sequence[str],
    *,
    input_bytes: bytes | None = None,
    timeout_seconds: float,
    allowed_returncodes: frozenset[int] = frozenset({0}),
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            hardened_git_command(args),
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=max(0.1, float(timeout_seconds)),
            env=(
                dict(environment)
                if environment is not None
                else build_child_environment(ChildEnvironmentProfile.GIT)
            ),
        )
    except subprocess.TimeoutExpired as exc:
        raise GitSafetyTimeoutError("Git helper inspection timed out") from exc
    except (OSError, ValueError) as exc:
        raise GitSafetyError("Git helper inspection could not start") from exc
    if completed.returncode not in allowed_returncodes:
        raise GitSafetyError(f"Git helper inspection failed: {_git_error_detail(completed.stderr)}")
    return completed


def _git_config_inspection_environment() -> dict[str, str]:
    """Allow read-only discovery of normal config locations, never config injection."""

    source = os.environ
    child = build_child_environment(ChildEnvironmentProfile.GIT, parent=source)
    for key in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_SYSTEM"):
        child.pop(key, None)
    for raw_key, value in source.items():
        key = _normalized_key(raw_key)
        if key in _GIT_CONFIG_LOCATION_KEYS and value and not _is_function_export(key, value):
            child[key] = value
    return child


def _parse_filter_config(payload: bytes) -> dict[str, dict[str, bytes]]:
    config: dict[str, dict[str, bytes]] = {}
    for record in payload.split(b"\0"):
        if not record:
            continue
        key_bytes, separator, value = record.partition(b"\n")
        if not separator:
            raise GitSafetyError("Git filter configuration returned malformed output")
        key = key_bytes.decode("utf-8", errors="surrogateescape")
        lowered = key.casefold()
        if not lowered.startswith("filter."):
            continue
        matched_suffix = next(
            (suffix for suffix in _GIT_FILTER_CONFIG_SUFFIXES if lowered.endswith(f".{suffix}")),
            "",
        )
        if not matched_suffix:
            continue
        driver = key[len("filter.") : -len(f".{matched_suffix}")]
        if not driver:
            continue
        config.setdefault(driver, {})[matched_suffix] = value.strip()
    return config


def inspect_git_filters(
    repo_path: Path,
    *,
    cached: bool = False,
    timeout_seconds: float = 10.0,
) -> GitFilterInspection:
    """Inspect selected filters without checking out files or invoking drivers."""

    repo_args = ["-C", str(repo_path)]
    files = _run_git_inspection(
        [*repo_args, "ls-files", "-z"],
        timeout_seconds=timeout_seconds,
    ).stdout
    if not files:
        return GitFilterInspection()

    cached_arg = ["--cached"] if cached else []
    attributes = _run_git_inspection(
        [*repo_args, "check-attr", "-z", *cached_arg, "--stdin", "filter"],
        input_bytes=files,
        timeout_seconds=timeout_seconds,
    ).stdout
    fields = attributes.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 3:
        raise GitSafetyError("Git attribute inspection returned malformed output")

    active: set[str] = set()
    reserved_values = {b"set", b"unset", b"unspecified"}
    for index in range(0, len(fields), 3):
        attribute = fields[index + 1]
        raw_driver = fields[index + 2]
        if attribute != b"filter" or not raw_driver or raw_driver in reserved_values:
            continue
        driver = raw_driver.decode("utf-8", errors="surrogateescape")
        if not _GIT_SAFE_FILTER_NAME_RE.fullmatch(driver):
            raise GitSafetyError("repository selects an unsupported Git filter driver name")
        active.add(driver)

    if not active:
        return GitFilterInspection()

    config_payload = _run_git_inspection(
        [*repo_args, "config", "--includes", "-z", "--get-regexp", r"^filter\."],
        timeout_seconds=timeout_seconds,
        allowed_returncodes=frozenset({0, 1}),
        environment=_git_config_inspection_environment(),
    ).stdout
    filter_config = _parse_filter_config(config_payload)

    required_executable: set[str] = set()
    false_values = {b"", b"0", b"false", b"no", b"off"}
    for driver in active:
        driver_config = filter_config.get(driver, {})
        executable = any(driver_config.get(key, b"") for key in ("clean", "smudge", "process"))
        required = driver_config.get("required", b"").lower() not in false_values
        if executable and required:
            required_executable.add(driver)
    return GitFilterInspection(
        active_drivers=tuple(sorted(active)),
        required_executable_drivers=tuple(sorted(required_executable)),
    )


def _normalized_key(key: str) -> str:
    return key.upper() if os.name == "nt" else key


def _is_function_export(key: str, value: str) -> bool:
    return key.startswith("BASH_FUNC_") or value.lstrip().startswith("()")


def build_child_environment(
    profile: ChildEnvironmentProfile,
    *,
    parent: Mapping[str, str] | None = None,
    overrides: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build a bounded child environment for one operation family.

    MCP stdio servers may receive explicit per-server overrides. Ambient
    runtime-injection controls remain excluded from every profile.
    """

    policy = _POLICIES[profile]
    source = os.environ if parent is None else parent
    child: dict[str, str] = {}
    for raw_key, value in source.items():
        key = _normalized_key(raw_key)
        if not value or _is_function_export(key, value):
            continue
        if key in policy.exact or any(key.startswith(prefix) for prefix in policy.prefixes):
            child[key] = value

    child.setdefault("PATH", os.defpath)

    if profile is ChildEnvironmentProfile.GIT:
        child.update(_git_fixed_environment())

    if overrides:
        if profile is not ChildEnvironmentProfile.MCP_STDIO:
            raise ValueError("explicit child-environment overrides are limited to MCP stdio")
        for raw_key, value in overrides.items():
            key = _normalized_key(raw_key)
            if not key or _is_function_export(key, value):
                continue
            child[key] = value
    return child


__all__ = [
    "ChildEnvironmentProfile",
    "GitFilterInspection",
    "GitSafetyError",
    "GitSafetyTimeoutError",
    "RequiredGitFilterError",
    "build_child_environment",
    "hardened_git_command",
    "inspect_git_filters",
]
