"""F5 no-source-checkout wheel and container acceptance journeys."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import zipfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_PACKAGING = os.environ.get("SHISAD_RUN_PACKAGING_TESTS") == "1"
RUN_CONTAINER = os.environ.get("SHISAD_RUN_CONTAINER_TESTS") == "1"
MATRIX_ROOM = "!f5-room:test"
MATRIX_USER = "@f5-user:test"
RESPONSE_MARKERS = {
    "hello": "F5_HELLO_OK",
    "time.now": "F5_TIME_OK",
    "reminder.create": "F5_REMINDER_OK",
    "fs.write": "F5_APPROVAL_OK",
    "matrix": "F5_MATRIX_OK",
}

pytestmark = pytest.mark.skipif(
    not RUN_PACKAGING,
    reason="set SHISAD_RUN_PACKAGING_TESTS=1 for clean-artifact acceptance",
)


def _clean_env(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    blocked_prefixes = (
        "SHISAD_",
        "SHISA_",
        "OPENAI_",
        "OPENROUTER_",
        "GEMINI_",
        "ANTHROPIC_",
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT"}
        and not key.startswith(blocked_prefixes)
    }
    env["UV_NO_CONFIG"] = "1"
    if overrides:
        env.update(overrides)
    return env


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    timeout: float = 180.0,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(command),
        cwd=cwd,
        env=dict(env) if env is not None else _clean_env(),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode != 0:
        pytest.fail(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("f5-wheel")
    _run(
        ["uv", "build", "--wheel", "--out-dir", str(output)],
        cwd=REPO_ROOT,
        timeout=120.0,
    )
    wheels = list(output.glob("shisad-*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def _wheel_metadata(wheel: Path) -> str:
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        return archive.read(metadata_name).decode("utf-8")


def _assert_assistant_metadata(wheel: Path) -> None:
    metadata = _wheel_metadata(wheel)
    assert metadata.count("Provides-Extra: assistant") == 1
    expected = {
        "Requires-Dist: discord-py<3,>=2.4; extra == 'assistant'",
        "Requires-Dist: matrix-nio[e2e]<0.26,>=0.25; extra == 'assistant'",
        "Requires-Dist: mcp<2,>=1.28.1; extra == 'assistant'",
        "Requires-Dist: python-telegram-bot<22,>=21.6; extra == 'assistant'",
        "Requires-Dist: slack-bolt<2,>=1.21; extra == 'assistant'",
        "Requires-Dist: slack-sdk<4,>=3.33; extra == 'assistant'",
        "Requires-Dist: textual<1,>=0.89; extra == 'assistant'",
    }
    assistant_requirements = {
        line
        for line in metadata.splitlines()
        if "extra == 'assistant'" in line or 'extra == "assistant"' in line
    }
    assert assistant_requirements == expected


def _create_venv(tmp_path: Path, wheel: Path, *, extra: str = "") -> tuple[Path, Path]:
    venv = tmp_path / (extra or "base")
    _run(["uv", "venv", "--python", "3.12", str(venv)], cwd=tmp_path)
    python = venv / "bin" / "python"
    requirement = f"{wheel}[{extra}]" if extra else str(wheel)
    _run(
        ["uv", "pip", "install", "--python", str(python), requirement],
        cwd=tmp_path,
        timeout=300.0,
    )
    return python, venv / "bin" / "shisad"


@dataclass(slots=True)
class _Cli:
    prefix: list[str]
    cwd: Path
    env: Mapping[str, str] | None = None

    def run(self, *args: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
        return _run(
            [*self.prefix, *args],
            cwd=self.cwd,
            env=self.env,
            timeout=timeout,
        )


class _ArtifactServer(ThreadingHTTPServer):
    matrix_event_sent: bool
    matrix_responses: list[str]
    provider_requests: list[dict[str, Any]]
    lock: threading.Lock

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _ArtifactHandler)
        self.matrix_event_sent = False
        self.matrix_responses = []
        self.provider_requests = []
        self.lock = threading.Lock()


class _ArtifactHandler(BaseHTTPRequestHandler):
    server: _ArtifactServer

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        assert isinstance(payload, dict)
        return payload

    def _send_json(self, payload: Mapping[str, Any]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:
        if self.path.rstrip("/").endswith("/v1/chat/completions"):
            payload = self._json_body()
            with self.server.lock:
                self.server.provider_requests.append(payload)
            self._send_json(_planner_response(payload))
            return
        self._send_json({})

    def do_GET(self) -> None:
        if "/_matrix/client/" not in self.path or "/sync" not in self.path:
            self._send_json({})
            return
        with self.server.lock:
            send_event = not self.server.matrix_event_sent
            self.server.matrix_event_sent = True
        timeline: list[dict[str, Any]] = []
        if send_event:
            timeline.append(
                {
                    "type": "m.room.message",
                    "sender": MATRIX_USER,
                    "event_id": "$f5-event",
                    "origin_server_ts": 1,
                    "content": {"msgtype": "m.text", "body": "matrix package hello"},
                }
            )
        self._send_json(
            {
                "next_batch": f"f5-{int(time.monotonic() * 1000)}",
                "rooms": {
                    "join": {MATRIX_ROOM: {"timeline": {"events": timeline, "limited": False}}}
                },
            }
        )

    def do_PUT(self) -> None:
        payload = self._json_body()
        body = str(payload.get("body", ""))
        with self.server.lock:
            self.server.matrix_responses.append(body)
        self._send_json({"event_id": f"$reply-{len(self.server.matrix_responses)}"})


def _planner_response(payload: Mapping[str, Any]) -> dict[str, Any]:
    messages = payload.get("messages", [])
    assert isinstance(messages, list)
    all_text = "\n".join(
        str(message.get("content", "")) for message in messages if isinstance(message, dict)
    )
    lowered_all = all_text.lower()
    if "tools" not in payload and "post-tool synthesis pass" in lowered_all:
        for request_text, tool_name in (
            ("write package approval", "fs.write"),
            ("create package reminder", "reminder.create"),
            ("current package time", "time.now"),
        ):
            if request_text in lowered_all:
                return _openai_response(RESPONSE_MARKERS[tool_name])
        for tool_name in ("fs.write", "reminder.create", "time.now"):
            if tool_name in lowered_all:
                return _openai_response(RESPONSE_MARKERS[tool_name])
        return _openai_response("F5_TOOL_OK")

    previous_tool = ""
    for message in reversed(messages):
        if not isinstance(message, dict):
            continue
        calls = message.get("tool_calls", [])
        if isinstance(calls, list) and calls:
            function = calls[0].get("function", {}) if isinstance(calls[0], dict) else {}
            previous_tool = str(function.get("name", "")) if isinstance(function, dict) else ""
            break
    if any(isinstance(message, dict) and message.get("role") == "tool" for message in messages):
        return _respond_to_user(payload, RESPONSE_MARKERS.get(previous_tool, "F5_TOOL_OK"))

    user_text = "\n".join(
        str(message.get("content", ""))
        for message in messages
        if isinstance(message, dict) and message.get("role") == "user"
    )
    lowered = user_text.lower()
    if "matrix package hello" in lowered:
        return _respond_to_user(payload, RESPONSE_MARKERS["matrix"])
    if "write package approval" in lowered:
        match = re.search(r"WRITE_PATH=([^\s]+)", user_text)
        assert match is not None
        return _openai_response(
            "",
            tool_name="fs.write",
            arguments={"path": match.group(1), "content": "F5_APPROVED_CONTENT"},
        )
    if "create package reminder" in lowered:
        return _openai_response(
            "",
            tool_name="reminder.create",
            arguments={
                "message": "F5 package reminder",
                "when": "in 1 hour",
                "name": "f5-package",
            },
        )
    if "current package time" in lowered:
        return _openai_response("", tool_name="time.now", arguments={})
    return _respond_to_user(payload, RESPONSE_MARKERS["hello"])


def _respond_to_user(payload: Mapping[str, Any], content: str) -> dict[str, Any]:
    tools = payload.get("tools", [])
    if isinstance(tools, list) and len(tools) == 1:
        function = tools[0].get("function", {}) if isinstance(tools[0], dict) else {}
        if isinstance(function, dict) and function.get("name") == "respond_to_user":
            return _openai_response(
                "", tool_name="respond_to_user", arguments={"final_answer": content}
            )
    return _openai_response(content)


def _openai_response(
    content: str,
    *,
    tool_name: str = "",
    arguments: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant", "content": content}
    finish_reason = "stop"
    if tool_name:
        message["tool_calls"] = [
            {
                "id": f"f5-{tool_name.replace('.', '-')}",
                "type": "function",
                "function": {
                    "name": tool_name,
                    "arguments": json.dumps(dict(arguments or {}), sort_keys=True),
                },
            }
        ]
        finish_reason = "tool_calls"
    return {
        "model": "f5-controlled",
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


@contextmanager
def _artifact_server() -> Iterator[_ArtifactServer]:
    server = _ArtifactServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def _short_runtime_root(label: str) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix=f"shisad-f5-{label}-") as directory:
        yield Path(directory)


def _write_policy(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                'version: "1"',
                "default_deny: false",
                "default_require_confirmation: false",
                "default_capabilities:",
                "  - file.read",
                "  - file.write",
                "  - http.request",
                "  - email.read",
                "  - memory.read",
                "  - memory.write",
                "  - message.send",
                "  - shell.exec",
                "tools:",
                "  fs.write:",
                "    confirmation:",
                "      level: software",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _runtime_env(root: Path, server: _ArtifactServer, *, matrix: bool = False) -> dict[str, str]:
    data_dir = root / "data"
    runtime_dir = root / "run"
    workspace = root / "workspace"
    runtime_dir.mkdir(parents=True)
    workspace.mkdir(parents=True)
    policy = root / "policy.yaml"
    _write_policy(policy)
    values = {
        "SHISAD_DATA_DIR": str(data_dir),
        "SHISAD_SOCKET_PATH": str(runtime_dir / "control.sock"),
        "SHISAD_POLICY_PATH": str(policy),
        "SHISAD_ASSISTANT_FS_ROOTS": json.dumps([str(workspace)]),
        "SHISAD_MEMORY_AUTO_EXTRACTION_ENABLED": "false",
        "SHISAD_WEB_SEARCH_ENABLED": "false",
        "SHISAD_BROWSER_ENABLED": "false",
        "SHISAD_MODEL_PLANNER_PROVIDER_PRESET": "openai_default",
        "SHISAD_MODEL_PLANNER_BASE_URL": f"http://127.0.0.1:{server.server_port}/v1",
        "SHISAD_MODEL_PLANNER_MODEL_ID": "f5-controlled",
        "SHISAD_MODEL_PLANNER_API_KEY": "f5-placeholder-not-a-secret",
        "SHISAD_MODEL_PLANNER_REMOTE_ENABLED": "true",
        "SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED": "false",
        "SHISAD_MODEL_MONITOR_REMOTE_ENABLED": "false",
        "SHISAD_MODEL_ALLOW_HTTP_LOCALHOST": "true",
        "SHISAD_MODEL_BLOCK_PRIVATE_RANGES": "false",
    }
    if matrix:
        values.update(
            {
                "SHISAD_MATRIX_ENABLED": "true",
                "SHISAD_MATRIX_HOMESERVER": f"http://127.0.0.1:{server.server_port}",
                "SHISAD_MATRIX_USER_ID": "@f5-bot:test",
                "SHISAD_MATRIX_ACCESS_TOKEN": "f5-matrix-placeholder",
                "SHISAD_MATRIX_ROOM_ID": MATRIX_ROOM,
                "SHISAD_MATRIX_E2EE": "false",
                "SHISAD_MATRIX_TRUSTED_USERS": json.dumps([MATRIX_USER]),
                "SHISAD_CHANNEL_IDENTITY_ALLOWLIST": json.dumps({"matrix": [MATRIX_USER]}),
            }
        )
    return _clean_env(values)


@contextmanager
def _daemon(cli_path: Path, root: Path, env: Mapping[str, str]) -> Iterator[_Cli]:
    log_path = root / "daemon.log"
    with log_path.open("a", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            [str(cli_path), "start", "--foreground"],
            cwd=root,
            env=dict(env),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        cli = _Cli([str(cli_path)], root, env)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    pytest.fail(f"installed daemon exited early:\n{log_path.read_text()}")
                result = _run(
                    [str(cli_path), "status"],
                    cwd=root,
                    env=env,
                    timeout=5,
                    check=False,
                )
                if result.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                pytest.fail(f"installed daemon did not start:\n{log_path.read_text()}")
            yield cli
            cli.run("stop")
            process.wait(timeout=20)
            assert process.returncode == 0, log_path.read_text(encoding="utf-8")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def _exercise_core_journey(
    cli: _Cli,
    workspace_file: str,
    server: _ArtifactServer,
) -> dict[str, Any]:
    assert "Status: running" in cli.run("status").stdout
    doctor = json.loads(cli.run("doctor", "check", "--component", "all").stdout)
    sandbox = doctor["checks"]["sandbox"]
    assert sandbox["sandbox_policy"]["containment_profile"] == "supported"
    assert "expert_host_fallback_enabled" not in sandbox["problems"]

    created = cli.run("session", "create", "--user", "f5-user", "--workspace", "f5")
    match = re.search(r"Session created: (\S+)", created.stdout)
    assert match is not None
    session_id = match.group(1)
    assert (
        RESPONSE_MARKERS["hello"]
        in cli.run("session", "message", session_id, "hello from wheel").stdout
    )
    time_result = cli.run("session", "message", session_id, "current package time")
    assert RESPONSE_MARKERS["time.now"] in time_result.stdout, (
        f"{time_result.stdout}\n{(cli.cwd / 'daemon.log').read_text(encoding='utf-8')}"
    )
    reminder_result = cli.run("session", "message", session_id, "create package reminder")
    assert RESPONSE_MARKERS["reminder.create"] in reminder_result.stdout, (
        reminder_result.stdout,
        server.provider_requests[-3:],
    )
    assert "F5 package reminder" in cli.run("task", "list", "--json").stdout

    pending_reply = cli.run(
        "session",
        "message",
        session_id,
        f"write package approval to {workspace_file} WRITE_PATH={workspace_file}",
    )
    assert "shisad action confirm" in pending_reply.stdout
    pending = json.loads(cli.run("action", "list", "--session", session_id, "--json").stdout)[
        "actions"
    ]
    row = next(item for item in pending if item["tool_name"] == "fs.write")
    confirmed = json.loads(
        cli.run(
            "action",
            "confirm",
            row["confirmation_id"],
            "--nonce",
            row["decision_nonce"],
            "--json",
        ).stdout
    )
    assert confirmed["confirmed"] is True
    assert "F5_APPROVED_CONTENT" in cli.run("fs", "read", workspace_file).stdout
    return sandbox


def test_base_wheel_cli_and_missing_extra(built_wheel: Path, tmp_path: Path) -> None:
    python, cli_path = _create_venv(tmp_path, built_wheel)
    help_result = _run([str(cli_path), "--help"], cwd=tmp_path)
    assert "Security-first AI agent daemon" in help_result.stdout
    missing = _run([str(cli_path), "chat"], cwd=tmp_path, check=False)
    assert missing.returncode != 0
    assert "shisad[chat]" in (missing.stdout + missing.stderr)
    resolved = _run(
        [
            str(python),
            "-c",
            "import pathlib, shisad; print(pathlib.Path(shisad.__file__).resolve())",
        ],
        cwd=tmp_path,
    ).stdout.strip()
    assert str(REPO_ROOT) not in resolved


def test_assistant_extra_clean_wheel_journey(built_wheel: Path, tmp_path: Path) -> None:
    _assert_assistant_metadata(built_wheel)
    python, cli_path = _create_venv(tmp_path, built_wheel, extra="assistant")
    imports = "import discord,mcp,nio,slack_bolt,slack_sdk,telegram,textual,shisad; print('ok')"
    assert _run([str(python), "-c", imports], cwd=tmp_path).stdout.strip() == "ok"

    with _artifact_server() as server, _short_runtime_root("wheel") as root:
        env = _runtime_env(root, server)
        workspace_file = str(root / "workspace" / "approved.txt")
        with _daemon(cli_path, root, env) as cli:
            _exercise_core_journey(cli, workspace_file, server)
        with _daemon(cli_path, root, env) as restarted:
            assert "F5 package reminder" in restarted.run("task", "list", "--json").stdout
            assert "F5_APPROVED_CONTENT" in restarted.run("fs", "read", workspace_file).stdout


def test_assistant_extra_configured_matrix_journey(built_wheel: Path, tmp_path: Path) -> None:
    _assert_assistant_metadata(built_wheel)
    _python, cli_path = _create_venv(tmp_path, built_wheel, extra="assistant")
    with _artifact_server() as server, _short_runtime_root("matrix") as root:
        env = _runtime_env(root, server, matrix=True)
        with _daemon(cli_path, root, env):
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                with server.lock:
                    if any(RESPONSE_MARKERS["matrix"] in body for body in server.matrix_responses):
                        break
                time.sleep(0.2)
            else:
                pytest.fail(f"Matrix response not delivered: {server.matrix_responses!r}")


def _docker_prefix() -> list[str]:
    docker = shutil.which("docker")
    if docker and _run([docker, "info"], cwd=REPO_ROOT, check=False, timeout=15).returncode == 0:
        return [docker]
    sudo = shutil.which("sudo")
    if docker and sudo:
        command = [sudo, "-n", docker]
        if _run([*command, "info"], cwd=REPO_ROOT, check=False, timeout=15).returncode == 0:
            return command
    pytest.fail("Docker engine is unavailable for required F5 container evidence")


def test_official_container_clean_artifact_journey(
    built_wheel: Path,
    tmp_path: Path,
) -> None:
    if not RUN_CONTAINER:
        pytest.skip("set SHISAD_RUN_CONTAINER_TESTS=1 for the required image lane")
    _assert_assistant_metadata(built_wheel)
    assert (REPO_ROOT / "Dockerfile").is_file()
    assert (REPO_ROOT / "scripts" / "clean_artifact_smoke.py").is_file()
    docker = _docker_prefix()
    image = f"shisad-f5-test:{os.getpid()}"
    name = f"shisad-f5-{os.getpid()}"
    data_volume = f"shisad-f5-data-{os.getpid()}"
    workspace_volume = f"shisad-f5-work-{os.getpid()}"
    policy = tmp_path / "container-policy.yaml"
    _write_policy(policy)

    def docker_run(*args: str, timeout: float = 300.0) -> subprocess.CompletedProcess[str]:
        return _run([*docker, *args], cwd=REPO_ROOT, timeout=timeout)

    try:
        docker_run("build", "--tag", image, ".", timeout=900)
        image_metadata = json.loads(docker_run("image", "inspect", image).stdout)[0]
        baked_env_names = {
            value.partition("=")[0] for value in image_metadata["Config"].get("Env", [])
        }
        assert not baked_env_names.intersection(
            {
                "ANTHROPIC_API_KEY",
                "GEMINI_API_KEY",
                "OPENAI_API_KEY",
                "OPENROUTER_API_KEY",
                "SHISAD_MODEL_PLANNER_API_KEY",
            }
        )
        docker_run("volume", "create", data_volume)
        docker_run("volume", "create", workspace_volume)
        with _artifact_server() as server:
            environment = {
                "SHISAD_POLICY_PATH": "/etc/shisad/policy.yaml",
                "SHISAD_ASSISTANT_FS_ROOTS": json.dumps(["/workspace"]),
                "SHISAD_MEMORY_AUTO_EXTRACTION_ENABLED": "false",
                "SHISAD_WEB_SEARCH_ENABLED": "false",
                "SHISAD_BROWSER_ENABLED": "false",
                "SHISAD_MODEL_PLANNER_PROVIDER_PRESET": "openai_default",
                "SHISAD_MODEL_PLANNER_BASE_URL": f"http://127.0.0.1:{server.server_port}/v1",
                "SHISAD_MODEL_PLANNER_MODEL_ID": "f5-controlled",
                "SHISAD_MODEL_PLANNER_API_KEY": "f5-placeholder-not-a-secret",
                "SHISAD_MODEL_PLANNER_REMOTE_ENABLED": "true",
                "SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED": "false",
                "SHISAD_MODEL_MONITOR_REMOTE_ENABLED": "false",
                "SHISAD_MODEL_ALLOW_HTTP_LOCALHOST": "true",
                "SHISAD_MODEL_BLOCK_PRIVATE_RANGES": "false",
            }

            def start_container() -> _Cli:
                args = [
                    "run",
                    "--detach",
                    "--name",
                    name,
                    "--network",
                    "host",
                    "--volume",
                    f"{data_volume}:/var/lib/shisad",
                    "--volume",
                    f"{workspace_volume}:/workspace",
                    "--volume",
                    f"{policy}:/etc/shisad/policy.yaml:ro",
                ]
                for key, value in environment.items():
                    args.extend(["--env", f"{key}={value}"])
                docker_run(*args, image)
                cli = _Cli([*docker, "exec", name, "shisad"], REPO_ROOT)
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    status = _run([*cli.prefix, "status"], cwd=REPO_ROOT, timeout=15, check=False)
                    if status.returncode == 0:
                        return cli
                    time.sleep(0.5)
                pytest.fail(docker_run("logs", name).stdout)

            cli = start_container()
            assert docker_run("exec", name, "id", "-u").stdout.strip() == "10001"
            for directory in ("/run/shisad", "/var/lib/shisad", "/workspace"):
                ownership = docker_run(
                    "exec", name, "stat", "-c", "%a %u %g", directory
                ).stdout.strip()
                assert ownership == "700 10001 10001"

            runtime_probe = json.loads(
                docker_run(
                    "exec",
                    name,
                    "python",
                    "-c",
                    (
                        "import importlib.util,json,shutil; "
                        "print(json.dumps({'bwrap':shutil.which('bwrap'),"
                        "'capsh':shutil.which('capsh'),'pasta':shutil.which('pasta'),"
                        "'uv':shutil.which('uv'),"
                        "'pytest':importlib.util.find_spec('pytest') is not None,"
                        "'hatchling':importlib.util.find_spec('hatchling') is not None}))"
                    ),
                ).stdout
            )
            assert runtime_probe == {
                "bwrap": "/usr/local/bin/bwrap",
                "capsh": None,
                "pasta": "/usr/bin/pasta",
                "uv": None,
                "pytest": False,
                "hatchling": False,
            }
            artifact_import = docker_run(
                "exec",
                name,
                "python",
                "-c",
                (
                    "import discord,mcp,nio,slack_bolt,slack_sdk,telegram,textual,shisad; "
                    "print(shisad.__file__)"
                ),
            ).stdout.strip()
            assert artifact_import.startswith("/opt/shisad/")

            sandbox = _exercise_core_journey(cli, "/workspace/approved.txt", server)
            backends = sandbox["backends"]
            bwrap_ready = backends["nsjail"]["available"]
            for backend_name in ("container", "nsjail", "vm"):
                backend = backends[backend_name]
                assert backend["available"] is bwrap_ready
                assert backend["runtime"] == ("/usr/local/bin/bwrap" if bwrap_ready else "")
                assert backend["network_namespace_available"] is bwrap_ready
                assert backend["network_available"] is bwrap_ready
                assert backend["dns_control_available"] is bwrap_ready
            if not bwrap_ready:
                assert "default_backend_unavailable:nsjail" in sandbox["problems"]
                assert "network_backend_unavailable:container" in sandbox["problems"]
            assert sandbox["connect_path"]["available"] is False
            assert "connect_path_unavailable" in sandbox["problems"]
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                health = docker_run(
                    "inspect", "--format", "{{.State.Health.Status}}", name
                ).stdout.strip()
                if health == "healthy":
                    break
                time.sleep(0.5)
            assert health == "healthy"
            docker_run("stop", "--time", "20", name)
            logs = docker_run("logs", name).stdout
            assert "Traceback" not in logs
            assert (
                docker_run("inspect", "--format", "{{.State.ExitCode}}", name).stdout.strip() == "0"
            )
            docker_run("rm", name)

            restarted = start_container()
            assert "F5 package reminder" in restarted.run("task", "list", "--json").stdout
            assert (
                "F5_APPROVED_CONTENT"
                in restarted.run("fs", "read", "/workspace/approved.txt").stdout
            )
            docker_run("stop", "--time", "20", name)
            assert (
                docker_run("inspect", "--format", "{{.State.ExitCode}}", name).stdout.strip() == "0"
            )
            docker_run("rm", name)
            docker_run("volume", "inspect", data_volume)
            docker_run("volume", "inspect", workspace_volume)
    finally:
        _run([*docker, "rm", "--force", name], cwd=REPO_ROOT, check=False)
        _run([*docker, "volume", "rm", data_volume], cwd=REPO_ROOT, check=False)
        _run([*docker, "volume", "rm", workspace_volume], cwd=REPO_ROOT, check=False)
        _run([*docker, "image", "rm", image], cwd=REPO_ROOT, check=False)
