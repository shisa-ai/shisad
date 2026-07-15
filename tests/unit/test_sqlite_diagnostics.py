"""SQLite runtime diagnostic coverage."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from typing import Any

from click.testing import CliRunner

from shisad.cli import main as cli_main
from shisad.core.config import DaemonConfig
from shisad.daemon.handlers._impl import HandlerImplementation
from shisad.daemon.handlers._impl_admin import _DOCTOR_COMPONENTS
from shisad.memory import sqlite_diagnostics


class _Rows(list[tuple[str]]):
    def fetchall(self) -> list[tuple[str]]:
        return list(self)


class _FakeConnection:
    def __init__(self, *, fts5_available: bool, compile_options: Iterable[str]) -> None:
        self._fts5_available = fts5_available
        self._compile_options = tuple(compile_options)

    def __enter__(self) -> _FakeConnection:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def execute(self, sql: str, *_args: object, **_kwargs: object) -> _Rows:
        normalized = " ".join(sql.lower().split())
        if normalized == "pragma compile_options":
            return _Rows((option,) for option in self._compile_options)
        if "using fts5" in normalized:
            if not self._fts5_available:
                raise sqlite3.OperationalError("no such module: fts5")
            return _Rows([])
        raise AssertionError(f"unexpected SQL in sqlite diagnostic test: {sql}")


def test_gh83_sqlite_runtime_status_reports_fts5_available() -> None:
    status = sqlite_diagnostics.sqlite_runtime_status(
        connect=lambda _path: _FakeConnection(
            fts5_available=True,
            compile_options=("ENABLE_FTS5", "THREADSAFE=1"),
        )
    )

    assert status["status"] == "ok"
    assert status["problems"] == []
    assert status["sqlite"]["fts5"]["available"] is True
    assert status["sqlite"]["fts5"]["compile_option_reported"] is True
    assert status["sqlite"]["fts5"]["probe_error"] == ""


def test_gh83_sqlite_runtime_status_reports_missing_fts5_as_degraded() -> None:
    status = sqlite_diagnostics.sqlite_runtime_status(
        connect=lambda _path: _FakeConnection(
            fts5_available=False,
            compile_options=("THREADSAFE=1",),
        )
    )

    assert status["status"] == "degraded"
    assert status["problems"] == ["sqlite_fts5_unavailable"]
    assert status["sqlite"]["fts5"]["available"] is False
    assert status["sqlite"]["fts5"]["compile_option_reported"] is False
    assert status["sqlite"]["fts5"]["probe_error"] == ("OperationalError: no such module: fts5")
    assert status["hint"]


def test_gh83_doctor_storage_component_surfaces_sqlite_runtime_status(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "shisad.daemon.handlers._impl.sqlite_runtime_status",
        lambda: {
            "status": "degraded",
            "problems": ["sqlite_fts5_unavailable"],
            "sqlite": {"fts5": {"available": False}},
        },
    )
    impl = object.__new__(HandlerImplementation)

    assert "storage" in _DOCTOR_COMPONENTS
    assert impl._doctor_storage_status()["status"] == "degraded"


def test_gh83_doctor_check_storage_component_prints_sqlite_diagnostics(
    tmp_path,
    monkeypatch,
) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    calls: list[tuple[str, dict[str, Any] | None]] = []
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)

    def _fake_rpc_call(
        _config: DaemonConfig,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        calls.append((method, params))
        payload = {
            "status": "degraded",
            "component": "storage",
            "checks": {
                "storage": {
                    "status": "degraded",
                    "problems": ["sqlite_fts5_unavailable"],
                    "sqlite": {"fts5": {"available": False}},
                }
            },
            "error": "",
        }
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["doctor", "check", "--component", "storage"])

    assert result.exit_code == 0
    assert calls == [("doctor.check", {"component": "storage"})]
    assert "sqlite_fts5_unavailable" in result.output


def test_gh83_doctor_check_help_lists_storage_component() -> None:
    result = CliRunner().invoke(cli_main.cli, ["doctor", "check", "--help"])

    assert result.exit_code == 0
    assert "storage" in result.output


def test_f3_doctor_check_help_lists_approvals_component() -> None:
    result = CliRunner().invoke(cli_main.cli, ["doctor", "check", "--help"])

    assert result.exit_code == 0
    assert "approvals" in result.output


def test_f3_doctor_check_help_lists_skills_component() -> None:
    result = CliRunner().invoke(cli_main.cli, ["doctor", "check", "--help"])

    assert result.exit_code == 0
    assert "skills" in result.output
