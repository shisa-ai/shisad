"""Focused config-file contracts used by the O1 environment router."""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.core.config_file import (
    UnsupportedConfigSchemaError,
    load_config_file,
    selected_config_path,
)


def test_o1_unsupported_schema_error_is_typed(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("schema_version = 2\n", encoding="utf-8")

    with pytest.raises(UnsupportedConfigSchemaError) as exc:
        load_config_file(config_path, environ={})

    assert exc.value.actual_version == 2
    assert exc.value.supported_version == 1
    assert str(exc.value) == "unsupported schema_version: 2"


def test_o1_selected_config_path_preserves_canonical_precedence(tmp_path: Path) -> None:
    root_path = tmp_path / "root.toml"
    env_path = tmp_path / "env.toml"
    xdg_home = tmp_path / "xdg"

    assert (
        selected_config_path(
            root_path,
            environ={"SHISAD_CONFIG_PATH": str(env_path), "XDG_CONFIG_HOME": str(xdg_home)},
        )
        == root_path
    )
    assert (
        selected_config_path(
            None,
            environ={"SHISAD_CONFIG_PATH": str(env_path), "XDG_CONFIG_HOME": str(xdg_home)},
        )
        == env_path
    )
    assert selected_config_path(None, environ={"XDG_CONFIG_HOME": str(xdg_home)}) == (
        xdg_home / "shisad" / "config.toml"
    )
