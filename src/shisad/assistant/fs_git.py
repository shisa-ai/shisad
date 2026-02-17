"""Filesystem and git read-first helper surface."""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shisad.assistant.boundary_helpers import _is_within


@dataclass(slots=True)
class FsGitToolkit:
    """Restricted filesystem/git helper with allowlisted roots."""

    roots: list[Path]
    max_read_bytes: int

    def list_dir(self, *, path: str, recursive: bool = False, limit: int = 200) -> dict[str, Any]:
        resolved = self._resolve_path(path)
        if isinstance(resolved, dict):
            return resolved
        if not resolved.exists():
            return self._error("path_not_found", path=str(resolved))
        if not resolved.is_dir():
            return self._error("not_a_directory", path=str(resolved))

        rows: list[dict[str, Any]] = []
        max_items = max(1, min(limit, 1000))
        iterator = resolved.rglob("*") if recursive else resolved.iterdir()
        for candidate in iterator:
            try:
                stat = candidate.stat()
            except OSError:
                continue
            rows.append(
                {
                    "path": str(candidate),
                    "type": "dir" if candidate.is_dir() else "file",
                    "size": stat.st_size,
                }
            )
            if len(rows) >= max_items:
                break
        return {
            "ok": True,
            "path": str(resolved),
            "entries": rows,
            "count": len(rows),
            "error": "",
        }

    def read_file(self, *, path: str, max_bytes: int | None = None) -> dict[str, Any]:
        resolved = self._resolve_path(path)
        if isinstance(resolved, dict):
            return resolved
        if not resolved.exists():
            return self._error("path_not_found", path=str(resolved))
        if not resolved.is_file():
            return self._error("not_a_file", path=str(resolved))

        byte_limit = self.max_read_bytes if max_bytes is None else int(max_bytes)
        byte_limit = max(1024, min(byte_limit, 2 * 1024 * 1024))
        try:
            payload = resolved.read_bytes()
        except OSError:
            return self._error("read_failed", path=str(resolved))
        truncated = False
        if len(payload) > byte_limit:
            payload = payload[:byte_limit]
            truncated = True
        text = payload.decode("utf-8", errors="replace")
        return {
            "ok": True,
            "path": str(resolved),
            "content": text,
            "truncated": truncated,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "error": "",
        }

    def write_file(self, *, path: str, content: str, confirm: bool) -> dict[str, Any]:
        resolved = self._resolve_path(path)
        if isinstance(resolved, dict):
            return resolved
        if not confirm:
            return {
                "ok": False,
                "path": str(resolved),
                "written": False,
                "confirmation_required": True,
                "bytes_written": 0,
                "error": "explicit_confirmation_required",
            }
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            payload = content.encode("utf-8")
            resolved.write_bytes(payload)
        except OSError:
            return {
                "ok": False,
                "path": str(resolved),
                "written": False,
                "confirmation_required": False,
                "bytes_written": 0,
                "error": "write_failed",
            }
        return {
            "ok": True,
            "path": str(resolved),
            "written": True,
            "confirmation_required": False,
            "bytes_written": len(payload),
            "error": "",
        }

    def git_status(self, *, repo_path: str) -> dict[str, Any]:
        return self._run_git(repo_path=repo_path, args=["status", "--short", "--branch"])

    def git_diff(self, *, repo_path: str, ref: str = "", max_lines: int = 400) -> dict[str, Any]:
        args = ["diff"]
        normalized_ref = ref.strip()
        if normalized_ref:
            if normalized_ref.startswith("-"):
                return self._error("invalid_ref", path=repo_path)
            args.append(normalized_ref)
        result = self._run_git(repo_path=repo_path, args=args)
        if not result.get("ok"):
            return result
        output = str(result.get("output", ""))
        lines = output.splitlines()
        truncated = False
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            truncated = True
        result["output"] = "\n".join(lines)
        result["truncated"] = truncated
        return result

    def git_log(self, *, repo_path: str, limit: int = 20) -> dict[str, Any]:
        safe_limit = max(1, min(limit, 100))
        return self._run_git(repo_path=repo_path, args=["log", "--oneline", f"-n{safe_limit}"])

    def _run_git(self, *, repo_path: str, args: list[str]) -> dict[str, Any]:
        resolved = self._resolve_path(repo_path)
        if isinstance(resolved, dict):
            return resolved
        if not resolved.exists() or not resolved.is_dir():
            return self._error("repo_not_found", path=str(resolved))
        if not (resolved / ".git").exists():
            return self._error("not_a_git_repo", path=str(resolved))
        command = ["git", "-C", str(resolved), *args]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
        except (OSError, ValueError):
            return self._error("git_execution_failed", path=str(resolved))
        if completed.returncode != 0:
            return {
                "ok": False,
                "repo_path": str(resolved),
                "output": completed.stdout,
                "error": completed.stderr.strip() or f"git_exit_{completed.returncode}",
            }
        return {
            "ok": True,
            "repo_path": str(resolved),
            "output": completed.stdout,
            "error": "",
        }

    def _resolve_path(self, value: str) -> Path | dict[str, Any]:
        if not self.roots:
            return self._error("fs_roots_unconfigured", path=value)
        roots = [root.expanduser().resolve() for root in self.roots]
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = roots[0] / candidate
        resolved = candidate.resolve()
        if not any(_is_within(resolved, root) for root in roots):
            return self._error("path_not_allowlisted", path=str(resolved))
        return resolved

    @staticmethod
    def _error(reason: str, *, path: str) -> dict[str, Any]:
        return {
            "ok": False,
            "path": path,
            "entries": [],
            "count": 0,
            "content": "",
            "truncated": False,
            "sha256": "",
            "written": False,
            "confirmation_required": False,
            "bytes_written": 0,
            "repo_path": path,
            "output": "",
            "error": reason,
        }
