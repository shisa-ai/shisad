#!/usr/bin/env python3
"""Deterministic Playwright-CLI stand-in used by browser tool tests.

This fixture implements a tiny subset of the `@playwright/cli` command surface
that shisad uses. It is intentionally small and synchronous: enough to exercise
the wrapper/runtime contract without requiring a real browser install.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
    b"\x00\x00\x00\x0cIDATx\x9cc`\x00\x00\x00\x02\x00\x01\xe2!\xbc3"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.visible_parts: list[str] = []
        self._tag_stack: list[str] = []
        self._current_form: dict[str, str] | None = None
        self._forms: list[dict[str, str]] = []
        self._current_element: dict[str, str] | None = None
        self._elements: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key: (value or "") for key, value in attrs}
        self._tag_stack.append(tag)
        if tag == "form":
            self._current_form = {
                "action": attr_map.get("action", ""),
                "method": attr_map.get("method", "get").lower(),
                "id": attr_map.get("id", ""),
            }
            self._forms.append(dict(self._current_form))
            return
        if tag == "a":
            self._current_element = {
                "kind": "link",
                "href": attr_map.get("href", ""),
                "id": attr_map.get("id", ""),
                "selector": _selector_for(tag="a", attrs=attr_map),
                "label": "",
            }
            return
        if tag == "button":
            self._current_element = {
                "kind": "button",
                "type": attr_map.get("type", "submit"),
                "id": attr_map.get("id", ""),
                "selector": _selector_for(tag="button", attrs=attr_map),
                "label": "",
                "form_action": (self._current_form or {}).get("action", ""),
                "form_method": (self._current_form or {}).get("method", "get"),
            }
            return
        if tag in {"input", "textarea"}:
            self._elements.append(
                {
                    "kind": "field",
                    "type": attr_map.get("type", "text"),
                    "name": attr_map.get("name", ""),
                    "id": attr_map.get("id", ""),
                    "selector": _selector_for(tag=tag, attrs=attr_map),
                    "label": attr_map.get("name", "") or attr_map.get("id", "") or tag,
                    "form_action": (self._current_form or {}).get("action", ""),
                    "form_method": (self._current_form or {}).get("method", "get"),
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None
        if self._current_element is not None and tag in {"a", "button"}:
            self._elements.append(dict(self._current_element))
            self._current_element = None
        if self._tag_stack and self._tag_stack[-1] == tag:
            self._tag_stack.pop()
        else:
            with_context = list(self._tag_stack)
            if tag in with_context:
                with_context.reverse()
                index = len(self._tag_stack) - with_context.index(tag) - 1
                self._tag_stack = self._tag_stack[:index]

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if not text:
            return
        current_tag = self._tag_stack[-1] if self._tag_stack else ""
        if current_tag == "title":
            self.title = f"{self.title} {text}".strip()
        if current_tag not in {"script", "style"}:
            self.visible_parts.append(text)
        if self._current_element is not None:
            self._current_element["label"] = (
                f"{self._current_element.get('label', '')} {text}".strip()
            )

    @property
    def visible_text(self) -> str:
        return " ".join(self.visible_parts).strip()

    @property
    def elements(self) -> list[dict[str, str]]:
        rendered: list[dict[str, str]] = []
        for index, item in enumerate(self._elements, start=1):
            copy = dict(item)
            copy["ref"] = f"e{index}"
            rendered.append(copy)
        return rendered


def _selector_for(*, tag: str, attrs: dict[str, str]) -> str:
    if attrs.get("id"):
        return f"#{attrs['id']}"
    if attrs.get("name"):
        return f'[name="{attrs["name"]}"]'
    return tag


def _storage_root(cwd: Path) -> Path:
    root = cwd / ".fake-playwright"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _state_path(cwd: Path, session: str) -> Path:
    return _storage_root(cwd) / f"{session or 'default'}.json"


def _load_state(cwd: Path, session: str) -> dict[str, object]:
    path = _state_path(cwd, session)
    if not path.exists():
        return {"current_url": "", "fields": {}, "opened": False}
    return json.loads(path.read_text(encoding="utf-8"))


def _save_state(cwd: Path, session: str, state: dict[str, object]) -> None:
    _state_path(cwd, session).write_text(json.dumps(state, indent=2), encoding="utf-8")


def _require_opened(state: dict[str, object]) -> None:
    if not bool(state.get("opened")):
        raise SystemExit("browser session is not open")


def _fetch_page(url: str) -> tuple[str, str]:
    if not url:
        return "", ""
    parsed = urlparse(url)
    if parsed.scheme in {"", "about"}:
        return "", ""
    request = urllib.request.Request(url, headers={"User-Agent": "fake-playwright-cli"})
    with urllib.request.urlopen(request, timeout=10.0) as response:
        raw = response.read()
    return raw.decode("utf-8", errors="replace"), url


def _parse_page(url: str) -> tuple[_PageParser, str]:
    html, final_url = _fetch_page(url)
    parser = _PageParser()
    parser.feed(html)
    parser.close()
    return parser, final_url


def _resolve_target(parser: _PageParser, target: str) -> dict[str, str] | None:
    for element in parser.elements:
        if target in {
            element.get("ref", ""),
            element.get("selector", ""),
            f"#{element.get('id', '')}" if element.get("id") else "",
            element.get("name", ""),
        }:
            return element
    return None


def _write_text_output(path: str | None, text: str) -> None:
    if path:
        Path(path).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def _handle_open(state: dict[str, object], cwd: Path, session: str, url: str) -> int:
    state["opened"] = True
    state["current_url"] = url or ""
    _save_state(cwd, session, state)
    return 0


def _handle_goto(state: dict[str, object], cwd: Path, session: str, url: str) -> int:
    _require_opened(state)
    state["current_url"] = url
    _save_state(cwd, session, state)
    return 0


def _handle_eval(
    state: dict[str, object],
    *,
    cwd: Path,
    session: str,
    filename: str | None,
) -> int:
    _require_opened(state)
    parser, final_url = _parse_page(str(state.get("current_url", "")))
    payload = json.dumps(
        {
            "url": final_url or str(state.get("current_url", "")),
            "title": parser.title,
            "visible_text": parser.visible_text,
        },
        ensure_ascii=True,
    )
    state["current_url"] = final_url or str(state.get("current_url", ""))
    _save_state(cwd, session, state)
    _write_text_output(filename, payload)
    return 0


def _handle_snapshot(
    state: dict[str, object],
    *,
    cwd: Path,
    session: str,
    filename: str | None,
) -> int:
    _require_opened(state)
    parser, final_url = _parse_page(str(state.get("current_url", "")))
    lines = [
        f"URL: {final_url or state.get('current_url', '')}",
        f"Title: {parser.title}",
        "Text:",
        parser.visible_text,
        "Elements:",
    ]
    for element in parser.elements:
        attributes = [f'selector="{element.get("selector", "")}"']
        if element.get("href"):
            attributes.append(f'href="{element.get("href", "")}"')
        if element.get("form_action"):
            attributes.append(f'form_action="{element.get("form_action", "")}"')
        if element.get("form_method"):
            attributes.append(f'form_method="{element.get("form_method", "")}"')
        lines.append(
            f'[{element["ref"]}] {element["kind"]} "{element.get("label", "").strip()}" '
            + " ".join(attributes)
        )
    output = "\n".join(lines).strip() + "\n"
    state["current_url"] = final_url or str(state.get("current_url", ""))
    _save_state(cwd, session, state)
    _write_text_output(filename, output)
    return 0


def _handle_fill(
    state: dict[str, object],
    *,
    cwd: Path,
    session: str,
    target: str,
    text: str,
    submit: bool,
) -> int:
    _require_opened(state)
    parser, final_url = _parse_page(str(state.get("current_url", "")))
    element = _resolve_target(parser, target)
    if element is None:
        raise SystemExit(f"unknown target: {target}")
    fields = dict(state.get("fields", {}))
    field_name = element.get("name") or element.get("id") or element.get("selector") or target
    fields[field_name] = text
    state["fields"] = fields
    next_url = final_url or str(state.get("current_url", ""))
    if submit:
        action = element.get("form_action", "") or next_url
        method = element.get("form_method", "get").lower()
        if method == "get" and fields:
            encoded = urlencode(fields)
            separator = "&" if "?" in action else "?"
            next_url = urljoin(next_url, action)
            next_url = f"{next_url}{separator}{encoded}"
        else:
            next_url = urljoin(next_url, action)
    state["current_url"] = next_url
    _save_state(cwd, session, state)
    return 0


def _handle_click(
    state: dict[str, object],
    *,
    cwd: Path,
    session: str,
    target: str,
) -> int:
    _require_opened(state)
    parser, final_url = _parse_page(str(state.get("current_url", "")))
    element = _resolve_target(parser, target)
    if element is None:
        raise SystemExit(f"unknown target: {target}")
    next_url = final_url or str(state.get("current_url", ""))
    if element.get("kind") == "link" and element.get("href"):
        next_url = urljoin(next_url, element["href"])
    elif element.get("kind") == "button":
        action = element.get("form_action", "") or next_url
        method = element.get("form_method", "get").lower()
        fields = dict(state.get("fields", {}))
        if method == "get" and fields:
            encoded = urlencode(fields)
            separator = "&" if "?" in action else "?"
            next_url = urljoin(next_url, action)
            next_url = f"{next_url}{separator}{encoded}"
        else:
            next_url = urljoin(next_url, action)
    state["current_url"] = next_url
    _save_state(cwd, session, state)
    return 0


def _handle_screenshot(filename: str | None) -> int:
    if not filename:
        raise SystemExit("screenshot requires --filename")
    Path(filename).write_bytes(_PNG_BYTES)
    return 0


def _handle_list(cwd: Path) -> int:
    root = _storage_root(cwd)
    sessions = sorted(path.stem for path in root.glob("*.json"))
    output = "\n".join(sessions)
    if output:
        output += "\n"
    sys.stdout.write(output)
    return 0


def _handle_close(cwd: Path, session: str) -> int:
    path = _state_path(cwd, session)
    if path.exists():
        path.unlink()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    session = ""
    if args and args[0].startswith("-s="):
        session = args.pop(0).split("=", 1)[1]
    if not args:
        raise SystemExit("command required")

    command = args.pop(0)
    cwd = Path.cwd()
    state = _load_state(cwd, session)

    if command == "open":
        url = args[0] if args else ""
        return _handle_open(state, cwd, session, url)
    if command == "goto":
        if not args:
            raise SystemExit("goto requires url")
        return _handle_goto(state, cwd, session, args[0])
    if command == "eval":
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("func")
        parser.add_argument("element", nargs="?")
        parser.add_argument("--filename")
        parsed = parser.parse_args(args)
        _ = parsed.func, parsed.element
        return _handle_eval(state, cwd=cwd, session=session, filename=parsed.filename)
    if command == "snapshot":
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("element", nargs="?")
        parser.add_argument("--filename")
        parsed = parser.parse_args(args)
        _ = parsed.element
        return _handle_snapshot(state, cwd=cwd, session=session, filename=parsed.filename)
    if command == "fill":
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("target")
        parser.add_argument("text")
        parser.add_argument("--submit", action="store_true")
        parsed = parser.parse_args(args)
        return _handle_fill(
            state,
            cwd=cwd,
            session=session,
            target=parsed.target,
            text=parsed.text,
            submit=bool(parsed.submit),
        )
    if command == "click":
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("target")
        parser.add_argument("button", nargs="?")
        parsed = parser.parse_args(args)
        _ = parsed.button
        return _handle_click(state, cwd=cwd, session=session, target=parsed.target)
    if command == "screenshot":
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("target", nargs="?")
        parser.add_argument("--filename")
        parsed = parser.parse_args(args)
        _ = parsed.target
        return _handle_screenshot(parsed.filename)
    if command == "list":
        return _handle_list(cwd)
    if command == "close":
        return _handle_close(cwd, session)
    raise SystemExit(f"unsupported fake playwright command: {command}")


if __name__ == "__main__":
    raise SystemExit(main())
