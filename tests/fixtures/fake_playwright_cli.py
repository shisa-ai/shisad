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
from collections.abc import Mapping
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
    b"\x00\x00\x00\x0cIDATx\x9cc`\x00\x00\x00\x02\x00\x01\xe2!\xbc3"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)
_BUTTON_NON_SUBMIT_TYPES = {"button", "reset"}
_FORM_METHODS = {"get", "post", "dialog"}
_IMPLICIT_ENTER_SUBMIT_INPUT_TYPES = {
    "date",
    "datetime-local",
    "email",
    "month",
    "number",
    "password",
    "search",
    "tel",
    "text",
    "time",
    "url",
    "week",
}
_FILLABLE_FIELD_CONTROL_TYPES = _IMPLICIT_ENTER_SUBMIT_INPUT_TYPES | {""}
_INPUT_TYPES = {
    "button",
    "checkbox",
    "color",
    "date",
    "datetime-local",
    "email",
    "file",
    "hidden",
    "image",
    "month",
    "number",
    "password",
    "radio",
    "range",
    "reset",
    "search",
    "submit",
    "tel",
    "text",
    "time",
    "url",
    "week",
}
_HTML_VOID_TAGS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}


def _normalize_button_type(value: str) -> str:
    normalized = value.strip().lower()
    return normalized if normalized in _BUTTON_NON_SUBMIT_TYPES else "submit"


def _normalize_input_type(value: str) -> str:
    normalized = value.strip().lower()
    return normalized if normalized in _INPUT_TYPES else "text"


def _normalize_form_method(value: str) -> str:
    normalized = value.strip().lower()
    return normalized if normalized in _FORM_METHODS else "get"


def _is_native_disabled_attrs(attrs: Mapping[str, str]) -> bool:
    return "disabled" in attrs


def _is_action_disabled_attrs(
    attrs: Mapping[str, str],
    *,
    inherited_native_disabled: bool = False,
) -> bool:
    return (
        inherited_native_disabled
        or _is_native_disabled_attrs(attrs)
        or attrs.get("aria-disabled", "").strip().lower() == "true"
    )


def _style_declarations(value: str) -> dict[str, str]:
    declarations: dict[str, tuple[int, int, str]] = {}
    for index, item in enumerate(value.split(";")):
        name, separator, raw = item.partition(":")
        if not separator:
            continue
        raw_value = raw.strip().lower()
        important = raw_value.endswith("!important")
        normalized = raw_value.removesuffix("!important").strip()
        priority = 1 if important else 0
        key = name.strip().lower()
        current = declarations.get(key)
        if current is None or (priority, index) >= (current[0], current[1]):
            declarations[key] = (priority, index, normalized)
    return {name: item[2] for name, item in declarations.items()}


def _attrs_hide_descendants(attrs: Mapping[str, str]) -> bool:
    if "hidden" in attrs:
        return True
    style = _style_declarations(attrs.get("style", ""))
    return (
        style.get("display") == "none"
        or style.get("opacity") == "0"
    )


def _attrs_visibility_state(attrs: Mapping[str, str]) -> str:
    style = _style_declarations(attrs.get("style", ""))
    value = style.get("visibility", "")
    return value if value in {"hidden", "visible"} else ""


def _attrs_hide_candidate(
    attrs: Mapping[str, str],
    *,
    tag: str,
    control_type: str = "",
    inherited_hidden: bool = False,
) -> bool:
    if inherited_hidden or _attrs_hide_descendants(attrs):
        return True
    if attrs.get("aria-hidden", "").strip().lower() == "true":
        return True
    style = _style_declarations(attrs.get("style", ""))
    if style.get("opacity") == "0":
        return True
    return tag == "input" and control_type == "hidden"


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.visible_parts: list[str] = []
        self._tag_stack: list[str] = []
        self._hidden_stack: list[bool] = []
        self._visibility_hidden_stack: list[bool] = []
        self._fieldset_stack: list[dict[str, bool | int]] = []
        self._current_form: dict[str, str] | None = None
        self._forms: list[dict[str, str]] = []
        self._current_element: dict[str, str] | None = None
        self._elements: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key: (value or "") for key, value in attrs}
        inherited_native_disabled = self._in_disabled_fieldset()
        inherited_hidden = self._in_hidden_context()
        inherited_visibility_hidden = self._in_visibility_hidden_context()
        visibility_state = _attrs_visibility_state(attr_map)
        visibility_hidden = (
            visibility_state == "hidden"
            or (inherited_visibility_hidden and visibility_state != "visible")
        )
        parent_tag = self._tag_stack[-1] if self._tag_stack else ""
        if tag == "legend" and parent_tag == "fieldset" and self._fieldset_stack:
            fieldset = self._fieldset_stack[-1]
            if not bool(fieldset.get("first_legend_seen", False)):
                fieldset["first_legend_seen"] = True
                fieldset["first_legend_depth"] = len(self._tag_stack) + 1
                fieldset["first_legend_active"] = True
        if tag not in _HTML_VOID_TAGS:
            self._tag_stack.append(tag)
            self._hidden_stack.append(inherited_hidden or _attrs_hide_descendants(attr_map))
            self._visibility_hidden_stack.append(visibility_hidden)
        if tag == "fieldset":
            self._fieldset_stack.append(
                {
                    "disabled": _is_native_disabled_attrs(attr_map),
                    "first_legend_seen": False,
                    "first_legend_depth": 0,
                    "first_legend_active": False,
                }
            )
            return
        if tag == "form":
            self._current_form = {
                "action": attr_map.get("action", ""),
                "method": _normalize_form_method(attr_map.get("method", "")),
                "id": attr_map.get("id", ""),
                "_key": attr_map.get("id", "") or f"__form_{len(self._forms) + 1}",
            }
            self._forms.append(self._current_form)
            return
        if tag == "a":
            self._current_element = {
                "kind": "link",
                "href": attr_map.get("href", ""),
                "id": attr_map.get("id", ""),
                "selector": _selector_for(tag="a", attrs=attr_map),
                "hidden": "1" if _attrs_hide_candidate(
                    attr_map,
                    tag=tag,
                    inherited_hidden=inherited_hidden,
                ) or visibility_hidden else "",
                "label": "",
            }
            return
        if tag == "button":
            form = self._form_for_attrs(attr_map)
            native_disabled = _is_native_disabled_attrs(attr_map) or inherited_native_disabled
            control_type = _normalize_button_type(attr_map.get("type", ""))
            form_action, form_method = self._form_metadata_for(
                attr_map,
                form=form,
                is_submitter=control_type == "submit",
            )
            self._current_element = {
                "kind": "button",
                "type": attr_map.get("type", "submit"),
                "control_type": control_type,
                "id": attr_map.get("id", ""),
                "_form_id": form.get("_key", "") if form else "",
                "disabled": "1" if _is_action_disabled_attrs(
                    attr_map,
                    inherited_native_disabled=native_disabled,
                ) else "",
                "hidden": "1" if _attrs_hide_candidate(
                    attr_map,
                    tag=tag,
                    control_type=control_type,
                    inherited_hidden=inherited_hidden,
                ) or visibility_hidden else "",
                "selector": _selector_for(tag="button", attrs=attr_map),
                "label": "",
                "form_action": form_action,
                "form_method": form_method,
            }
            self._record_default_submitter(
                form,
                attr_map,
                is_submitter=control_type == "submit",
                native_disabled=native_disabled,
            )
            return
        if tag in {"input", "textarea"}:
            form = self._form_for_attrs(attr_map)
            native_disabled = _is_native_disabled_attrs(attr_map) or inherited_native_disabled
            control_type = _normalize_input_type(attr_map.get("type", "")) if tag == "input" else ""
            is_submitter = tag == "input" and control_type in {"submit", "image"}
            form_action, form_method = self._form_metadata_for(
                attr_map,
                form=form,
                is_submitter=is_submitter,
            )
            self._elements.append(
                {
                    "kind": "field",
                    "type": attr_map.get("type", "text"),
                    "control_type": control_type,
                    "name": attr_map.get("name", ""),
                    "id": attr_map.get("id", ""),
                    "_form_id": form.get("_key", "") if form else "",
                    "disabled": "1" if _is_action_disabled_attrs(
                        attr_map,
                        inherited_native_disabled=native_disabled,
                    ) else "",
                    "hidden": "1" if _attrs_hide_candidate(
                        attr_map,
                        tag=tag,
                        control_type=control_type,
                        inherited_hidden=inherited_hidden,
                    ) or visibility_hidden else "",
                    "selector": _selector_for(tag=tag, attrs=attr_map),
                    "label": attr_map.get("name", "") or attr_map.get("id", "") or tag,
                    "form_action": form_action,
                    "form_method": form_method,
                }
            )
            self._record_default_submitter(
                form,
                attr_map,
                is_submitter=is_submitter,
                native_disabled=native_disabled,
            )

    def handle_endtag(self, tag: str) -> None:
        closing_index = self._open_tag_index(tag)
        closing_depth = closing_index + 1 if closing_index is not None else len(self._tag_stack)
        if tag == "legend":
            for fieldset in reversed(self._fieldset_stack):
                if bool(fieldset.get("first_legend_active", False)) and int(
                    fieldset.get("first_legend_depth", 0) or 0
                ) == closing_depth:
                    fieldset["first_legend_active"] = False
                    break
        if tag == "fieldset" and self._fieldset_stack:
            self._fieldset_stack.pop()
        if tag == "form":
            self._current_form = None
        if self._current_element is not None and tag in {"a", "button"}:
            self._elements.append(dict(self._current_element))
            self._current_element = None
        self._close_tag_stack(tag)

    def _in_disabled_fieldset(self) -> bool:
        for fieldset in self._fieldset_stack:
            if not bool(fieldset.get("disabled", False)):
                continue
            if bool(fieldset.get("first_legend_active", False)):
                continue
            return True
        return False

    def _in_hidden_context(self) -> bool:
        return any(self._hidden_stack)

    def _in_visibility_hidden_context(self) -> bool:
        return any(self._visibility_hidden_stack)

    def _open_tag_index(self, tag: str) -> int | None:
        for index in range(len(self._tag_stack) - 1, -1, -1):
            if self._tag_stack[index] == tag:
                return index
        return None

    def _close_tag_stack(self, tag: str) -> None:
        index = self._open_tag_index(tag)
        if index is None:
            return
        self._tag_stack = self._tag_stack[:index]
        self._hidden_stack = self._hidden_stack[:index]
        self._visibility_hidden_stack = self._visibility_hidden_stack[:index]

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if not text:
            return
        current_tag = self._tag_stack[-1] if self._tag_stack else ""
        if current_tag == "title":
            self.title = f"{self.title} {text}".strip()
        hidden_context = self._in_hidden_context()
        visibility_hidden = self._in_visibility_hidden_context()
        if (
            current_tag not in {"script", "style"}
            and not hidden_context
            and not visibility_hidden
        ):
            self.visible_parts.append(text)
        if (
            self._current_element is not None
            and current_tag not in {"script", "style"}
            and not hidden_context
            and not visibility_hidden
        ):
            self._current_element["label"] = (
                f"{self._current_element.get('label', '')} {text}".strip()
            )

    @property
    def visible_text(self) -> str:
        return " ".join(self.visible_parts).strip()

    @property
    def elements(self) -> list[dict[str, str]]:
        rendered: list[dict[str, str]] = []
        for item in self._elements:
            copy = dict(item)
            if _is_disabled_element(copy) or _is_hidden_element(copy):
                continue
            form = self._form_by_id(copy.get("_form_id", ""))
            if (
                form
                and copy.get("kind") == "field"
                and copy.get("control_type", "") not in {"submit", "image"}
            ):
                if form.get("default_action") is not None:
                    copy["form_action"] = form.get("default_action", "")
                    copy["form_method"] = form.get("default_method", "get")
                elif self._can_implicitly_submit_from_field(copy, form=form):
                    copy["form_action"] = form.get("action", "")
                    copy["form_method"] = form.get("method", "get")
            copy.pop("_form_id", None)
            copy["ref"] = f"e{len(rendered) + 1}"
            rendered.append(copy)
        return rendered

    def _form_for_attrs(self, attrs: dict[str, str]) -> dict[str, str] | None:
        form_id = attrs.get("form", "")
        if form_id:
            return self._form_by_id(form_id)
        return self._current_form

    def _form_by_id(self, form_id: str) -> dict[str, str] | None:
        if not form_id:
            return None
        for form in self._forms:
            if form.get("id") == form_id or form.get("_key") == form_id:
                return form
        return None

    def _can_implicitly_submit_from_field(
        self,
        element: Mapping[str, str],
        *,
        form: dict[str, str],
    ) -> bool:
        if not _is_implicit_enter_submit_field(element):
            return False
        if form.get("default_submitter_seen") == "1":
            return False
        form_id = form.get("_key", "")
        blocking_fields = [
            item
            for item in self._elements
            if item.get("_form_id", "") == form_id and _is_implicit_enter_submit_field(item)
        ]
        return len(blocking_fields) <= 1

    @staticmethod
    def _form_metadata_for(
        attrs: dict[str, str],
        *,
        form: dict[str, str] | None,
        is_submitter: bool,
    ) -> tuple[str, str]:
        if not form or not is_submitter:
            return "", ""
        action = (
            attrs.get("formaction", "")
            if is_submitter and "formaction" in attrs
            else form.get("action", "")
        )
        method = (
            attrs.get("formmethod", "")
            if is_submitter and "formmethod" in attrs
            else form.get("method", "get")
        )
        return action, _normalize_form_method(method)

    def _record_default_submitter(
        self,
        form: dict[str, str] | None,
        attrs: dict[str, str],
        *,
        is_submitter: bool,
        native_disabled: bool = False,
    ) -> None:
        if not form or not is_submitter or form.get("default_submitter_seen") == "1":
            return
        form["default_submitter_seen"] = "1"
        if native_disabled or _is_native_disabled_attrs(attrs):
            form["default_submitter_disabled"] = "1"
            return
        action, method = self._form_metadata_for(attrs, form=form, is_submitter=True)
        form["default_action"] = action
        form["default_method"] = method


def _is_disabled_element(element: Mapping[str, str]) -> bool:
    return str(element.get("disabled", "")).strip().lower() in {"1", "true"}


def _is_hidden_element(element: Mapping[str, str]) -> bool:
    return str(element.get("hidden", "")).strip().lower() in {"1", "true"}


def _is_implicit_enter_submit_field(element: Mapping[str, str]) -> bool:
    return (
        element.get("kind", "").strip().lower() == "field"
        and element.get("control_type", "").strip().lower()
        in _IMPLICIT_ENTER_SUBMIT_INPUT_TYPES
    )


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
    if parsed.hostname == "example.com":
        return (
            "<html><head><title>External Example</title></head>"
            "<body>Example external browser page</body></html>",
            url,
        )
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
        if element.get("control_type"):
            attributes.append(f'control_type="{element.get("control_type", "")}"')
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
    store_field: bool,
    click_target: str,
) -> int:
    _require_opened(state)
    original_fields = dict(state.get("fields", {}))
    if not store_field:
        state["fields"] = {}
        _save_state(cwd, session, state)
    parser, final_url = _parse_page(str(state.get("current_url", "")))
    element = _resolve_target(parser, target)
    if element is None:
        raise SystemExit(f"unknown target: {target}")
    if not _is_fillable_target(element):
        raise SystemExit(f"target is not fillable: {target}")
    fields = dict(state.get("fields", {}) if store_field else original_fields)
    field_name = element.get("name") or element.get("id") or element.get("selector") or target
    submission_fields = {**fields, field_name: text}
    if store_field:
        fields[field_name] = text
    else:
        fields.pop(target, None)
        fields.pop(field_name, None)
    state["fields"] = fields
    next_url = final_url or str(state.get("current_url", ""))
    if submit or click_target:
        target_element = element
        if click_target:
            target_element = _resolve_target(parser, click_target) or {}
            if not target_element:
                raise SystemExit(f"unknown target: {click_target}")
        if click_target and target_element.get("kind") == "link" and target_element.get("href"):
            next_url = urljoin(next_url, target_element["href"])
        elif (
            (submit and _is_enter_submit_control(target_element))
            or (bool(click_target) and _is_click_submit_control(target_element))
        ):
            action = target_element.get("form_action", "") or next_url
            method = _normalize_form_method(target_element.get("form_method", "get"))
            if method == "get" and submission_fields:
                encoded = urlencode(submission_fields)
                separator = "&" if "?" in action else "?"
                next_url = urljoin(next_url, action)
                next_url = f"{next_url}{separator}{encoded}"
            else:
                next_url = urljoin(next_url, action)
    state["current_url"] = next_url
    _save_state(cwd, session, state)
    return 0


def _is_enter_submit_control(element: Mapping[str, object]) -> bool:
    form_method = str(element.get("form_method", "")).strip()
    if not form_method or _normalize_form_method(form_method) == "dialog":
        return False
    kind = str(element.get("kind", "")).strip().lower()
    control_type = str(element.get("control_type", "")).strip().lower()
    return kind == "field" and control_type in _IMPLICIT_ENTER_SUBMIT_INPUT_TYPES


def _is_fillable_target(element: Mapping[str, object]) -> bool:
    kind = str(element.get("kind", "")).strip().lower()
    control_type = str(element.get("control_type", "")).strip().lower()
    return kind == "field" and control_type in _FILLABLE_FIELD_CONTROL_TYPES


def _is_click_submit_control(element: Mapping[str, object]) -> bool:
    form_method = str(element.get("form_method", "")).strip()
    if not form_method or _normalize_form_method(form_method) == "dialog":
        return False
    kind = str(element.get("kind", "")).strip().lower()
    control_type = str(element.get("control_type", "")).strip().lower()
    if kind == "button":
        return _normalize_button_type(control_type) == "submit"
    if kind == "field":
        return control_type in {"submit", "image"}
    return False


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
    elif _is_click_submit_control(element):
        action = element.get("form_action", "") or next_url
        method = _normalize_form_method(element.get("form_method", "get"))
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


def _parse_fill_args(args: list[str]) -> tuple[str, str, bool, bool, str]:
    if len(args) < 2:
        raise SystemExit("fill requires target and text")
    target = args.pop(0)
    text = args.pop(0)
    submit = False
    store_field = True
    click_target = ""
    index = 0
    while index < len(args):
        option = args[index]
        if option == "--submit":
            submit = True
        elif option == "--click":
            click_target = args[index + 1] if index + 1 < len(args) else ""
            if not click_target:
                raise SystemExit("fill --click requires target")
            index += 1
        elif option == "--no-store":
            store_field = False
        else:
            raise SystemExit(f"unsupported fill option: {option}")
        index += 1
    if submit and click_target:
        raise SystemExit("fill accepts --submit or --click, not both")
    return target, text, submit, store_field, click_target


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
        target, text, submit, store_field, click_target = _parse_fill_args(args)
        return _handle_fill(
            state,
            cwd=cwd,
            session=session,
            target=target,
            text=text,
            submit=submit,
            store_field=store_field,
            click_target=click_target,
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
