"""Production Playwright wrapper protocol smoke tests."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WRAPPER = _REPO_ROOT / "scripts" / "shisad-playwright-cli.mjs"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is required for wrapper tests")
def test_gh33_playwright_wrapper_supports_shisad_protocol_with_fake_playwright(
    tmp_path: Path,
) -> None:
    project = tmp_path / "app"
    project.mkdir()
    wrapper = project / "shisad-playwright-cli.mjs"
    shutil.copy2(_WRAPPER, wrapper)
    fake_module = project / "node_modules" / "@playwright" / "test"
    fake_module.mkdir(parents=True)
    (fake_module / "index.js").write_text(
        r"""
const fs = require("fs");

function submittedUrl(page) {
  const value = encodeURIComponent(page.fields["#search"] || "");
  return new URL(`/submitted?q=${value}`, page._url || "http://example.test/").toString();
}

class Locator {
  constructor(page, selector) {
    this.page = page;
    this.selector = selector;
  }
  first() {
    return this;
  }
  async fill(text) {
    if (this.selector === "#missing") {
      throw new Error("missing target");
    }
    this.page.fields[this.selector] = text;
    if (text === "old-sensitive") {
      this.page._url = new URL(
        `/replayed?value=${encodeURIComponent(text)}`,
        this.page._url || "http://example.test/",
      ).toString();
    }
    if (this.selector === "#editor") {
      editor.setEditableText(text);
    }
  }
  async inputValue() {
    if (this.selector === "#editor") {
      throw new Error("not an input");
    }
    return this.page.fields[this.selector] || "";
  }
  async evaluate(callback) {
    if (this.selector === "#editor") {
      return callback(editor);
    }
    return this.page.fields[this.selector] || "";
  }
  async press(key) {
    if (key === "Enter") {
      this.page._url = submittedUrl(this.page);
    }
  }
  async click() {
    if (this.selector === "#continue") {
      this.page._url = new URL("/next", this.page._url).toString();
      return;
    }
    if (this.selector === "#submit") {
      this.page._url = submittedUrl(this.page);
    }
    if (this.selector === "#login") {
      this.page._url = new URL(
        this.page.fields["#search"] === "sensitive-secret" ? "/logged-in" : "/missing-password",
        this.page._url || "http://example.test/",
      ).toString();
    }
    if (this.selector === "#same-url-clear") {
      this.page.fields = {};
    }
  }
}

class FakeText {
  constructor(text) {
    this.nodeType = 3;
    this.textContent = text;
  }
  cloneNode() {
    return new FakeText(this.textContent);
  }
}

class FakeElement {
  constructor(tagName, attrs = {}, text = "", children = []) {
    this.tagName = tagName.toUpperCase();
    this.attrs = attrs;
    this.children = children;
    this.textNode = new FakeText(text);
    this.childNodes = [this.textNode, ...children];
    this.parentElement = null;
    this.nodeType = 1;
    for (const child of children) {
      child.parentElement = this;
    }
    this.refreshText();
  }
  refreshText() {
    const childText = this.children.map((child) => child.textContent || "").join("");
    this.innerText = `${this.textNode.textContent}${childText}`;
    this.textContent = `${this.textNode.textContent}${childText}`;
  }
  setEditableText(text) {
    this.textNode.textContent = text;
    this.refreshText();
  }
  cloneNode(deep) {
    const children = deep ? this.children.map((child) => child.cloneNode(true)) : [];
    return new FakeElement(
      this.tagName.toLowerCase(),
      { ...this.attrs },
      this.textNode.textContent,
      children,
    );
  }
  querySelectorAll(selector) {
    const matches = [];
    const visit = (element) => {
      for (const child of element.children) {
        if (selector === "[contenteditable]" && child.getAttribute("contenteditable") !== null) {
          matches.push(child);
        }
        visit(child);
      }
    };
    visit(this);
    return matches;
  }
  remove() {
    if (!this.parentElement) {
      return;
    }
    this.parentElement.children = this.parentElement.children.filter((child) => child !== this);
    this.parentElement.childNodes = this.parentElement.childNodes.filter((child) => child !== this);
    this.parentElement.refreshText();
    this.parentElement = null;
  }
  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null;
  }
  hasAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attrs, name);
  }
  get isContentEditable() {
    const ownValue = this.getAttribute("contenteditable");
    if (ownValue !== null) {
      return String(ownValue).toLowerCase() !== "false";
    }
    return Boolean(this.parentElement && this.parentElement.isContentEditable);
  }
  closest(tagName) {
    let current = this.parentElement;
    while (current) {
      if (current.tagName.toLowerCase() === tagName) {
        return current;
      }
      current = current.parentElement;
    }
    return null;
  }
}

const nestedButton = new FakeElement("button", {}, "Nested");
const section = new FakeElement("section", {}, "", [nestedButton]);
const continueLink = new FakeElement("a", { id: "continue", href: "/next" }, "Continue");
const searchInput = new FakeElement("input", { id: "search", name: "q" });
const submitButton = new FakeElement("button", { id: "submit" }, "Submit");
const loginButton = new FakeElement("button", { id: "login" }, "Log in");
const hiddenReserve = new FakeElement(
  "a",
  { id: "hidden-reserve", href: "#", "data-display": "none" },
  "Reserve",
);
const hiddenInput = new FakeElement("input", { id: "token", type: "hidden" });
const lockedToken = new FakeElement(
  "span",
  { id: "locked-token", contenteditable: "false" },
  "Locked",
);
const editor = new FakeElement(
  "div",
  { id: "editor", contenteditable: "true" },
  "Editable ",
  [lockedToken],
);
const externalSearch = new FakeElement("input", { id: "external-search" });
const externalForm = new FakeElement(
  "form",
  { id: "external-form", action: "/external", method: "get" },
  "",
  [externalSearch],
);
const externalSubmit = new FakeElement(
  "button",
  { id: "external-submit", type: "submit", form: "external-form", formaction: "/override" },
  "External Submit",
);
externalSearch.form = externalForm;
externalSubmit.form = externalForm;
const body = new FakeElement("body", {}, "", [
  continueLink,
  searchInput,
  submitButton,
  editor,
  loginButton,
  hiddenReserve,
  hiddenInput,
  section,
  externalForm,
  externalSubmit,
]);
const html = new FakeElement("html", {}, "", [body]);
const allElements = [
  html,
  body,
  continueLink,
  searchInput,
  submitButton,
  editor,
  loginButton,
  hiddenReserve,
  hiddenInput,
  lockedToken,
  section,
  nestedButton,
  externalForm,
  externalSearch,
  externalSubmit,
];
const submitterSelector =
  'button:not([type]), button[type="submit" i], input[type="submit" i], input[type="image" i]';
const fakeDocument = {
  documentElement: html,
  querySelectorAll(selector) {
    if (selector === submitterSelector) {
      return allElements.filter((element) => {
        const tag = element.tagName.toLowerCase();
        const type = String(element.getAttribute("type") || "").toLowerCase();
        return (
          (tag === "button" && (!type || type === "submit")) ||
          (tag === "input" && ["submit", "image"].includes(type))
        );
      });
    }
    if (selector.includes(",")) {
      return allElements.filter((element) => {
        const tag = element.tagName.toLowerCase();
        return (
          ["a", "button", "input", "textarea", "select"].includes(tag) ||
          element.getAttribute("contenteditable") !== null
        );
      });
    }
    return allElements.filter((element) => element.tagName.toLowerCase() === selector);
  },
};

function runInPageContext(fn, ...args) {
  const isolated = Function(`return (${fn.toString()});`)();
  return isolated(...args);
}

class Page {
  constructor() {
    this._url = "about:blank";
    this.fields = { "#search": "default" };
  }
  async goto(url) {
    this._url = url;
  }
  url() {
    return this._url;
  }
  async title() {
    return this._url.includes("/submitted") ? "Submitted" : "Browser Home";
  }
  locator(selector) {
    return new Locator(this, selector);
  }
  async waitForLoadState() {}
  async screenshot(options) {
    fs.writeFileSync(options.path, Buffer.from("89504e470d0a1a0a", "hex"));
  }
  visibleText() {
    const editorClone = editor.cloneNode(true);
    for (const node of editorClone.querySelectorAll("[contenteditable]")) {
      if (String(node.getAttribute("contenteditable")).toLowerCase() === "false") {
        node.remove();
      }
    }
    const editorText = editorClone.innerText || "";
    return this._url.includes("/submitted")
      ? `Form submitted ${this._url}`
      : `Hello browser Continue Submit field:${this.fields["#search"] || ""} editor:${editorText}`;
  }
  async evaluate(_fn, mode) {
    if (mode === "snapshot") {
      const previousDocument = globalThis.document;
      const previousWindow = globalThis.window;
      globalThis.window = {
        getComputedStyle: (element) => ({
          display: element.getAttribute("data-display") || "block",
          visibility: element.getAttribute("data-visibility") || "visible",
          opacity: element.getAttribute("data-opacity") || "1",
        }),
      };
      globalThis.document = fakeDocument;
      try {
        return runInPageContext(_fn, mode);
      } finally {
        globalThis.document = previousDocument;
        globalThis.window = previousWindow;
      }
    }
    if (mode === "metadata") {
      const previousDocument = globalThis.document;
      const previousWindow = globalThis.window;
      globalThis.window = { location: { href: this._url } };
      globalThis.document = {
        title: await this.title(),
        body: { innerText: this.visibleText() },
      };
      try {
        return runInPageContext(_fn, mode);
      } finally {
        globalThis.document = previousDocument;
        globalThis.window = previousWindow;
      }
    }
    return {};
  }
}

class Context {
  constructor() {
    this.page = new Page();
  }
  pages() {
    return [this.page];
  }
  async newPage() {
    return this.page;
  }
  async close() {}
}

exports.chromium = {
  launchPersistentContext: async () => new Context(),
};
""",
        encoding="utf-8",
    )
    session_dir = tmp_path / "session"
    session_dir.mkdir()

    def run_wrapper(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["node", str(wrapper), "-s=shisad-browser-session", *args],
            cwd=session_dir,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

    assert run_wrapper("--shisad-browser-wrapper-version").returncode == 0
    assert run_wrapper("open").returncode == 0
    assert run_wrapper("goto", "http://example.test/").returncode == 0

    metadata_path = session_dir / "page.json"
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["url"] == "http://example.test/"
    assert metadata["title"] == "Browser Home"
    assert "Hello browser" in metadata["visible_text"]

    state_path = session_dir / ".shisad-playwright" / "shisad-browser-session.json"
    state_path.write_text(
        json.dumps(
            {
                "opened": True,
                "current_url": "http://other.test/",
                "fields": {"#search": "legacy-secret"},
            }
        ),
        encoding="utf-8",
    )
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    legacy = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert legacy["url"] == "http://other.test/"
    assert "legacy-secret" not in legacy["visible_text"]
    migrated_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert migrated_state["fields"] == {}
    assert migrated_state["fields_url"] == ""

    snapshot_path = session_dir / "snapshot.txt"
    assert run_wrapper("goto", "http://example.test/").returncode == 0
    result = run_wrapper("snapshot", "--filename", str(snapshot_path))
    assert result.returncode == 0, result.stderr
    snapshot = snapshot_path.read_text(encoding="utf-8")
    assert '[e1] link "Continue" selector="#continue" href="/next"' in snapshot
    assert '[e3] button "Submit" selector="#submit"' in snapshot
    assert '[e4] field "Editable" selector="#editor"' in snapshot
    assert 'button "Nested" selector="html > body > section > button"' in snapshot
    assert (
        'field "external-search" selector="#external-search" control_type="text" '
        'form_action="/override" form_method="get"'
    ) in snapshot
    assert "button:nth-of-type(2)" not in snapshot
    assert "hidden-reserve" not in snapshot
    assert "Reserve" not in snapshot
    assert "#token" not in snapshot
    assert "Locked" not in snapshot
    assert "#locked-token" not in snapshot

    assert run_wrapper("fill", "#search", "--help").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    flag_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert flag_text["url"] == "http://example.test/"
    assert "--help" in flag_text["visible_text"]

    assert run_wrapper("fill", "#search", "--submit").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    submit_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert submit_text["url"] == "http://example.test/"
    assert "--submit" in submit_text["visible_text"]

    assert run_wrapper("fill", "#search", "--no-store").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    no_store_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert no_store_text["url"] == "http://example.test/"
    assert "--no-store" in no_store_text["visible_text"]

    assert run_wrapper("fill", "#search", "").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    empty_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert empty_text["url"] == "http://example.test/"
    assert "field:default" not in empty_text["visible_text"]

    assert run_wrapper("fill", "#search", "sensitive-secret", "--no-store").returncode == 0
    sensitive_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert "sensitive-secret" not in json.dumps(sensitive_state, sort_keys=True)
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    sensitive_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert sensitive_text["url"] == "http://example.test/"
    assert "sensitive-secret" not in sensitive_text["visible_text"]

    state_path.write_text(
        json.dumps(
            {
                "opened": True,
                "current_url": "http://example.test/",
                "fields_url": "http://example.test/",
                "fields": {"#search": "old-sensitive"},
            }
        ),
        encoding="utf-8",
    )
    assert run_wrapper("fill", "#search", "replacement-secret", "--no-store").returncode == 0
    restored_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert "old-sensitive" not in json.dumps(restored_state, sort_keys=True)
    assert "replacement-secret" not in json.dumps(restored_state, sort_keys=True)
    assert restored_state["current_url"] == "http://example.test/"

    state_path.write_text(
        json.dumps(
            {
                "opened": True,
                "current_url": "http://example.test/",
                "fields_url": "http://example.test/",
                "fields": {"#missing": "old-sensitive"},
            }
        ),
        encoding="utf-8",
    )
    missing = run_wrapper("fill", "#missing", "replacement-secret", "--no-store")
    assert missing.returncode != 0
    failed_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert "old-sensitive" not in json.dumps(failed_state, sort_keys=True)
    assert "replacement-secret" not in json.dumps(failed_state, sort_keys=True)

    assert run_wrapper("goto", "http://example.test/").returncode == 0
    login = run_wrapper("fill", "#search", "sensitive-secret", "--click", "#login", "--no-store")
    assert login.returncode == 0, login.stderr
    login_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert login_state["current_url"] == "http://example.test/logged-in"
    assert "sensitive-secret" not in json.dumps(login_state, sort_keys=True)

    assert run_wrapper("goto", "http://example.test/").returncode == 0
    assert run_wrapper("fill", "#editor", "rich-secret").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    rich_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert rich_text["url"] == "http://example.test/"
    assert "rich-secret" in rich_text["visible_text"]
    assert "Locked" not in rich_text["visible_text"]

    assert run_wrapper("fill", "#editor", "line one\nline two").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    multiline_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert multiline_text["url"] == "http://example.test/"
    assert "line one\nline two" in multiline_text["visible_text"]
    assert "line one line two" not in multiline_text["visible_text"]
    assert "Locked" not in multiline_text["visible_text"]

    assert run_wrapper("fill", "#search", "same-url-secret").returncode == 0
    assert run_wrapper("click", "#same-url").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    same_url = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert same_url["url"] == "http://example.test/"
    assert "same-url-secret" in same_url["visible_text"]

    assert run_wrapper("click", "#same-url-clear").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    same_url_cleared = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert same_url_cleared["url"] == "http://example.test/"
    assert "same-url-secret" not in same_url_cleared["visible_text"]

    assert run_wrapper("fill", "#search", "secret").returncode == 0
    assert run_wrapper("goto", "http://other.test/").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    other = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert other["url"] == "http://other.test/"
    assert "secret" not in other["visible_text"]

    assert run_wrapper("goto", "http://example.test/").returncode == 0
    assert run_wrapper("fill", "#search", "hello").returncode == 0
    assert run_wrapper("click", "#submit").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    submitted = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert submitted["url"] == "http://example.test/submitted?q=hello"
    assert submitted["title"] == "Submitted"
