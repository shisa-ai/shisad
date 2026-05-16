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

function defaultDisplayFor(element) {
  const blockTags = new Set([
    "body",
    "div",
    "fieldset",
    "form",
    "html",
    "legend",
    "section",
  ]);
  return blockTags.has(element.tagName.toLowerCase()) ? "block" : "inline";
}

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
    if (!["#search", "#editor"].includes(this.selector)) {
      throw new Error("target is not fillable");
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
      const previousWindow = globalThis.window;
      globalThis.window = {
        getComputedStyle: (element) => ({
          display: element.getAttribute("data-display") || defaultDisplayFor(element),
          visibility: element.getAttribute("data-visibility") || "visible",
          opacity: element.getAttribute("data-opacity") || "1",
        }),
      };
      try {
        return callback(editor);
      } finally {
        globalThis.window = previousWindow;
      }
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
    if (this.tagName.toLowerCase() === "br") {
      this.innerText = "\n";
      this.textContent = "";
      return;
    }
    const visibleChildText = this.children
      .filter((child) => {
        const tag = child.tagName.toLowerCase();
        return (
          tag !== "script" &&
          tag !== "style" &&
          !child.hasAttribute("hidden") &&
          child.getAttribute("data-display") !== "none" &&
          child.getAttribute("data-visibility") !== "hidden" &&
          child.getAttribute("data-opacity") !== "0"
        );
      })
      .map((child) => child.innerText || "")
      .join("");
    const childText = this.children.map((child) => child.textContent || "").join("");
    this.innerText = `${this.textNode.textContent}${visibleChildText}`;
    this.textContent = `${this.textNode.textContent}${childText}`;
  }
  replaceChildren(children) {
    for (const child of this.children) {
      child.parentElement = null;
    }
    this.children = children;
    this.childNodes = [this.textNode, ...this.children];
    for (const child of this.children) {
      child.parentElement = this;
    }
  }
  setEditableText(text) {
    if (text === "alpha hidden-break beta") {
      this.textNode.textContent = "alpha";
      this.replaceChildren([
        new FakeElement("br", { hidden: "" }),
        new FakeElement("span", {}, "beta"),
      ]);
      this.refreshText();
      return;
    }
    if (text === "empty placeholder") {
      this.textNode.textContent = "";
      this.replaceChildren([
        new FakeElement("span", { contenteditable: "false" }, "Locked"),
        new FakeElement("span", { hidden: "" }, "ignore"),
        new FakeElement("br"),
      ]);
      this.refreshText();
      return;
    }
    if (text === "block placeholder") {
      this.textNode.textContent = "";
      this.replaceChildren([new FakeElement("div", {}, "", [new FakeElement("br")])]);
      this.refreshText();
      return;
    }
    if (text === "hello block world") {
      this.textNode.textContent = "hello";
      this.replaceChildren([new FakeElement("div", {}, "world")]);
      this.refreshText();
      return;
    }
    if (text === "hello display-block world") {
      this.textNode.textContent = "hello";
      this.replaceChildren([
        new FakeElement("span", { "data-display": "block" }, "world"),
      ]);
      this.refreshText();
      return;
    }
    if (text === "hello nested-display-block world") {
      this.textNode.textContent = "hello";
      this.replaceChildren([
        new FakeElement("span", {}, "", [
          new FakeElement("span", { "data-display": "block" }, "world"),
        ]),
      ]);
      this.refreshText();
      return;
    }
    if (text === "nested-display-block world after") {
      this.textNode.textContent = "";
      this.replaceChildren([
        new FakeElement("span", {}, "", [
          new FakeElement("span", { "data-display": "block" }, "world"),
        ]),
        new FakeElement("span", {}, "after"),
      ]);
      this.refreshText();
      return;
    }
    if (text === "hello nested-empty-display-block world") {
      this.textNode.textContent = "hello";
      this.replaceChildren([
        new FakeElement("span", {}, "", [
          new FakeElement("span", { "data-display": "block" }),
        ]),
        new FakeElement("span", {}, "world"),
      ]);
      this.refreshText();
      return;
    }
    if (text === "hello empty-block world") {
      this.textNode.textContent = "hello";
      this.replaceChildren([new FakeElement("div"), new FakeElement("span", {}, "world")]);
      this.refreshText();
      return;
    }
    if (text === "leading empty-block world") {
      this.textNode.textContent = "";
      this.replaceChildren([
        new FakeElement("div"),
        new FakeElement("div"),
        new FakeElement("span", {}, "world"),
      ]);
      this.refreshText();
      return;
    }
    if (text === "hello double-empty-block world") {
      this.textNode.textContent = "hello";
      this.replaceChildren([
        new FakeElement("div"),
        new FakeElement("div"),
        new FakeElement("span", {}, "world"),
      ]);
      this.refreshText();
      return;
    }
    if (text === "hello break-empty-block world") {
      this.textNode.textContent = "hello";
      this.replaceChildren([
        new FakeElement("br"),
        new FakeElement("div"),
        new FakeElement("span", {}, "world"),
      ]);
      this.refreshText();
      return;
    }
    if (text.includes("\n")) {
      const parts = text.split("\n");
      const generatedChildren = [];
      this.textNode.textContent = parts.shift() || "";
      for (const part of parts) {
        generatedChildren.push(new FakeElement("br"));
        generatedChildren.push(new FakeElement("span", {}, part));
      }
      this.replaceChildren(generatedChildren);
      this.refreshText();
      return;
    }
    this.textNode.textContent = text;
    this.replaceChildren([]);
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
  contains(node) {
    if (node === this) {
      return true;
    }
    return this.children.some((child) => child.contains(node));
  }
  querySelectorAll(selector) {
    const matches = [];
    const visit = (element) => {
      for (const child of element.children) {
        if (
          selector === "*" ||
          (selector === "[contenteditable]" && child.getAttribute("contenteditable") !== null)
        ) {
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
  get disabled() {
    return this.hasAttribute("disabled");
  }
  get hidden() {
    return this.hasAttribute("hidden");
  }
  matches(selector) {
    if (selector === ":disabled") {
      if (this.disabled) {
        return true;
      }
      let current = this.parentElement;
      while (current) {
        if (current.tagName.toLowerCase() === "fieldset" && current.disabled) {
          const firstLegend = current.children.find(
            (child) => child.tagName.toLowerCase() === "legend",
          );
          if (firstLegend && firstLegend.contains(this)) {
            current = current.parentElement;
            continue;
          }
          return true;
        }
        current = current.parentElement;
      }
      return false;
    }
    return false;
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
const hiddenLabelText = new FakeElement("span", { hidden: "" }, "Delete");
const hiddenLabelButton = new FakeElement(
  "button",
  { id: "hidden-label-button", "aria-label": "Continue safely" },
  "",
  [hiddenLabelText],
);
const opacityLabelText = new FakeElement("span", { "data-opacity": "0" }, "Delete");
const opacityLabelButton = new FakeElement(
  "button",
  { id: "opacity-label-button" },
  "Proceed",
  [opacityLabelText],
);
const hiddenEditableText = new FakeElement("span", { hidden: "" }, "Delete");
const mixedEditor = new FakeElement(
  "div",
  { id: "mixed-editor", contenteditable: "true" },
  "Edit ",
  [hiddenEditableText],
);
const opacityChildButton = new FakeElement("button", { id: "opacity-child-button" }, "Hidden");
const opacityContainer = new FakeElement("div", { "data-opacity": "0" }, "", [
  opacityChildButton,
]);
const visibilityChildButton = new FakeElement(
  "button",
  { id: "visibility-child-button", "data-visibility": "visible" },
  "Visible child",
);
const visibilityContainer = new FakeElement(
  "div",
  { "data-visibility": "hidden" },
  "",
  [visibilityChildButton],
);
const lockedToken = new FakeElement(
  "span",
  { id: "locked-token", contenteditable: "false" },
  "Locked",
);
const opacityEditorText = new FakeElement("span", { "data-opacity": "0" }, "Phantom");
const editor = new FakeElement(
  "div",
  { id: "editor", contenteditable: "true" },
  "Editable ",
  [lockedToken, opacityEditorText],
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
  {
    id: "external-submit",
    type: "menu",
    form: "external-form",
    formaction: "/override",
    formmethod: "",
  },
  "External Submit",
);
externalSearch.form = externalForm;
externalSubmit.form = externalForm;
const dialogSearch = new FakeElement("input", { id: "dialog-search" });
const dialogForm = new FakeElement(
  "form",
  { id: "dialog-form", action: "/dialog", method: "dialog" },
  "",
  [dialogSearch],
);
dialogSearch.form = dialogForm;
const multiSearch = new FakeElement("input", { id: "multi-search" });
const multiOther = new FakeElement("input", { id: "multi-other" });
const multiFieldForm = new FakeElement(
  "form",
  { id: "multi-field-form", action: "/multi", method: "get" },
  "",
  [multiSearch, multiOther],
);
multiSearch.form = multiFieldForm;
multiOther.form = multiFieldForm;
const disabledSearch = new FakeElement("input", { id: "disabled-search" });
const disabledSubmit = new FakeElement(
  "button",
  { id: "disabled-submit", type: "submit", disabled: "" },
  "Disabled",
);
const disabledSubmitForm = new FakeElement(
  "form",
  { id: "disabled-submit-form", action: "/disabled", method: "get" },
  "",
  [disabledSearch, disabledSubmit],
);
disabledSearch.form = disabledSubmitForm;
disabledSubmit.form = disabledSubmitForm;
const ariaSearch = new FakeElement("input", { id: "aria-search" });
const ariaSubmit = new FakeElement(
  "button",
  { id: "aria-submit", type: "submit", "aria-disabled": "true" },
  "ARIA Disabled",
);
const ariaSubmitForm = new FakeElement(
  "form",
  { id: "aria-submit-form", action: "/aria", method: "get" },
  "",
  [ariaSearch, ariaSubmit],
);
ariaSearch.form = ariaSubmitForm;
ariaSubmit.form = ariaSubmitForm;
const disabledBlockerSearch = new FakeElement("input", { id: "disabled-blocker-search" });
const disabledBlockerOther = new FakeElement(
  "input",
  { id: "disabled-blocker-other", disabled: "" },
);
const disabledBlockerForm = new FakeElement(
  "form",
  { id: "disabled-blocker-form", action: "/disabled-blocker", method: "get" },
  "",
  [disabledBlockerSearch, disabledBlockerOther],
);
disabledBlockerSearch.form = disabledBlockerForm;
disabledBlockerOther.form = disabledBlockerForm;
const fieldsetSubmitSearch = new FakeElement("input", { id: "fieldset-submit-search" });
const fieldsetSubmitButton = new FakeElement(
  "button",
  { id: "fieldset-submit", type: "submit" },
  "Fieldset Submit",
);
const disabledSubmitFieldset = new FakeElement(
  "fieldset",
  { disabled: "" },
  "",
  [fieldsetSubmitButton],
);
const fieldsetSubmitForm = new FakeElement(
  "form",
  { id: "fieldset-submit-form", action: "/fieldset-submit", method: "get" },
  "",
  [fieldsetSubmitSearch, disabledSubmitFieldset],
);
fieldsetSubmitSearch.form = fieldsetSubmitForm;
fieldsetSubmitButton.form = fieldsetSubmitForm;
const fieldsetBlockerSearch = new FakeElement("input", { id: "fieldset-blocker-search" });
const fieldsetBlockerOther = new FakeElement("input", { id: "fieldset-blocker-other" });
const disabledBlockerFieldset = new FakeElement(
  "fieldset",
  { disabled: "" },
  "",
  [fieldsetBlockerOther],
);
const fieldsetBlockerForm = new FakeElement(
  "form",
  { id: "fieldset-blocker-form", action: "/fieldset-blocker", method: "get" },
  "",
  [fieldsetBlockerSearch, disabledBlockerFieldset],
);
fieldsetBlockerSearch.form = fieldsetBlockerForm;
fieldsetBlockerOther.form = fieldsetBlockerForm;
const legendSubmitSearch = new FakeElement("input", { id: "legend-submit-search" });
const legendSubmitButton = new FakeElement(
  "button",
  { id: "legend-submit", type: "submit" },
  "Legend Submit",
);
const firstLegend = new FakeElement("legend", {}, "", [legendSubmitButton]);
const legendSubmitFieldset = new FakeElement(
  "fieldset",
  { disabled: "" },
  "",
  [firstLegend],
);
const legendSubmitForm = new FakeElement(
  "form",
  { id: "legend-submit-form", action: "/legend-submit", method: "get" },
  "",
  [legendSubmitSearch, legendSubmitFieldset],
);
legendSubmitSearch.form = legendSubmitForm;
legendSubmitButton.form = legendSubmitForm;
const unresolvedFormSearch = new FakeElement("input", {
  id: "unresolved-form-search",
  form: "missing-form",
});
const emptyFormSearch = new FakeElement("input", {
  id: "empty-form-search",
  form: "",
});
const unresolvedFormSubmit = new FakeElement(
  "button",
  { id: "unresolved-form-submit", type: "submit", form: "missing-form" },
  "Unresolved Submit",
);
const unresolvedFormOwner = new FakeElement(
  "form",
  { id: "unresolved-form-owner", action: "/should-not-submit", method: "post" },
  "",
  [unresolvedFormSearch, emptyFormSearch, unresolvedFormSubmit],
);
const body = new FakeElement("body", {}, "", [
  continueLink,
  searchInput,
  submitButton,
  editor,
  hiddenLabelButton,
  opacityLabelButton,
  mixedEditor,
  loginButton,
  hiddenReserve,
  hiddenInput,
  section,
  externalForm,
  externalSubmit,
  dialogForm,
  multiFieldForm,
  disabledSubmitForm,
  ariaSubmitForm,
  disabledBlockerForm,
  fieldsetSubmitForm,
  fieldsetBlockerForm,
  legendSubmitForm,
  unresolvedFormOwner,
  opacityContainer,
  visibilityContainer,
]);
const html = new FakeElement("html", {}, "", [body]);
const allElements = [
  html,
  body,
  continueLink,
  searchInput,
  submitButton,
  editor,
  hiddenLabelButton,
  hiddenLabelText,
  opacityLabelButton,
  opacityLabelText,
  mixedEditor,
  hiddenEditableText,
  loginButton,
  hiddenReserve,
  hiddenInput,
  lockedToken,
  section,
  nestedButton,
  externalForm,
  externalSearch,
  externalSubmit,
  dialogForm,
  dialogSearch,
  multiFieldForm,
  multiSearch,
  multiOther,
  disabledSubmitForm,
  disabledSearch,
  disabledSubmit,
  ariaSubmitForm,
  ariaSearch,
  ariaSubmit,
  disabledBlockerForm,
  disabledBlockerSearch,
  disabledBlockerOther,
  fieldsetSubmitForm,
  fieldsetSubmitSearch,
  disabledSubmitFieldset,
  fieldsetSubmitButton,
  fieldsetBlockerForm,
  fieldsetBlockerSearch,
  disabledBlockerFieldset,
  fieldsetBlockerOther,
  legendSubmitForm,
  legendSubmitSearch,
  legendSubmitFieldset,
  firstLegend,
  legendSubmitButton,
  unresolvedFormOwner,
  unresolvedFormSearch,
  emptyFormSearch,
  unresolvedFormSubmit,
  opacityContainer,
  opacityChildButton,
  visibilityContainer,
  visibilityChildButton,
];
const submitterSelector = "button, input";
const fakeDocument = {
  documentElement: html,
  querySelectorAll(selector) {
    if (selector === submitterSelector) {
      return allElements.filter((element) => {
        const tag = element.tagName.toLowerCase();
        const type = String(element.getAttribute("type") || "").toLowerCase();
        return (
          (tag === "button" && !["button", "reset"].includes(type)) ||
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
          display: element.getAttribute("data-display") || defaultDisplayFor(element),
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
    assert 'button "Continue safely" selector="#hidden-label-button"' in snapshot
    assert 'button "Proceed" selector="#opacity-label-button"' in snapshot
    assert 'Proceed Delete' not in snapshot
    assert 'field "Edit" selector="#mixed-editor"' in snapshot
    assert "Delete" not in snapshot
    assert "Phantom" not in snapshot
    assert "#opacity-child-button" not in snapshot
    assert 'button "Visible child" selector="#visibility-child-button"' in snapshot
    assert 'button "Nested" selector="html > body > section > button"' in snapshot
    assert (
        'field "external-search" selector="#external-search" control_type="text" '
        'form_action="/override" form_method="get"'
    ) in snapshot
    assert (
        'field "dialog-search" selector="#dialog-search" control_type="text" '
        'form_action="/dialog" form_method="dialog"'
    ) in snapshot
    assert 'field "multi-search" selector="#multi-search" control_type="text"' in snapshot
    assert (
        'field "multi-search" selector="#multi-search" control_type="text" '
        'form_action='
    ) not in snapshot
    assert 'field "disabled-search" selector="#disabled-search" control_type="text"' in snapshot
    assert (
        'field "disabled-search" selector="#disabled-search" control_type="text" '
        'form_action='
    ) not in snapshot
    assert "#disabled-submit" not in snapshot
    assert (
        'field "aria-search" selector="#aria-search" control_type="text" '
        'form_action="/aria" form_method="get"'
    ) in snapshot
    assert "#aria-submit" not in snapshot
    assert (
        'field "disabled-blocker-search" selector="#disabled-blocker-search" '
        'control_type="text" form_action='
    ) not in snapshot
    assert "#disabled-blocker-other" not in snapshot
    assert (
        'field "fieldset-submit-search" selector="#fieldset-submit-search" '
        'control_type="text" form_action='
    ) not in snapshot
    assert 'selector="#fieldset-submit"' not in snapshot
    assert (
        'field "fieldset-blocker-search" selector="#fieldset-blocker-search" '
        'control_type="text" form_action='
    ) not in snapshot
    assert "#fieldset-blocker-other" not in snapshot
    assert (
        'field "legend-submit-search" selector="#legend-submit-search" '
        'control_type="text" form_action="/legend-submit" form_method="get"'
    ) in snapshot
    assert 'selector="#legend-submit"' in snapshot
    assert 'field "unresolved-form-search" selector="#unresolved-form-search"' in snapshot
    assert (
        'field "unresolved-form-search" selector="#unresolved-form-search" '
        'control_type="text" form_action='
    ) not in snapshot
    assert 'field "empty-form-search" selector="#empty-form-search"' in snapshot
    assert (
        'field "empty-form-search" selector="#empty-form-search" '
        'control_type="text" form_action='
    ) not in snapshot
    assert 'button "Unresolved Submit" selector="#unresolved-form-submit"' in snapshot
    assert (
        'button "Unresolved Submit" selector="#unresolved-form-submit" '
        'control_type="submit" form_action='
    ) not in snapshot
    assert "button:nth-of-type(2)" not in snapshot
    assert "hidden-reserve" not in snapshot
    assert "Reserve" not in snapshot
    assert "#token" not in snapshot
    assert "Locked" not in snapshot
    assert "#locked-token" not in snapshot

    assert run_wrapper("fill", "#search", "--help").returncode == 0
    assert run_wrapper("fill", "#editor", "").returncode == 0
    editor_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert "Phantom" not in json.dumps(editor_state, sort_keys=True)
    assert run_wrapper("fill", "#continue", "not-fillable", "--submit").returncode != 0
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

    assert run_wrapper("fill", "#editor", "single line").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    single_line_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "single line" in single_line_text["visible_text"]
    assert "line one" not in single_line_text["visible_text"]
    assert "line two" not in single_line_text["visible_text"]

    assert run_wrapper("fill", "#editor", "trail\n\n").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    trailing_break_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "trail\n\n" in trailing_break_text["visible_text"]

    assert run_wrapper("fill", "#editor", "alpha hidden-break beta").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    hidden_break_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "alphabeta" in hidden_break_text["visible_text"]
    assert "alpha\nbeta" not in hidden_break_text["visible_text"]

    assert run_wrapper("fill", "#editor", "\n").returncode == 0
    single_blank_line_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert single_blank_line_state["fields"]["#editor"] == "\n"
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    single_blank_line_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "editor:\n" in single_blank_line_text["visible_text"]

    assert run_wrapper("fill", "#editor", "\n\n").returncode == 0
    blank_line_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert blank_line_state["fields"]["#editor"] == "\n\n"
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    blank_line_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "editor:\n\n" in blank_line_text["visible_text"]

    assert run_wrapper("fill", "#editor", "empty placeholder").returncode == 0
    placeholder_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert placeholder_state["fields"]["#editor"] == ""
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    placeholder_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "editor:\n" not in placeholder_text["visible_text"]

    assert run_wrapper("fill", "#editor", "block placeholder").returncode == 0
    block_placeholder_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert block_placeholder_state["fields"]["#editor"] == ""
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    block_placeholder_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "editor:\n" not in block_placeholder_text["visible_text"]

    assert run_wrapper("fill", "#editor", "hello block world").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    block_child_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "hello\nworld" in block_child_text["visible_text"]
    assert "helloworld" not in block_child_text["visible_text"]

    assert run_wrapper("fill", "#editor", "hello display-block world").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    display_block_child_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "hello\nworld" in display_block_child_text["visible_text"]
    assert "helloworld" not in display_block_child_text["visible_text"]

    assert run_wrapper("fill", "#editor", "hello nested-display-block world").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    nested_display_block_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "hello\nworld" in nested_display_block_text["visible_text"]
    assert "helloworld" not in nested_display_block_text["visible_text"]

    assert run_wrapper("fill", "#editor", "nested-display-block world after").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    nested_display_block_after_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "world\nafter" in nested_display_block_after_text["visible_text"]
    assert "worldafter" not in nested_display_block_after_text["visible_text"]

    assert run_wrapper("fill", "#editor", "hello nested-empty-display-block world").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    nested_empty_display_block_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "hello\nworld" in nested_empty_display_block_text["visible_text"]
    assert "helloworld" not in nested_empty_display_block_text["visible_text"]

    assert run_wrapper("fill", "#editor", "hello empty-block world").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    empty_block_child_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "hello\nworld" in empty_block_child_text["visible_text"]
    assert "helloworld" not in empty_block_child_text["visible_text"]

    assert run_wrapper("fill", "#editor", "leading empty-block world").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    leading_empty_block_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "\n\nworld" in leading_empty_block_text["visible_text"]
    assert "editor:world" not in leading_empty_block_text["visible_text"]

    assert run_wrapper("fill", "#editor", "hello double-empty-block world").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    double_empty_block_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "hello\n\nworld" in double_empty_block_text["visible_text"]
    assert "hello\nworld" not in double_empty_block_text["visible_text"]

    assert run_wrapper("fill", "#editor", "hello break-empty-block world").returncode == 0
    result = run_wrapper("eval", "() => JSON.stringify({})", "--filename", str(metadata_path))
    assert result.returncode == 0, result.stderr
    break_empty_block_text = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "hello\n\nworld" in break_empty_block_text["visible_text"]
    assert "hello\nworld" not in break_empty_block_text["visible_text"]

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
