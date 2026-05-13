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
    this.page.fields[this.selector] = text;
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
  }
}

class Page {
  constructor() {
    this._url = "about:blank";
    this.fields = {};
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
  async evaluate(_fn, mode) {
    if (mode === "snapshot") {
      return [
        {
          kind: "link",
          label: "Continue",
          selector: "#continue",
          href: "/next",
        },
        {
          kind: "field",
          label: "q",
          selector: "#search",
          form_action: "/submitted",
          form_method: "get",
        },
        {
          kind: "button",
          label: "Submit",
          selector: "#submit",
          form_action: "/submitted",
          form_method: "get",
        },
      ];
    }
    return {
      url: this._url,
      title: await this.title(),
      visible_text: this._url.includes("/submitted")
        ? `Form submitted ${this._url}`
        : `Hello browser Continue Submit field:${this.fields["#search"] || ""}`,
    };
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
