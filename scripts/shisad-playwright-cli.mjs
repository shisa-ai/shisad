#!/usr/bin/env node
/*
 * Production Playwright bridge for shisad browser tools.
 *
 * This is not the upstream Playwright CLI. It implements the small shisad wire
 * protocol consumed by BrowserToolkit: a session flag (`-s=...`) plus
 * open/goto/eval/snapshot/fill/click/screenshot/list/close subcommands.
 */

import { createRequire } from "node:module";
import fs from "node:fs/promises";
import path from "node:path";

const VERSION = "shisad-browser-wrapper 2";
const DOCTOR_OK = "shisad-browser-wrapper doctor ok";
const STATE_DIR = ".shisad-playwright";
const DEFAULT_TIMEOUT_MS = 15000;
const PNG_1X1_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";

function usage() {
  return [
    "Usage: shisad-playwright-cli [-s=<session>] <command> [args]",
    "",
    "Commands:",
    "  open [url]",
    "  goto <url>",
    "  eval <function> [element] [--filename <path>]",
    "  snapshot [element] [--filename <path>]",
    "  fill <selector> <text> [--submit] [--click <selector>] [--no-store]",
    "  click <selector>",
    "  screenshot [target] --filename <path>",
    "  list",
    "  close",
    "",
    "Protocol probe:",
    "  --shisad-browser-wrapper-version",
    "  --shisad-browser-wrapper-doctor",
    "  -s=<session> is the shisad session selector.",
  ].join("\n");
}

function parseArgv(argv) {
  const args = [...argv];
  let session = "default";
  if (args.length > 0 && args[0].startsWith("-s=")) {
    session = args.shift().slice(3) || "default";
  }
  const command = args.shift() || "";
  if (command === "--shisad-browser-wrapper-version") {
    return { probe: "version" };
  }
  if (command === "--shisad-browser-wrapper-doctor") {
    return { probe: "doctor" };
  }
  if (command === "--help" || command === "-h") {
    return { probe: "help" };
  }
  return { session, command, args };
}

function extractOption(args, option) {
  const index = args.length - 2;
  if (index < 0 || args[index] !== option) {
    return "";
  }
  const value = args[index + 1] || "";
  args.splice(index, 2);
  return value;
}

function sessionToken(raw) {
  return String(raw || "default").replace(/[^A-Za-z0-9_.-]/g, "_");
}

function storageRoot(cwd) {
  return path.join(cwd, STATE_DIR);
}

function statePath(cwd, session) {
  return path.join(storageRoot(cwd), `${sessionToken(session)}.json`);
}

function profilePath(cwd, session) {
  return path.join(storageRoot(cwd), `profile-${sessionToken(session)}`);
}

async function loadState(cwd, session) {
  try {
    const raw = await fs.readFile(statePath(cwd, session), "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      const fieldsUrl = String(parsed.fields_url || "");
      return {
        opened: Boolean(parsed.opened),
        current_url: String(parsed.current_url || ""),
        fields_url: fieldsUrl,
        fields:
          fieldsUrl &&
          parsed.fields &&
          typeof parsed.fields === "object" &&
          !Array.isArray(parsed.fields)
            ? parsed.fields
            : {},
      };
    }
  } catch {
    // Missing or corrupt state starts a clean browser session.
  }
  return { opened: false, current_url: "", fields_url: "", fields: {} };
}

async function saveState(cwd, session, state) {
  await fs.mkdir(storageRoot(cwd), { recursive: true });
  await fs.writeFile(statePath(cwd, session), `${JSON.stringify(state, null, 2)}\n`, "utf8");
}

function requireOpened(state) {
  if (!state.opened) {
    throw new Error("browser session is not open");
  }
}

function loadPlaywright() {
  const require = createRequire(import.meta.url);
  try {
    return require("@playwright/test");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `@playwright/test is not available. Install with: npm install @playwright/test; ${message}`,
    );
  }
}

function timeoutMs() {
  const parsed = Number.parseInt(process.env.SHISAD_PLAYWRIGHT_TIMEOUT_MS || "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_TIMEOUT_MS;
}

async function waitForSettled(page) {
  if (typeof page.waitForLoadState === "function") {
    await page.waitForLoadState("domcontentloaded", { timeout: timeoutMs() }).catch(() => {});
  }
}

async function goto(page, url) {
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: timeoutMs() });
  await waitForSettled(page);
}

async function writeOutput(filename, text) {
  if (filename) {
    await fs.writeFile(filename, text, "utf8");
    return;
  }
  process.stdout.write(text);
}

function cleanAttribute(value) {
  return String(value || "").replace(/\s+/g, " ").replaceAll('"', "'").trim();
}

function snapshotLines(elements) {
  const lines = [];
  for (const [index, item] of elements.entries()) {
    const ref = `e${index + 1}`;
    const kind = cleanAttribute(item.kind || "element");
    const label = cleanAttribute(item.label || "");
    const attrs = [`selector="${cleanAttribute(item.selector || "")}"`];
    if (item.href) {
      attrs.push(`href="${cleanAttribute(item.href)}"`);
    }
    if (item.control_type) {
      attrs.push(`control_type="${cleanAttribute(item.control_type)}"`);
    }
    if (item.form_action) {
      attrs.push(`form_action="${cleanAttribute(item.form_action)}"`);
    }
    if (item.form_method) {
      attrs.push(`form_method="${cleanAttribute(item.form_method)}"`);
    }
    lines.push(`[${ref}] ${kind} "${label}" ${attrs.join(" ")}`.trim());
  }
  return `${lines.join("\n")}\n`;
}

async function metadata(page) {
  return await page.evaluate(
    (mode) => {
      if (mode !== "metadata") {
        return {};
      }
      return {
        url: window.location.href,
        title: document.title,
        visible_text: document.body ? document.body.innerText || "" : "",
      };
    },
    "metadata",
  );
}

async function snapshot(page) {
  return await page.evaluate(
    (mode) => {
      if (mode !== "snapshot") {
        return [];
      }
      const cssEscape = (value) => {
        const raw = String(value || "");
        if (globalThis.CSS && typeof globalThis.CSS.escape === "function") {
          return globalThis.CSS.escape(raw);
        }
        return raw.replace(/[^A-Za-z0-9_-]/g, (char) => `\\${char}`);
      };
      const attrValue = (value) => String(value || "").replace(/\\/g, "\\\\").replace(/'/g, "\\'");
      const selectorFor = (element) => {
        const tag = element.tagName.toLowerCase();
        const id = element.getAttribute("id");
        if (id) {
          return `#${cssEscape(id)}`;
        }
        const name = element.getAttribute("name");
        if (name) {
          return `${tag}[name='${attrValue(name)}']`;
        }
        const aria = element.getAttribute("aria-label");
        if (aria) {
          return `${tag}[aria-label='${attrValue(aria)}']`;
        }
        const parts = [];
        let current = element;
        while (current && current.nodeType === 1) {
          const currentTag = current.tagName.toLowerCase();
          let part = currentTag;
          const parent = current.parentElement;
          if (parent) {
            const siblings = Array.from(parent.children).filter(
              (item) => item.tagName.toLowerCase() === currentTag,
            );
            if (siblings.length > 1) {
              part = `${currentTag}:nth-of-type(${siblings.indexOf(current) + 1})`;
            }
          }
          parts.unshift(part);
          if (current === document.documentElement) {
            break;
          }
          current = parent;
        }
        return parts.join(" > ") || tag;
      };
      const hasContenteditableFalse = (element) => {
        const value = element.getAttribute("contenteditable");
        return value !== null && String(value).toLowerCase() === "false";
      };
      const computedStyleFor = (element) =>
        typeof window !== "undefined" && typeof window.getComputedStyle === "function"
          ? window.getComputedStyle(element)
          : null;
      const hidesSubtreeContent = (item) => {
        if (!item || item.nodeType !== 1) {
          return false;
        }
        const tag = item.tagName.toLowerCase();
        if (tag === "script" || tag === "style" || item.hidden) {
          return true;
        }
        const style = computedStyleFor(item);
        return Boolean(
          style &&
            (style.display === "none" || style.opacity === "0"),
        );
      };
      const hasHiddenStyleAncestor = (element) => {
        let current = element.parentElement;
        while (current && current.nodeType === 1) {
          if (hidesSubtreeContent(current)) {
            return true;
          }
          current = current.parentElement;
        }
        return false;
      };
      const isVisibleCandidate = (element) => {
        const tag = element.tagName.toLowerCase();
        if (tag === "input" && String(element.getAttribute("type") || "").toLowerCase() === "hidden") {
          return false;
        }
        if (
          isNativeDisabledControl(element) ||
          element.getAttribute("aria-disabled") === "true" ||
          element.hidden
        ) {
          return false;
        }
        if (element.getAttribute("aria-hidden") === "true") {
          return false;
        }
        const style = computedStyleFor(element);
        if (
          style &&
          (style.display === "none" || style.visibility === "hidden" || style.opacity === "0")
        ) {
          return false;
        }
        if (hasHiddenStyleAncestor(element)) {
          return false;
        }
        if (typeof element.getClientRects === "function" && element.getClientRects().length === 0) {
          return false;
        }
        if (typeof element.getBoundingClientRect === "function") {
          const rect = element.getBoundingClientRect();
          if (rect && rect.width <= 0 && rect.height <= 0) {
            return false;
          }
        }
        return true;
      };
      const visibleTextFor = (element) => {
        const textFor = (node, textHidden = false) => {
          if (!node) {
            return "";
          }
          if (node.nodeType === 3) {
            return textHidden ? "" : node.textContent || "";
          }
          if (node.nodeType !== 1 || hidesSubtreeContent(node)) {
            return "";
          }
          const style = computedStyleFor(node);
          const nextTextHidden = style
            ? style.visibility === "hidden"
            : textHidden;
          return Array.from(node.childNodes || [])
            .map((child) => textFor(child, nextTextHidden))
            .join(" ");
        };
        return textFor(element).replace(/\s+/g, " ").trim();
      };
      const editableTextFor = (element) => {
        const textFor = (node, textHidden = false) => {
          if (!node) {
            return "";
          }
          if (node.nodeType === 3) {
            return textHidden ? "" : node.textContent || "";
          }
          if (node.nodeType !== 1 || hasContenteditableFalse(node) || hidesSubtreeContent(node)) {
            return "";
          }
          const style = computedStyleFor(node);
          const nextTextHidden = style
            ? style.visibility === "hidden"
            : textHidden;
          return Array.from(node.childNodes || [])
            .map((child) => textFor(child, nextTextHidden))
            .join(" ");
        };
        return Array.from(element.childNodes || [])
          .map((child) => textFor(child))
          .join(" ")
          .replace(/\s+/g, " ")
          .trim();
      };
      const labelFor = (element) => {
        const tag = element.tagName.toLowerCase();
        if (tag === "input" || tag === "textarea" || tag === "select") {
          return (
            element.getAttribute("aria-label") ||
            element.getAttribute("placeholder") ||
            element.getAttribute("name") ||
            element.getAttribute("id") ||
            tag
          );
        }
        if (element.isContentEditable) {
          return (
            element.getAttribute("aria-label") ||
            editableTextFor(element) ||
            element.getAttribute("placeholder") ||
            element.getAttribute("name") ||
            element.getAttribute("id") ||
            tag
          );
        }
        return (
          element.getAttribute("aria-label") ||
          visibleTextFor(element) ||
          element.getAttribute("name") ||
          element.getAttribute("id") ||
          tag
        );
      };
      const inputTypes = new Set([
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
      ]);
      const implicitEnterSubmitInputTypes = new Set([
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
      ]);
      const implicitSubmitBlockingFieldCount = new WeakMap();
      const controlTypeFor = (element, tag) => {
        if (tag === "button") {
          const buttonType = String(element.getAttribute("type") || "").trim().toLowerCase();
          return buttonType === "button" || buttonType === "reset" ? buttonType : "submit";
        }
        if (tag === "input") {
          const inputType = String(element.getAttribute("type") || "").trim().toLowerCase();
          return inputTypes.has(inputType) ? inputType : "text";
        }
        return "";
      };
      const isSubmitControl = (tag, controlType) => {
        if (tag === "button") {
          return controlType === "submit";
        }
        if (tag === "input") {
          return controlType === "submit" || controlType === "image";
        }
        return false;
      };
      const isNativeDisabledControl = (element) =>
        Boolean(element.disabled) ||
        (typeof element.matches === "function" && element.matches(":disabled"));
      const elementForm = (element) => element.form || element.closest("form");
      const defaultSubmitterFor = (form) => {
        if (!form) {
          return null;
        }
        return (
          Array.from(document.querySelectorAll("button, input")).find((candidate) => {
            const tag = candidate.tagName.toLowerCase();
            return elementForm(candidate) === form && isSubmitControl(tag, controlTypeFor(candidate, tag));
          }) || null
        );
      };
      const isImplicitEnterSubmitField = (tag, controlType) =>
        tag === "input" && implicitEnterSubmitInputTypes.has(controlType);
      const implicitSubmitBlockingFieldCountFor = (form) => {
        if (!form) {
          return 0;
        }
        if (!implicitSubmitBlockingFieldCount.has(form)) {
          const count = Array.from(document.querySelectorAll("input")).filter((candidate) => {
            const tag = candidate.tagName.toLowerCase();
            return (
              elementForm(candidate) === form &&
              isImplicitEnterSubmitField(tag, controlTypeFor(candidate, tag))
            );
          }).length;
          implicitSubmitBlockingFieldCount.set(form, count);
        }
        return implicitSubmitBlockingFieldCount.get(form) || 0;
      };
      const canImplicitlySubmitFromField = (element, tag, controlType, form) =>
        elementForm(element) === form &&
        isImplicitEnterSubmitField(tag, controlType) &&
        implicitSubmitBlockingFieldCountFor(form) <= 1;
      const formMethodFor = (form, submitter) => {
        const raw =
          submitter && submitter.hasAttribute("formmethod")
            ? submitter.getAttribute("formmethod") || ""
            : form.getAttribute("method") || "";
        const method = String(raw || "").trim().toLowerCase();
        return method === "post" || method === "dialog" ? method : "get";
      };
      const formMetadataFor = (element, tag, controlType, form) => {
        if (!form) {
          return { action: "", method: "" };
        }
        const submitter = isSubmitControl(tag, controlType) ? element : defaultSubmitterFor(form);
        if (submitter && isNativeDisabledControl(submitter)) {
          return { action: "", method: "" };
        }
        if (!submitter && !canImplicitlySubmitFromField(element, tag, controlType, form)) {
          return { action: "", method: "" };
        }
        const action =
          submitter && submitter.hasAttribute("formaction")
            ? submitter.getAttribute("formaction") || ""
            : form.getAttribute("action") || "";
        const method =
          formMethodFor(form, submitter);
        return { action, method };
      };
      return Array.from(
        document.querySelectorAll("a, button, input, textarea, select, [contenteditable]"),
      ).filter((element) => {
        const tag = element.tagName.toLowerCase();
        return (
          isVisibleCandidate(element) &&
          (tag === "a" ||
            tag === "button" ||
            tag === "input" ||
            tag === "textarea" ||
            tag === "select" ||
            Boolean(element.isContentEditable))
        );
      }).map(
        (element) => {
          const tag = element.tagName.toLowerCase();
          const form = element.form || element.closest("form");
          const controlType = controlTypeFor(element, tag);
          const formMetadata = formMetadataFor(element, tag, controlType, form);
          return {
            kind: tag === "a" ? "link" : tag === "button" ? "button" : "field",
            label: labelFor(element),
            selector: selectorFor(element),
            href: tag === "a" ? element.getAttribute("href") || "" : "",
            control_type: controlType,
            form_action: formMetadata.action,
            form_method: formMetadata.method,
          };
        },
      );
    },
    "snapshot",
  );
}

async function firstLocator(page, target) {
  const locator = page.locator(target);
  if (typeof locator.count === "function" && (await locator.count()) < 1) {
    throw new Error(`unknown target: ${target}`);
  }
  if (typeof locator.filter === "function") {
    const visible = locator.filter({ visible: true });
    if (typeof visible.count === "function" && (await visible.count()) > 0) {
      return visible.first();
    }
  }
  return locator.first();
}

function clearFieldState(state) {
  state.fields = {};
  state.fields_url = "";
}

function dropFieldState(state, selector) {
  const nextFields = { ...(state.fields || {}) };
  delete nextFields[selector];
  state.fields = nextFields;
  if (Object.keys(nextFields).length === 0) {
    state.fields_url = "";
  }
}

async function applyFieldState(page, state) {
  if (!state.fields_url || state.fields_url !== state.current_url) {
    clearFieldState(state);
    return;
  }
  for (const [selector, value] of Object.entries(state.fields || {})) {
    try {
      const locator = await firstLocator(page, selector);
      await locator.fill(String(value));
    } catch {
      // The page changed; stale field state should not block read-only actions.
    }
  }
}

async function syncFieldState(page, state) {
  const selectors = Object.keys(state.fields || {});
  if (selectors.length === 0) {
    clearFieldState(state);
    return;
  }
  const nextFields = {};
  for (const selector of selectors) {
    let value = "";
    let readable = false;
    try {
      const locator = await firstLocator(page, selector);
      if (typeof locator.inputValue === "function") {
        try {
          value = await locator.inputValue({ timeout: Math.min(timeoutMs(), 1000) });
          readable = true;
        } catch {
          value = "";
        }
      }
      if (!String(value || "") && typeof locator.evaluate === "function") {
        value = await locator.evaluate((element) => {
          if (element && "value" in element) {
            return String(element.value || "");
          }
          if (element && element.isContentEditable) {
            const blockTextTags = new Set([
              "address",
              "article",
              "aside",
              "blockquote",
              "div",
              "dl",
              "fieldset",
              "figcaption",
              "figure",
              "footer",
              "form",
              "h1",
              "h2",
              "h3",
              "h4",
              "h5",
              "h6",
              "header",
              "li",
              "main",
              "nav",
              "ol",
              "p",
              "pre",
              "section",
              "table",
              "ul",
            ]);
            const computedStyleFor = (item) =>
              typeof window !== "undefined" && typeof window.getComputedStyle === "function"
                ? window.getComputedStyle(item)
                : null;
            const elementTextState = (node, textHidden) => {
              const attrValue = node.getAttribute("contenteditable");
              const tag = node.tagName.toLowerCase();
              const style = computedStyleFor(node);
              const suppressed =
                (attrValue !== null && String(attrValue).toLowerCase() === "false") ||
                tag === "script" ||
                tag === "style" ||
                node.hidden ||
                (style && (style.display === "none" || style.opacity === "0"));
              const nextTextHidden = style
                ? style.visibility === "hidden"
                : textHidden;
              return { tag, suppressed, nextTextHidden };
            };
            const stripSyntheticTrailingBreak = (result) =>
              result.syntheticTrailingBreak ? result.text.slice(0, -1) : result.text;
            const textForChildren = (children, textHidden) => {
              let text = "";
              let syntheticTrailingBreak = false;
              for (const child of children) {
                const childState = child.nodeType === 1 ? elementTextState(child, textHidden) : null;
                const childIsVisibleBlock = Boolean(
                  childState &&
                    !childState.suppressed &&
                    !childState.nextTextHidden &&
                    blockTextTags.has(childState.tag),
                );
                const childText = textFor(child, textHidden);
                if (!childText) {
                  if (childIsVisibleBlock && text && !text.endsWith("\n")) {
                    text += "\n";
                    syntheticTrailingBreak = false;
                  }
                  continue;
                }
                if (childIsVisibleBlock && text && !text.endsWith("\n")) {
                  text += "\n";
                  syntheticTrailingBreak = false;
                }
                text += childText;
                syntheticTrailingBreak = false;
                if (childIsVisibleBlock && !text.endsWith("\n")) {
                  text += "\n";
                  syntheticTrailingBreak = true;
                }
              }
              return { text, syntheticTrailingBreak };
            };
            const textFor = (node, textHidden = false) => {
              if (!node) {
                return "";
              }
              if (node.nodeType === 3) {
                return textHidden ? "" : node.textContent || "";
              }
              if (node.nodeType !== 1) {
                return "";
              }
              const { tag, suppressed, nextTextHidden } = elementTextState(node, textHidden);
              if (suppressed) {
                return "";
              }
              if (tag === "br") {
                return nextTextHidden ? "" : "\n";
              }
              return stripSyntheticTrailingBreak(
                textForChildren(Array.from(node.childNodes || []), nextTextHidden),
              );
            };
            const editableText = stripSyntheticTrailingBreak(
              textForChildren(Array.from(element.childNodes || []), false),
            );
            if (/^\n*$/u.test(editableText)) {
              return "";
            }
            return String(editableText);
          }
          return "";
        });
        readable = true;
      }
      if (readable) {
        nextFields[selector] = String(value);
      }
    } catch {
      // Missing/non-input selectors are dropped from replay state.
    }
  }
  state.fields = nextFields;
  state.fields_url = Object.keys(nextFields).length > 0 ? state.current_url : "";
}

async function withPage(cwd, session, state, action, options = {}) {
  const loadCurrentUrl = options.loadCurrentUrl !== false;
  const restoreFields = options.restoreFields !== false;
  const { chromium } = loadPlaywright();
  if (!chromium || typeof chromium.launchPersistentContext !== "function") {
    throw new Error("@playwright/test did not expose chromium.launchPersistentContext");
  }
  await fs.mkdir(profilePath(cwd, session), { recursive: true });
  const context = await chromium.launchPersistentContext(profilePath(cwd, session), {
    headless: process.env.SHISAD_PLAYWRIGHT_HEADLESS !== "0",
    viewport: { width: 1280, height: 900 },
    });
  try {
    const pages = typeof context.pages === "function" ? context.pages() : [];
    const page = pages[0] || (await context.newPage());
    const beforeUrl = state.current_url;
    if (loadCurrentUrl && state.current_url) {
      await goto(page, state.current_url);
      if (restoreFields) {
        await applyFieldState(page, state);
      }
    }
    await action(page);
    state.opened = true;
    state.current_url = typeof page.url === "function" ? page.url() : state.current_url;
    if (beforeUrl && state.current_url !== beforeUrl) {
      clearFieldState(state);
    } else {
      await syncFieldState(page, state);
    }
    await saveState(cwd, session, state);
  } finally {
    await context.close();
  }
}

async function main() {
  const parsed = parseArgv(process.argv.slice(2));
  if (parsed.probe === "version") {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (parsed.probe === "doctor") {
    const { chromium } = loadPlaywright();
    if (!chromium || typeof chromium.launchPersistentContext !== "function") {
      throw new Error("@playwright/test did not expose chromium.launchPersistentContext");
    }
    process.stdout.write(`${DOCTOR_OK}\n`);
    return 0;
  }
  if (parsed.probe === "help") {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }
  const cwd = process.cwd();
  const state = await loadState(cwd, parsed.session);
  const args = [...parsed.args];

  switch (parsed.command) {
    case "open": {
      state.opened = true;
      const url = args[0] || "";
      if (url) {
        await withPage(cwd, parsed.session, state, (page) => goto(page, url), {
          loadCurrentUrl: false,
          restoreFields: false,
        });
      } else {
        await saveState(cwd, parsed.session, state);
      }
      return 0;
    }
    case "goto": {
      requireOpened(state);
      const url = args[0];
      if (!url) {
        throw new Error("goto requires url");
      }
      await withPage(cwd, parsed.session, state, (page) => goto(page, url), {
        loadCurrentUrl: false,
        restoreFields: false,
      });
      return 0;
    }
    case "eval": {
      requireOpened(state);
      const filename = extractOption(args, "--filename");
      await withPage(cwd, parsed.session, state, async (page) => {
        await writeOutput(filename, `${JSON.stringify(await metadata(page))}\n`);
      });
      return 0;
    }
    case "snapshot": {
      requireOpened(state);
      const filename = extractOption(args, "--filename");
      await withPage(cwd, parsed.session, state, async (page) => {
        await writeOutput(filename, snapshotLines(await snapshot(page)));
      });
      return 0;
    }
    case "fill": {
      requireOpened(state);
      const target = args.shift();
      if (!target) {
        throw new Error("fill requires target");
      }
      const text = args.shift() || "";
      let submit = false;
      let clickTarget = "";
      let storeField = true;
      for (let index = 0; index < args.length; index += 1) {
        const option = args[index];
        if (option === "--submit") {
          submit = true;
        } else if (option === "--click") {
          clickTarget = args[index + 1] || "";
          if (!clickTarget) {
            throw new Error("fill --click requires target");
          }
          index += 1;
        } else if (option === "--no-store") {
          storeField = false;
        } else {
          throw new Error(`unsupported fill option: ${option}`);
        }
      }
      if (submit && clickTarget) {
        throw new Error("fill accepts --submit or --click, not both");
      }
      if (!storeField) {
        dropFieldState(state, target);
        await saveState(cwd, parsed.session, state);
      }
      await withPage(cwd, parsed.session, state, async (page) => {
        const locator = await firstLocator(page, target);
        await locator.fill(String(text));
        if (storeField) {
          state.fields = { ...(state.fields || {}), [target]: String(text) };
          state.fields_url = state.current_url;
        } else {
          dropFieldState(state, target);
        }
        if (submit && typeof locator.press === "function") {
          await locator.press("Enter");
          await waitForSettled(page);
        } else if (clickTarget) {
          const clickLocator = await firstLocator(page, clickTarget);
          await clickLocator.click();
          await waitForSettled(page);
        }
      });
      return 0;
    }
    case "click": {
      requireOpened(state);
      const target = args[0];
      if (!target) {
        throw new Error("click requires target");
      }
      await withPage(cwd, parsed.session, state, async (page) => {
        const locator = await firstLocator(page, target);
        await locator.click();
        await waitForSettled(page);
      });
      return 0;
    }
    case "screenshot": {
      requireOpened(state);
      const filename = extractOption(args, "--filename");
      if (!filename) {
        throw new Error("screenshot requires --filename");
      }
      await withPage(cwd, parsed.session, state, async (page) => {
        if (typeof page.screenshot === "function") {
          await page.screenshot({ path: filename, fullPage: true, timeout: timeoutMs() });
        } else {
          await fs.writeFile(filename, Buffer.from(PNG_1X1_BASE64, "base64"));
        }
      });
      return 0;
    }
    case "list": {
      await fs.mkdir(storageRoot(cwd), { recursive: true });
      const entries = await fs.readdir(storageRoot(cwd));
      const sessions = entries
        .filter((entry) => entry.endsWith(".json"))
        .map((entry) => entry.slice(0, -5))
        .sort();
      if (sessions.length > 0) {
        process.stdout.write(`${sessions.join("\n")}\n`);
      }
      return 0;
    }
    case "close": {
      await fs.rm(statePath(cwd, parsed.session), { force: true });
      await fs.rm(profilePath(cwd, parsed.session), { force: true, recursive: true });
      return 0;
    }
    default:
      throw new Error(parsed.command ? `unsupported browser command: ${parsed.command}` : "command required");
  }
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
