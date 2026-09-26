import { it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, copyFileSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

function buildInput(envToken?: string, localToken?: string) {
  const root = mkdtempSync(join(tmpdir(), "ledger-token-"));
  try {
    mkdirSync(join(root, "scripts"));
    copyFileSync(resolve("scripts/inject-origin-token.mjs"), join(root, "scripts/inject-origin-token.mjs"));
    if (localToken) writeFileSync(join(root, ".env.local"), `SHISAD_LEDGER_ORIGIN_TOKEN=${localToken}\n`);
    const env = { ...process.env };
    delete env.SHISAD_LEDGER_ORIGIN_TOKEN;
    if (envToken !== undefined) env.SHISAD_LEDGER_ORIGIN_TOKEN = envToken;
    const result = spawnSync(process.execPath, [join(root, "scripts/inject-origin-token.mjs")], { env, encoding: "utf8" });
    const source = result.status === 0 ? readFileSync(join(root, "src/generated/origin-token.ts"), "utf8") : "";
    return { ...result, source };
  } finally { rmSync(root, { recursive: true, force: true }); }
}

it("rejects missing build input instead of producing a tokenless bridge", () => {
  const result = buildInput();
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /SHISAD_LEDGER_ORIGIN_TOKEN/);
});
it("injects the application token without logging its value", () => {
  const result = buildInput("test-application-token");
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.source, /test-application-token/);
  assert.ok(!`${result.stdout}${result.stderr}`.includes("test-application-token"));
});
it("uses local build input with environment taking precedence", () => {
  assert.match(buildInput(undefined, "local-fixture").source, /local-fixture/);
  assert.match(buildInput("override-fixture", "local-fixture").source, /override-fixture/);
});
it("compiled signer receives the embedded token without runtime configuration", () => {
  const env = { ...process.env };
  delete env.SHISAD_LEDGER_ORIGIN_TOKEN;
  const result = spawnSync(process.execPath, ["--import", "tsx", "-e", `
    const { SignerEthBuilder } = require('@ledgerhq/device-signer-kit-ethereum');
    const { APPLICATION_ORIGIN_TOKEN } = require('./dist/generated/origin-token.js');
    const { buildEthSigner } = require('./dist/device.js');
    let ok = false;
    SignerEthBuilder.prototype.build = function () {
      ok = Boolean(APPLICATION_ORIGIN_TOKEN) && this._originToken === APPLICATION_ORIGIN_TOKEN;
      return {};
    };
    buildEthSigner({}, 'build-test');
    if (!ok) throw new Error('Embedded token did not reach SDK');
  `], { env, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});
it("packages the compiled token and pinned dependencies without the local input", () => {
  const result = spawnSync("npm", ["pack", "--ignore-scripts", "--dry-run", "--json"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const files = new Set(JSON.parse(result.stdout)[0].files.map((f: { path: string }) => f.path));
  assert.ok(files.has("dist/generated/origin-token.js"));
  assert.ok(files.has("npm-shrinkwrap.json"));
  assert.ok(!files.has(".env.local"));
  assert.ok(!files.has("src/generated/origin-token.ts"));
});
