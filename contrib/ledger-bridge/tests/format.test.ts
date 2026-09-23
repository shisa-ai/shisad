import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { buildTypedData, formatForDevice, type IntentEnvelope } from "../src/format";

function referenceEnvelope(): IntentEnvelope {
  return {
    schema_version: "shisad.intent.v1",
    intent_id: "intent-ledger-1",
    agent_id: "daemon-1",
    workspace_id: "workspace-1",
    session_id: "session-1",
    created_at: "2026-04-10T12:00:00Z",
    expires_at: "2026-04-10T12:05:00Z",
    action: {
      tool: "deploy.production",
      display_summary: "Deploy v2.1.0 to production cluster",
      parameters: { version: "2.1.0", target: "prod" },
      destinations: ["deploy.example.com"],
    },
    policy_context: {
      required_level: "trusted_display_authorization",
      confirmation_reason: "deploy.production requires trusted-display",
      matched_rule: "deploy.production",
      action_digest: "sha256:action-ledger",
    },
    nonce: "b64:intent-nonce-ledger",
  };
}

describe("EIP-712 typed-data formatting", () => {
  it("binds the canonical full-intent hash while keeping readable fields", () => {
    const typedData = buildTypedData(
      referenceEnvelope(),
      "sha256:94f0e3e648c007a6069c42ca5df7f2386a9621b5264aac70f4228ea51a4276b7",
    );

    assert.deepEqual(typedData.types.IntentEnvelope, [
      { name: "intentId", type: "string" },
      { name: "action", type: "IntentAction" },
      { name: "policy", type: "PolicyContext" },
      { name: "fullIntentHash", type: "string" },
      { name: "nonce", type: "string" },
    ]);
    assert.equal(
      typedData.message.fullIntentHash,
      "sha256:94f0e3e648c007a6069c42ca5df7f2386a9621b5264aac70f4228ea51a4276b7",
    );
  });

  it("includes the full-intent hash in the operator-facing debug summary", () => {
    const rendered = formatForDevice(
      referenceEnvelope(),
      "sha256:94f0e3e648c007a6069c42ca5df7f2386a9621b5264aac70f4228ea51a4276b7",
    );

    assert.match(rendered, /Intent: intent-ledger-1/);
    assert.match(rendered, /Intent Hash: sha256:94f0e3e648c007a6069c42ca5df7f2386a9621b5264aac70f4228ea51a4276b7/);
  });
});


it("clear-signing descriptor matches the signed domain, types and all leaf fields", () => {
  const descriptor = JSON.parse(readFileSync(new URL("../clear-signing/eip712-shisad.json", import.meta.url), "utf8"));
  const typed = buildTypedData(referenceEnvelope(), "sha256:canonical-intent");
  assert.deepEqual(descriptor.context.eip712.domain, typed.domain);
  assert.deepEqual(descriptor.context.eip712.schemas, [{primaryType: typed.primaryType, types: typed.types}]);
  const format = descriptor.display.formats.IntentEnvelope;
  const leaves = (obj: Record<string, unknown>, prefix = ""): string[] =>
    Object.entries(obj).flatMap(([key, value]) => {
      const path = prefix ? `${prefix}.${key}` : key;
      return typeof value === "object" && value !== null
        ? leaves(value as Record<string, unknown>, path) : [path];
    });
  assert.deepEqual(format.fields.map((field: {path: string}) => field.path).sort(), leaves(typed.message).sort());
  assert.deepEqual([...format.required].sort(), leaves(typed.message).sort());
  assert.deepEqual(format.excluded, []);
});
