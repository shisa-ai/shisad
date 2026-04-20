/**
 * Format an IntentEnvelope for signing on a Ledger device.
 *
 * - buildTypedData() produces an EIP-712 typed-data structure for signTypedData.
 *   The device renders labeled fields with Clear Signing support.
 * - formatForDevice() produces a plain-text summary for logging/debug.
 */

export interface IntentAction {
  tool: string;
  display_summary: string;
  parameters: Record<string, unknown>;
  destinations: string[];
}

export interface IntentPolicyContext {
  required_level: string;
  confirmation_reason: string;
  matched_rule: string;
  action_digest: string;
}

export interface IntentEnvelope {
  schema_version: string;
  intent_id: string;
  agent_id: string;
  workspace_id: string;
  session_id: string;
  created_at: string;
  expires_at: string | null;
  action: IntentAction;
  policy_context: IntentPolicyContext;
  nonce: string;
}

/**
 * EIP-712 typed-data payload for Ledger signTypedData.
 *
 * Keep type definitions in sync with the daemon-side EIP-712 digest
 * computation in src/shisad/core/approval.py::_EIP712_TYPES.
 */
export function buildTypedData(envelope: IntentEnvelope, fullIntentHash: string) {
  return {
    domain: {
      name: "shisad",
      version: "1",
      chainId: 0,
    },
    types: {
      EIP712Domain: [
        { name: "name", type: "string" },
        { name: "version", type: "string" },
        { name: "chainId", type: "uint256" },
      ],
      IntentAction: [
        { name: "tool", type: "string" },
        { name: "summary", type: "string" },
        { name: "destinations", type: "string" },
      ],
      PolicyContext: [
        { name: "level", type: "string" },
        { name: "digest", type: "string" },
      ],
      IntentEnvelope: [
        { name: "intentId", type: "string" },
        { name: "action", type: "IntentAction" },
        { name: "policy", type: "PolicyContext" },
        { name: "fullIntentHash", type: "string" },
        { name: "nonce", type: "string" },
      ],
    },
    primaryType: "IntentEnvelope",
    message: {
      intentId: envelope.intent_id,
      action: {
        tool: envelope.action.tool,
        summary: envelope.action.display_summary,
        destinations: envelope.action.destinations.join(", ") || "[none]",
      },
      policy: {
        level: envelope.policy_context.required_level,
        digest: envelope.policy_context.action_digest,
      },
      fullIntentHash,
      nonce: envelope.nonce,
    },
  };
}

/**
 * Plain-text summary for logging / debug. Not used for signing.
 */
export function formatForDevice(envelope: IntentEnvelope, fullIntentHash = ""): string {
  const { action, policy_context, intent_id } = envelope;
  const destinations =
    action.destinations.length > 0
      ? action.destinations.join(", ")
      : "[none]";

  return [
    "[shisad] Approve Action",
    `Tool: ${action.tool}`,
    `Action: ${action.display_summary}`,
    `Risk: ${policy_context.required_level}`,
    `Dest: ${destinations}`,
    `Intent: ${intent_id}`,
    ...(fullIntentHash ? [`Intent Hash: ${fullIntentHash}`] : []),
  ].join("\n");
}
