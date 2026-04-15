/**
 * Format an IntentEnvelope's action into a human-readable summary for the
 * Ledger device screen.  On Stax/Flex the full text is rendered; on Nano
 * devices the user scrolls through the fields.
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
 * Produce the message string that the Ledger device will display and sign
 * via Ethereum personal_sign.
 */
export function formatForDevice(envelope: IntentEnvelope): string {
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
  ].join("\n");
}
