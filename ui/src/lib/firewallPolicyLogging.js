/**
 * Shared firewall policy logging helpers.
 *
 * Used by both FirewallRules.jsx (matrix toggle) and LogDetail.jsx (row toggle)
 * to avoid duplicating controllability checks and confirmation copy.
 */

/** Whether a policy can have its logging toggled. */
export function isControllablePolicy(policy) {
  if (!policy) return false
  if (policy.metadata?.origin === 'DERIVED') return false
  if (policy.enabled === false) return false
  return true
}

/** Warning text shared by both FirewallRules bulk confirm and LogDetail single confirm. */
export const SYSLOG_DELAY_WARNING =
  'Changes are applied immediately on the UniFi Gateway but may take up to 5 minutes to reflect in the Log Stream.'

const _RULE_NAME_RE = /^(.+?)-(A|D|R)-(\d+)$/
const _ACTION_LABELS = { 'A': 'Allow', 'D': 'Drop', 'R': 'Reject' }

/** Parse a syslog rule_name into {chain, actionCode, action, priority} or null. */
export function parseRuleName(ruleName) {
  if (!ruleName) return null
  const m = ruleName.match(_RULE_NAME_RE)
  if (!m) return null
  return {
    chain: m[1],
    actionCode: m[2],
    action: _ACTION_LABELS[m[2]] || m[2],
    priority: parseInt(m[3], 10),
  }
}
