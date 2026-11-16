import type {
  CapabilityDecision,
  CapabilityDecisionMap,
  CapabilityRisk,
  ToolCapabilityId,
  ToolScanReport,
  ToolSecuritySettings
} from './types'
import { TOOL_CAPABILITY_IDS } from './types'

export interface CapabilityInfo {
  id: ToolCapabilityId
  risk: CapabilityRisk
  /** Short label, as shown on an app-store permission list. */
  label: string
  /** One sentence in plain language. */
  description: string
  /** Whether a decision gates running the tool (informational otherwise). */
  gating: boolean
}

export const CAPABILITY_CATALOG: Record<ToolCapabilityId, CapabilityInfo> = {
  network: {
    id: 'network',
    risk: 'medium',
    label: 'Internet and network access',
    description:
      'Can send and receive data over the network, including to servers you did not choose.',
    gating: true
  },
  'fs-read': {
    id: 'fs-read',
    risk: 'low',
    label: 'Read files',
    description: 'Can read files on this computer that your user account can read.',
    gating: true
  },
  'fs-write': {
    id: 'fs-write',
    risk: 'medium',
    label: 'Create, change or delete files',
    description: 'Can modify or remove files on this computer.',
    gating: true
  },
  process: {
    id: 'process',
    risk: 'high',
    label: 'Run programs and shell commands',
    description:
      'Can start other programs with your permissions, which can do anything you can do.',
    gating: true
  },
  env: {
    id: 'env',
    risk: 'medium',
    label: 'Read environment variables',
    description: 'Can read environment variables, which often contain API keys and tokens.',
    gating: true
  },
  secrets: {
    id: 'secrets',
    risk: 'critical',
    label: 'Access credentials',
    description:
      'References SSH keys, cloud or package-registry credentials, browser data or keychains.',
    gating: true
  },
  'dynamic-code': {
    id: 'dynamic-code',
    risk: 'high',
    label: 'Run code generated at runtime',
    description:
      'Uses eval, new Function or dynamic imports, so what runs cannot be fully reviewed.',
    gating: true
  },
  native: {
    id: 'native',
    risk: 'high',
    label: 'Native binaries',
    description: 'Ships or loads compiled native code that this scanner cannot inspect.',
    gating: true
  },
  'install-script': {
    id: 'install-script',
    risk: 'high',
    label: 'Runs scripts during installation',
    description:
      'Defines npm lifecycle scripts that would run as soon as the package is installed.',
    gating: false
  },
  'load-time': {
    id: 'load-time',
    risk: 'medium',
    label: 'Runs code when loaded',
    description:
      'Does work as soon as Pi loads it, before you use any of its tools (session start, event hooks).',
    gating: false
  },
  obfuscated: {
    id: 'obfuscated',
    risk: 'high',
    label: 'Hidden or encoded code',
    description: 'Contains large encoded or obfuscated blobs that hide what the code does.',
    gating: true
  },
  'untrusted-output': {
    id: 'untrusted-output',
    risk: 'medium',
    label: 'Brings outside data into the conversation',
    description:
      'Returns content from outside sources. It is tracked as untrusted, and later actions that could send data out are checked.',
    gating: false
  }
}

export const RISK_ORDER: Record<CapabilityRisk, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3
}

export function defaultDecisionForRisk(risk: CapabilityRisk): CapabilityDecision {
  return risk === 'critical' ? 'block' : risk === 'low' ? 'allow' : 'ask'
}

export function defaultToolSecuritySettings(): ToolSecuritySettings {
  const capabilityDefaults = Object.fromEntries(
    TOOL_CAPABILITY_IDS.map((id) => [id, defaultDecisionForRisk(CAPABILITY_CATALOG[id].risk)])
  ) as Record<ToolCapabilityId, CapabilityDecision>
  capabilityDefaults['untrusted-output'] = 'allow'
  capabilityDefaults['load-time'] = 'allow'
  capabilityDefaults['install-script'] = 'block'
  return {
    schemaVersion: 1,
    capabilityDefaults,
    unreviewedTools: 'ask',
    requireReviewBeforeInstall: true,
    blockInstallScripts: true,
    quarantineDangerous: true,
    provenance: {
      enabled: true,
      workspaceFilesUntrusted: true,
      sinkWhenTainted: 'ask',
      untrustedArgument: 'block'
    },
    camel: { enabled: false, model: null }
  }
}

const DECISION_RANK: Record<CapabilityDecision, number> = { allow: 0, ask: 1, block: 2 }

export function strictestDecision(decisions: Iterable<CapabilityDecision>): CapabilityDecision {
  let worst: CapabilityDecision = 'allow'
  for (const decision of decisions)
    if (DECISION_RANK[decision] > DECISION_RANK[worst]) worst = decision
  return worst
}

/** Decisions to pre-fill on the install screen. Critical findings push their capability to block. */
export function suggestedDecisions(
  report: ToolScanReport,
  settings: ToolSecuritySettings
): CapabilityDecisionMap {
  const suggested: CapabilityDecisionMap = {}
  for (const capability of report.capabilities) {
    if (!CAPABILITY_CATALOG[capability].gating) continue
    suggested[capability] = settings.capabilityDefaults[capability]
  }
  for (const finding of report.findings) {
    if (
      finding.severity === 'critical' &&
      finding.capability &&
      CAPABILITY_CATALOG[finding.capability].gating
    )
      suggested[finding.capability] = 'block'
  }
  return suggested
}

export function capabilityRiskOf(capabilities: Iterable<ToolCapabilityId>): CapabilityRisk {
  let worst: CapabilityRisk = 'low'
  for (const id of capabilities)
    if (RISK_ORDER[CAPABILITY_CATALOG[id].risk] > RISK_ORDER[worst])
      worst = CAPABILITY_CATALOG[id].risk
  return worst
}
