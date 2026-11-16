/**
 * Tool security: capability manifests, scan reports, per-tool decisions,
 * provenance (taint) tracking and the opt-in CaMeL secure planner.
 *
 * Shared by Main (enforcement) and Renderer (review UI). Main is the only
 * authority: the renderer displays these values and requests changes over
 * validated IPC, but never decides whether a tool may run.
 */

export const TOOL_CAPABILITY_IDS = [
  'network',
  'fs-read',
  'fs-write',
  'process',
  'env',
  'secrets',
  'dynamic-code',
  'native',
  'install-script',
  'load-time',
  'obfuscated',
  'untrusted-output'
] as const

export type ToolCapabilityId = (typeof TOOL_CAPABILITY_IDS)[number]

export type CapabilityRisk = 'low' | 'medium' | 'high' | 'critical'

/** What happens before a tool with this capability runs. */
export type CapabilityDecision = 'allow' | 'ask' | 'block'

export const CAPABILITY_DECISIONS: readonly CapabilityDecision[] = ['allow', 'ask', 'block']

export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface ScanFinding {
  /** Stable rule id, e.g. `network.fetch`, `exfil.webhook-host`. */
  rule: string
  severity: FindingSeverity
  capability?: ToolCapabilityId
  title: string
  /** Plain-language explanation of why this matters. */
  detail: string
  file?: string
  line?: number
  /** Short source excerpt (redacted, at most 160 characters). */
  snippet?: string
  /** Tool the evidence belongs to; absent for package-level code. */
  tool?: string
}

export interface ScannedTool {
  name: string
  capabilities: ToolCapabilityId[]
}

export interface PackageManifestSummary {
  name: string | null
  version: string | null
  description: string | null
  author: string | null
  license: string | null
  repository: string | null
  homepage: string | null
}

/**
 * Optional capability manifest a package can declare in package.json:
 *
 * ```json
 * "piHarness": {
 *   "capabilities": ["network", "env"],
 *   "network": ["api.example.com"],
 *   "env": ["EXAMPLE_API_KEY"],
 *   "tools": { "weather_lookup": { "capabilities": ["network", "untrusted-output"] } }
 * }
 * ```
 */
export interface DeclaredCapabilities {
  capabilities: ToolCapabilityId[]
  network: string[]
  env: string[]
  tools: Record<string, ToolCapabilityId[]>
}

export type ScanVerdict = 'clean' | 'review' | 'dangerous'

export interface ToolScanReport {
  /** sha256 over the package's code and manifest (dependencies excluded). */
  digest: string
  scannedAt: string
  manifest: PackageManifestSummary
  declared: DeclaredCapabilities | null
  /** Capabilities found anywhere in the package (union of tools and load-time code). */
  capabilities: ToolCapabilityId[]
  /** Detected capabilities the manifest did not declare (empty when no manifest). */
  undeclared: ToolCapabilityId[]
  tools: ScannedTool[]
  networkHosts: string[]
  envVars: string[]
  installScripts: Record<string, string>
  findings: ScanFinding[]
  verdict: ScanVerdict
  files: number
  truncated: boolean
  /** Present after install when node_modules were scanned. */
  dependencies?: {
    packages: number
    capabilities: ToolCapabilityId[]
    findings: ScanFinding[]
    verdict: ScanVerdict
  }
}

export type ToolPackageStatus = 'approved' | 'unreviewed' | 'changed' | 'blocked'

export type CapabilityDecisionMap = Partial<Record<ToolCapabilityId, CapabilityDecision>>

/** A reviewed (or discovered) package that provides Pi tools. */
export interface ToolPackageRecord {
  /** Package identity (`npm:name`, `git:host/path`, `local:/path`). */
  id: string
  source: string
  status: ToolPackageStatus
  /** Digest the user approved; differs from `report.digest` when the code changed. */
  approvedDigest: string | null
  approvedAt: string | null
  allowInstallScripts: boolean
  /** Package-wide decisions, then per-tool overrides keyed by tool name. */
  decisions: CapabilityDecisionMap
  toolDecisions: Record<string, CapabilityDecisionMap>
  report: ToolScanReport | null
  installPath: string | null
  /** Pi package scope, needed to disable or re-enable the package. */
  scope?: 'global' | 'project'
  /** Disabled automatically because an unreviewed package showed malicious indicators. */
  quarantined?: boolean
}

export interface ProvenanceSettings {
  /** Track which data in a session came from untrusted sources. */
  enabled: boolean
  /** Treat workspace file contents (read/grep/bash output) as untrusted. */
  workspaceFilesUntrusted: boolean
  /** Exfiltration-capable actions after untrusted data entered the session. */
  sinkWhenTainted: CapabilityDecision
  /** Exfiltration-capable actions whose arguments contain untrusted data. */
  untrustedArgument: CapabilityDecision
}

export interface CamelSettings {
  /** Opt-in: plan with a privileged model that never sees tool outputs. */
  enabled: boolean
  /** Model override for planning/extraction; null uses the active model. */
  model: { providerKey: string; modelId: string } | null
}

export interface ToolSecuritySettings {
  schemaVersion: 1
  capabilityDefaults: Record<ToolCapabilityId, CapabilityDecision>
  /** Tools from packages nobody reviewed, or whose code changed since review. */
  unreviewedTools: CapabilityDecision
  /** Packages installed from the app must be reviewed first. */
  requireReviewBeforeInstall: boolean
  /** Block npm lifecycle scripts during install unless the package was approved with them. */
  blockInstallScripts: boolean
  /** Disable unreviewed packages whose scan finds malicious indicators, so their code never loads. */
  quarantineDangerous: boolean
  provenance: ProvenanceSettings
  camel: CamelSettings
}

export interface ToolInstallPreview {
  /** Opaque, short-lived token bound to this exact source and digest. */
  token: string
  source: string
  scope: 'global' | 'project'
  projectRoot: string | null
  packageId: string
  report: ToolScanReport
  /** Suggested decisions from the current defaults and the report. */
  suggested: CapabilityDecisionMap
  existing: ToolPackageRecord | null
  expiresAt: string
}

export interface ToolInstallApproval {
  token: string
  decisions: CapabilityDecisionMap
  allowInstallScripts: boolean
  /** Required when the verdict is `dangerous`. */
  acknowledgeDanger: boolean
}

export interface ToolSecurityOverview {
  settings: ToolSecuritySettings
  packages: ToolPackageRecord[]
}

// --------------------------------------------------------------- provenance

export interface ProvenanceSource {
  /** e.g. `tool:weather_lookup`, `file:notes.md`, `url:https://…` */
  label: string
  kind: 'tool' | 'file' | 'command' | 'url' | 'extraction'
  at: number
}

export interface ProvenanceStatus {
  sessionId: string
  tainted: boolean
  sources: ProvenanceSource[]
}

// --------------------------------------------------------------- CaMeL

export type CamelValue =
  | string
  | number
  | boolean
  | null
  | { ref: string; field?: string }
  | { concat: CamelValue[] }
  | { list: CamelValue[] }

export type CamelFieldType =
  'string' | 'number' | 'boolean' | { enum: string[] } | { list: 'string' }

export interface CamelToolStep {
  id: string
  tool: string
  args: Record<string, CamelValue>
}

export interface CamelExtractStep {
  id: string
  extract: {
    from: CamelValue
    instructions: string
    schema: Record<string, CamelFieldType>
  }
}

export type CamelStep = CamelToolStep | CamelExtractStep

export interface CamelPlan {
  goal: string
  steps: CamelStep[]
  output: CamelValue
}

export interface CamelPlanResult {
  planId: string
  plan: CamelPlan
  cwd: string
  model: string
}

export type CamelStepStatus = 'pending' | 'running' | 'done' | 'blocked' | 'failed' | 'skipped'

export interface CamelStepEvent {
  runId: string
  planId: string
  stepId: string
  status: CamelStepStatus
  /** Labels of the sources the step's result depends on. */
  sources: string[]
  trusted: boolean
  preview?: string
  reason?: string
}

export interface CamelRunResult {
  runId: string
  planId: string
  status: 'completed' | 'blocked' | 'failed'
  output: { text: string; sources: string[]; trusted: boolean } | null
  steps: CamelStepEvent[]
  error?: string
}

// --------------------------------------------------------------- renderer API

export interface ToolSecurityAPI {
  overview(): Promise<ToolSecurityOverview>
  updateSettings(settings: ToolSecuritySettings): Promise<ToolSecuritySettings>
  preview(input: {
    source: string
    scope: 'global' | 'project'
    projectRoot?: string | null
  }): Promise<ToolInstallPreview>
  approve(input: ToolInstallApproval): Promise<{ packageId: string }>
  setDecision(input: {
    packageId: string
    tool: string | null
    capability: ToolCapabilityId
    decision: CapabilityDecision | null
  }): Promise<ToolPackageRecord>
  approveInstalled(packageId: string): Promise<ToolPackageRecord>
  setBlocked(packageId: string, blocked: boolean): Promise<ToolPackageRecord>
  provenance(sessionId: string): Promise<ProvenanceStatus>
  camelPlan(input: { query: string; cwd: string }): Promise<CamelPlanResult>
  camelRun(planId: string): Promise<CamelRunResult>
  onCamelStep(listener: (event: CamelStepEvent) => void): () => void
}
