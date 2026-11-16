/**
 * Tool security service: review before install, approvals bound to a code
 * digest, per-capability decisions, and the index the runtime guard consults.
 *
 * The store is the single source of truth. Approvals are keyed by package
 * identity (independent of scope) and only hold while the installed code still
 * matches the approved digest; any change makes the package "changed" and its
 * tools fall back to the unreviewed-tool decision until it is reviewed again.
 */

import { randomBytes } from 'node:crypto'
import path from 'node:path'
import {
  CAPABILITY_CATALOG,
  defaultToolSecuritySettings,
  strictestDecision,
  suggestedDecisions
} from '@shared/tool-security/catalog'
import { toolSecuritySettingsSchema } from '@shared/tool-security/schema'
import type {
  CapabilityDecision,
  CapabilityDecisionMap,
  ToolCapabilityId,
  ToolInstallApproval,
  ToolInstallPreview,
  ToolPackageRecord,
  ToolScanReport,
  ToolSecurityOverview,
  ToolSecuritySettings
} from '@shared/tool-security/types'
import type { PiPackageInfo, PiPackageTarget } from '@shared/ipc/api-types'
import { packageIdentity } from '../packages/package-source'
import { SecurityError, ValidationError } from '../services/errors'
import type { JsonStore } from '../services/storage'
import { log } from '../services/logger'
import { scanPackage } from './scanner/package-scan'
import { stagePackage, type StageOptions } from './stage'

export interface ToolSecurityStoreRecord {
  settings: ToolSecuritySettings
  packages: Record<string, ToolPackageRecord>
}

export function emptyToolSecurityStore(): ToolSecurityStoreRecord {
  return { settings: defaultToolSecuritySettings(), packages: {} }
}

/** Pi's own tools and Pi-Harness tools; everything else comes from a package. */
export const BUILTIN_TOOL_NAMES = new Set([
  'read',
  'bash',
  'powershell',
  'edit',
  'write',
  'grep',
  'find',
  'ls',
  'codemode',
  'tool_search'
])

export interface ToolSecurityDependencies {
  store: JsonStore<ToolSecurityStoreRecord>
  stage: Omit<StageOptions, 'tempRoot'> & { tempRoot?: string }
  listPackages: () => Promise<PiPackageInfo[]>
  /** Tool names provided by Pi-Harness itself (architecture tools, quarantined extraction). */
  appToolNames: () => Iterable<string>
  /**
   * Register or unregister a package with Pi while keeping its files, so a
   * blocked package's code is never loaded into a session.
   */
  setPackageEnabled?: (
    target: { source: string; scope: 'global' | 'project' },
    enabled: boolean
  ) => Promise<void>
}

interface PendingPreview {
  source: string
  scope: 'global' | 'project'
  projectRoot: string | null
  identity: string
  report: ToolScanReport
  expires: number
}

interface PendingInstall {
  identity: string
  digest: string
  allowInstallScripts: boolean
  expires: number
}

export type ToolKind = 'builtin' | 'app' | 'package' | 'unknown'

export interface ToolDecision {
  kind: ToolKind
  toolName: string
  decision: CapabilityDecision
  capabilities: ToolCapabilityId[]
  packageId?: string
  packageName?: string
  status?: ToolPackageRecord['status']
  reasons: string[]
}

const PREVIEW_TTL_MS = 30 * 60 * 1000

export function sourceIdentity(source: string, installedPath?: string | null): string {
  if (source.startsWith('npm:')) return packageIdentity(source)
  const git = packageIdentity(source)
  if (git.startsWith('git:')) return git
  const local = installedPath ?? source
  const resolved = path.resolve(local)
  return `local:${process.platform === 'win32' ? resolved.toLowerCase() : resolved}`
}

export class ToolSecurityService {
  private readonly previews = new Map<string, PendingPreview>()
  private readonly pendingInstalls = new Map<string, PendingInstall>()
  private index = new Map<
    string,
    Array<{ record: ToolPackageRecord; capabilities: ToolCapabilityId[] }>
  >()
  private refreshing: Promise<void> | null = null

  constructor(private readonly deps: ToolSecurityDependencies) {}

  // ------------------------------------------------------------- settings

  async settings(): Promise<ToolSecuritySettings> {
    return normalizeSettings((await this.deps.store.read()).settings)
  }

  peekSettings(): ToolSecuritySettings {
    return normalizeSettings(this.deps.store.peek().settings)
  }

  async updateSettings(next: unknown): Promise<ToolSecuritySettings> {
    const parsed = toolSecuritySettingsSchema.safeParse(next)
    if (!parsed.success)
      throw new ValidationError('Invalid tool security settings', { issues: parsed.error.issues })
    await this.deps.store.mutate({ apply: (current) => ({ ...current, settings: parsed.data }) })
    return parsed.data
  }

  // ------------------------------------------------------------- overview

  async overview(): Promise<ToolSecurityOverview> {
    await this.refresh()
    const data = await this.deps.store.read()
    return {
      settings: normalizeSettings(data.settings),
      packages: Object.values(data.packages).sort((a, b) =>
        (a.report?.manifest.name ?? a.source).localeCompare(b.report?.manifest.name ?? b.source)
      )
    }
  }

  /** Rescan installed packages and reconcile approvals with their current code. */
  refresh(): Promise<void> {
    this.refreshing ??= this.doRefresh().finally(() => {
      this.refreshing = null
    })
    return this.refreshing
  }

  private async doRefresh(): Promise<void> {
    let installed: PiPackageInfo[] = []
    try {
      installed = await this.deps.listPackages()
    } catch (error) {
      log.harness.warn('tool security: package listing failed', error)
    }
    const scanned = new Map<string, { info: PiPackageInfo; report: ToolScanReport }>()
    for (const info of installed) {
      if (!info.registered || !info.installed || !info.path) continue
      const identity = sourceIdentity(info.source, info.sourceType === 'local' ? info.path : null)
      try {
        scanned.set(identity, { info, report: await scanPackage(info.path) })
      } catch (error) {
        log.harness.warn(`tool security: scan failed for ${info.source}`, error)
      }
    }
    await this.deps.store.mutate({
      apply: (current) => {
        const packages: Record<string, ToolPackageRecord> = {}
        for (const [id, record] of Object.entries(current.packages))
          packages[id] = { ...record, installPath: null }
        for (const [identity, { info, report }] of scanned) {
          const existing = packages[identity]
          const previousDeps =
            existing?.report?.digest === report.digest ? existing.report.dependencies : undefined
          const merged: ToolScanReport = previousDeps
            ? { ...report, dependencies: previousDeps }
            : report
          packages[identity] = {
            id: identity,
            source: info.source,
            status: statusFor(existing, report.digest),
            approvedDigest: existing?.approvedDigest ?? null,
            approvedAt: existing?.approvedAt ?? null,
            allowInstallScripts: existing?.allowInstallScripts ?? false,
            decisions: existing?.decisions ?? {},
            toolDecisions: existing?.toolDecisions ?? {},
            report: merged,
            installPath: info.path,
            scope: info.scope,
            ...(existing?.quarantined ? { quarantined: true } : {})
          }
        }
        return { ...current, packages }
      }
    })
    await this.quarantine()
    this.rebuildIndex()
  }

  /**
   * Unreviewed packages whose scan shows malicious indicators are disabled in
   * Pi before any session loads them. The user can review and unblock them.
   */
  private async quarantine(): Promise<void> {
    if (!this.deps.setPackageEnabled || !this.peekSettings().quarantineDangerous) return
    const candidates = Object.values(this.deps.store.peek().packages).filter(
      (record) =>
        record.installPath &&
        record.scope === 'global' &&
        record.status === 'unreviewed' &&
        record.report?.verdict === 'dangerous'
    )
    for (const record of candidates) {
      try {
        await this.deps.setPackageEnabled({ source: record.source, scope: 'global' }, false)
      } catch (error) {
        log.harness.warn(`tool security: could not quarantine ${record.source}`, error)
        continue
      }
      log.harness.warn(
        `tool security: quarantined ${record.source} (malicious indicators, not reviewed)`
      )
      await this.deps.store.mutate({
        apply: (current) => ({
          ...current,
          packages: {
            ...current.packages,
            [record.id]: { ...record, status: 'blocked', quarantined: true, installPath: null }
          }
        })
      })
    }
  }

  private rebuildIndex(): void {
    const index = new Map<
      string,
      Array<{ record: ToolPackageRecord; capabilities: ToolCapabilityId[] }>
    >()
    for (const record of Object.values(this.deps.store.peek().packages)) {
      if (!record.installPath || !record.report) continue
      for (const tool of record.report.tools) {
        const list = index.get(tool.name) ?? []
        list.push({ record, capabilities: tool.capabilities })
        index.set(tool.name, list)
      }
    }
    this.index = index
  }

  // ------------------------------------------------------------- review flow

  async preview(input: {
    source: string
    scope: 'global' | 'project'
    projectRoot?: string | null
  }): Promise<ToolInstallPreview> {
    this.prune()
    const staged = await stagePackage(input.source, this.deps.stage)
    let report: ToolScanReport
    try {
      report = await scanPackage(staged.root)
    } finally {
      await staged.cleanup()
    }
    const identity = sourceIdentity(input.source, staged.kind === 'local' ? staged.root : null)
    const token = randomBytes(24).toString('hex')
    const expires = Date.now() + PREVIEW_TTL_MS
    this.previews.set(token, {
      source: input.source,
      scope: input.scope,
      projectRoot: input.projectRoot ?? null,
      identity,
      report,
      expires
    })
    const data = await this.deps.store.read()
    return {
      token,
      source: input.source,
      scope: input.scope,
      projectRoot: input.projectRoot ?? null,
      packageId: identity,
      report,
      suggested: suggestedDecisions(report, normalizeSettings(data.settings)),
      existing: data.packages[identity] ?? null,
      expiresAt: new Date(expires).toISOString()
    }
  }

  /** Record the user's decisions; installing is a separate, checked step. */
  async approve(
    input: ToolInstallApproval
  ): Promise<{ packageId: string; target: PiPackageTarget }> {
    this.prune()
    const preview = this.previews.get(input.token)
    if (!preview) throw new SecurityError('This review has expired. Review the package again.')
    if (preview.report.verdict === 'dangerous' && !input.acknowledgeDanger)
      throw new SecurityError(
        'Confirm that you understand the risks before installing a dangerous package.'
      )
    const decisions: CapabilityDecisionMap = {}
    for (const [capability, decision] of Object.entries(input.decisions) as Array<
      [ToolCapabilityId, CapabilityDecision]
    >)
      if (preview.report.capabilities.includes(capability)) decisions[capability] = decision
    this.previews.delete(input.token)
    await this.deps.store.mutate({
      apply: (current) => {
        const existing = current.packages[preview.identity]
        const record: ToolPackageRecord = {
          id: preview.identity,
          source: preview.source,
          status: 'approved',
          approvedDigest: preview.report.digest,
          approvedAt: new Date().toISOString(),
          allowInstallScripts: input.allowInstallScripts,
          decisions,
          toolDecisions: existing?.toolDecisions ?? {},
          report: preview.report,
          installPath: existing?.installPath ?? null
        }
        return { ...current, packages: { ...current.packages, [preview.identity]: record } }
      }
    })
    this.pendingInstalls.set(preview.source, {
      identity: preview.identity,
      digest: preview.report.digest,
      allowInstallScripts: input.allowInstallScripts,
      expires: Date.now() + PREVIEW_TTL_MS
    })
    this.rebuildIndex()
    return {
      packageId: preview.identity,
      target: { source: preview.source, scope: preview.scope, projectRoot: preview.projectRoot }
    }
  }

  /** Called before an install/update started from the app. */
  assertInstallReviewed(target: PiPackageTarget): void {
    this.prune()
    if (!this.peekSettings().requireReviewBeforeInstall) return
    if (!this.pendingInstalls.has(target.source))
      throw new SecurityError('Review this package’s capabilities before installing it.', {
        source: target.source
      })
  }

  /** npm lifecycle scripts run only for packages approved with them enabled. */
  allowInstallScripts(source: string): boolean {
    const settings = this.peekSettings()
    if (!settings.blockInstallScripts) return true
    const pending = this.pendingInstalls.get(source)
    if (pending) return pending.allowInstallScripts
    const record = this.deps.store.peek().packages[sourceIdentity(source)]
    return record?.allowInstallScripts ?? false
  }

  /**
   * After install: the installed code must match what the user reviewed.
   * Returns a reason when it doesn't, so the caller can roll back.
   */
  async verifyInstalled(
    target: PiPackageTarget
  ): Promise<{ ok: true } | { ok: false; reason: string }> {
    const pending = this.pendingInstalls.get(target.source)
    this.pendingInstalls.delete(target.source)
    const installed = (await this.deps.listPackages()).find(
      (info) =>
        info.installed &&
        info.path &&
        sourceIdentity(info.source, info.sourceType === 'local' ? info.path : null) ===
          (pending?.identity ?? sourceIdentity(target.source))
    )
    if (!installed?.path) {
      await this.refresh()
      return { ok: true }
    }
    const report = await scanPackage(installed.path, { includeDependencies: true })
    if (pending && report.digest !== pending.digest) {
      await this.refresh()
      return {
        ok: false,
        reason:
          'The installed package is different from the version you reviewed, so it was removed.'
      }
    }
    await this.deps.store.mutate({
      apply: (current) => {
        const identity = pending?.identity ?? sourceIdentity(target.source)
        const record = current.packages[identity]
        if (!record) return current
        return {
          ...current,
          packages: {
            ...current.packages,
            [identity]: { ...record, report, installPath: installed.path }
          }
        }
      }
    })
    await this.refresh()
    return { ok: true }
  }

  async setDecision(input: {
    packageId: string
    tool: string | null
    capability: ToolCapabilityId
    decision: CapabilityDecision | null
  }): Promise<ToolPackageRecord> {
    let updated: ToolPackageRecord | null = null
    await this.deps.store.mutate({
      apply: (current) => {
        const record = current.packages[input.packageId]
        if (!record) throw new ValidationError('Unknown tool package')
        const next = structuredClone(record)
        const target = input.tool ? (next.toolDecisions[input.tool] ??= {}) : next.decisions
        if (input.decision === null) delete target[input.capability]
        else target[input.capability] = input.decision
        updated = next
        return { ...current, packages: { ...current.packages, [record.id]: next } }
      }
    })
    this.rebuildIndex()
    return updated!
  }

  /** Approve the currently installed code of a package (e.g. after an update or a CLI install). */
  async approveInstalled(packageId: string): Promise<ToolPackageRecord> {
    const blocked = this.deps.store.peek().packages[packageId]?.status === 'blocked'
    if (!blocked) await this.refresh()
    let updated: ToolPackageRecord | null = null
    await this.deps.store.mutate({
      apply: (current) => {
        const record = current.packages[packageId]
        if (!record?.report) throw new ValidationError('Unknown tool package')
        updated = {
          ...record,
          status: 'approved',
          quarantined: false,
          approvedDigest: record.report.digest,
          approvedAt: new Date().toISOString()
        }
        return { ...current, packages: { ...current.packages, [packageId]: updated } }
      }
    })
    // A blocked or quarantined package is registered with Pi again once approved.
    // If its files changed while it was blocked, the next refresh marks it "changed".
    if (blocked && this.deps.setPackageEnabled && (updated!.scope ?? 'global') === 'global')
      await this.deps.setPackageEnabled({ source: updated!.source, scope: 'global' }, true)
    await this.refresh()
    return this.deps.store.peek().packages[packageId] ?? updated!
  }

  async setBlocked(packageId: string, blocked: boolean): Promise<ToolPackageRecord> {
    const record = this.deps.store.peek().packages[packageId]
    if (!record) throw new ValidationError('Unknown tool package')
    if (!blocked && !record.approvedDigest && record.report?.verdict === 'dangerous')
      throw new ValidationError(
        'This package shows signs of malicious behavior. Review it and choose “Approve current version” to enable it.'
      )
    // Blocking unregisters the package from Pi (files kept) so its code never loads.
    if (this.deps.setPackageEnabled && (record.scope ?? 'global') === 'global')
      await this.deps
        .setPackageEnabled({ source: record.source, scope: 'global' }, !blocked)
        .catch((error) => {
          if (blocked) throw error
          log.harness.warn(`tool security: could not re-enable ${record.source}`, error)
        })
    let updated: ToolPackageRecord | null = null
    await this.deps.store.mutate({
      apply: (current) => {
        const latest = current.packages[packageId]
        if (!latest) throw new ValidationError('Unknown tool package')
        updated = {
          ...latest,
          quarantined: false,
          status: blocked
            ? 'blocked'
            : statusFor({ ...latest, status: 'approved' }, latest.report?.digest ?? '')
        }
        return { ...current, packages: { ...current.packages, [packageId]: updated } }
      }
    })
    await this.refresh()
    return this.deps.store.peek().packages[packageId] ?? updated!
  }

  // ------------------------------------------------------------- runtime

  classify(toolName: string): ToolKind {
    if (BUILTIN_TOOL_NAMES.has(toolName)) return 'builtin'
    for (const name of this.deps.appToolNames()) if (name === toolName) return 'app'
    return this.index.has(toolName) ? 'package' : 'unknown'
  }

  /** Capabilities of a third-party tool (union across packages that provide the name). */
  toolCapabilities(toolName: string): ToolCapabilityId[] {
    const caps = new Set<ToolCapabilityId>()
    for (const entry of this.index.get(toolName) ?? [])
      for (const cap of entry.capabilities) caps.add(cap)
    return [...caps]
  }

  /** What should happen before this tool runs. */
  decide(toolName: string): ToolDecision {
    const kind = this.classify(toolName)
    const settings = this.peekSettings()
    if (kind === 'builtin' || kind === 'app')
      return { kind, toolName, decision: 'allow', capabilities: [], reasons: [] }
    if (kind === 'unknown')
      return {
        kind,
        toolName,
        decision: settings.unreviewedTools,
        capabilities: [],
        reasons: ['This tool does not come from a package Pi-Harness has reviewed.']
      }
    const entries = this.index.get(toolName) ?? []
    const decisions: CapabilityDecision[] = []
    const reasons: string[] = []
    const capabilities = new Set<ToolCapabilityId>()
    let packageId: string | undefined
    let packageName: string | undefined
    let status: ToolPackageRecord['status'] | undefined
    for (const { record, capabilities: caps } of entries) {
      packageId ??= record.id
      packageName ??= record.report?.manifest.name ?? record.source
      status ??= record.status
      if (record.status === 'blocked') {
        decisions.push('block')
        reasons.push(`${packageName} is blocked.`)
        continue
      }
      const toolOverrides = record.toolDecisions[toolName] ?? {}
      for (const cap of caps) {
        capabilities.add(cap)
        if (!CAPABILITY_CATALOG[cap].gating) continue
        const decision =
          toolOverrides[cap] ?? record.decisions[cap] ?? settings.capabilityDefaults[cap]
        decisions.push(decision)
        if (decision !== 'allow') reasons.push(`${CAPABILITY_CATALOG[cap].label}: ${decision}`)
      }
      if (record.status !== 'approved') {
        decisions.push(settings.unreviewedTools)
        reasons.push(
          record.status === 'changed'
            ? 'The package code changed since you reviewed it.'
            : 'You have not reviewed this package.'
        )
        if (record.report?.verdict === 'dangerous') {
          decisions.push('block')
          reasons.push('The scan found signs of malicious behavior.')
        }
      }
    }
    return {
      kind,
      toolName,
      decision: strictestDecision(decisions),
      capabilities: [...capabilities],
      packageId,
      packageName,
      status,
      reasons
    }
  }

  /** Remember an allow/block answer from a runtime prompt for this tool's gating capabilities. */
  async rememberToolDecision(toolName: string, decision: CapabilityDecision): Promise<void> {
    const entries = this.index.get(toolName) ?? []
    for (const { record, capabilities } of entries)
      for (const cap of capabilities)
        if (CAPABILITY_CATALOG[cap].gating)
          await this.setDecision({
            packageId: record.id,
            tool: toolName,
            capability: cap,
            decision
          })
  }

  private prune(): void {
    const now = Date.now()
    for (const [token, preview] of this.previews)
      if (preview.expires < now) this.previews.delete(token)
    for (const [source, pending] of this.pendingInstalls)
      if (pending.expires < now) this.pendingInstalls.delete(source)
  }
}

function statusFor(
  existing: ToolPackageRecord | undefined,
  digest: string
): ToolPackageRecord['status'] {
  if (!existing) return 'unreviewed'
  if (existing.status === 'blocked') return 'blocked'
  if (!existing.approvedDigest) return 'unreviewed'
  return existing.approvedDigest === digest ? 'approved' : 'changed'
}

export function normalizeSettings(value: unknown): ToolSecuritySettings {
  const defaults = defaultToolSecuritySettings()
  if (!value || typeof value !== 'object') return defaults
  const raw = value as Partial<ToolSecuritySettings>
  const merged = {
    ...defaults,
    ...raw,
    capabilityDefaults: { ...defaults.capabilityDefaults, ...(raw.capabilityDefaults ?? {}) },
    provenance: { ...defaults.provenance, ...(raw.provenance ?? {}) },
    camel: { ...defaults.camel, ...(raw.camel ?? {}) }
  }
  const parsed = toolSecuritySettingsSchema.safeParse(merged)
  return parsed.success ? parsed.data : defaults
}
