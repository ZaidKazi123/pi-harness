/**
 * Scan a Pi package directory (staged before install, or installed) and
 * produce a capability report.
 *
 * Nothing in the package is executed or imported. Symbolic links are never
 * followed. Limits keep a hostile package from exhausting memory or time.
 */

import { createHash } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { CAPABILITY_CATALOG } from '@shared/tool-security/catalog'
import type {
  DeclaredCapabilities,
  FindingSeverity,
  PackageManifestSummary,
  ScanFinding,
  ScanVerdict,
  ToolCapabilityId,
  ToolScanReport
} from '@shared/tool-security/types'
import { TOOL_CAPABILITY_IDS } from '@shared/tool-security/types'
import { analyzeSource, type CodeEvidence } from './code-analysis'
import { analyzeText } from './text-rules'

const CODE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx'])
const NATIVE_EXTENSIONS = new Set(['.node', '.dll', '.so', '.dylib', '.exe', '.wasm'])
const LIFECYCLE_SCRIPTS = [
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'prepublish',
  'preprepare',
  'postprepare'
]
const SKIP_DIRS = new Set(['.git', '.hg', '.svn'])

export interface ScanLimits {
  maxFiles: number
  maxFileBytes: number
  maxTotalBytes: number
  maxFindings: number
}

export const DEFAULT_SCAN_LIMITS: ScanLimits = {
  maxFiles: 4000,
  maxFileBytes: 2 * 1024 * 1024,
  maxTotalBytes: 60 * 1024 * 1024,
  maxFindings: 300
}

interface WalkedFile {
  rel: string
  abs: string
  size: number
}

async function walk(
  root: string,
  includeDependencies: boolean,
  limits: ScanLimits
): Promise<{ files: WalkedFile[]; truncated: boolean }> {
  const files: WalkedFile[] = []
  let truncated = false
  const queue = ['']
  while (queue.length) {
    const relDir = queue.shift()!
    let entries: import('node:fs').Dirent[]
    try {
      entries = await fs.readdir(path.join(root, relDir), { withFileTypes: true })
    } catch {
      continue
    }
    entries.sort((a, b) => a.name.localeCompare(b.name))
    for (const entry of entries) {
      const rel = relDir ? `${relDir}/${entry.name}` : entry.name
      if (entry.isSymbolicLink()) continue
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue
        if (entry.name === 'node_modules' && !includeDependencies) continue
        queue.push(rel)
        continue
      }
      if (!entry.isFile()) continue
      if (files.length >= limits.maxFiles) {
        truncated = true
        continue
      }
      const abs = path.join(root, rel)
      const stat = await fs.lstat(abs).catch(() => null)
      if (!stat?.isFile()) continue
      files.push({ rel, abs, size: stat.size })
    }
  }
  return { files, truncated }
}

function readDeclared(pkg: Record<string, unknown> | null): DeclaredCapabilities | null {
  const raw = pkg?.piHarness
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  const record = raw as Record<string, unknown>
  const ids = (value: unknown): ToolCapabilityId[] =>
    Array.isArray(value)
      ? value.filter((v): v is ToolCapabilityId =>
          (TOOL_CAPABILITY_IDS as readonly string[]).includes(v as string)
        )
      : []
  const strings = (value: unknown): string[] =>
    Array.isArray(value)
      ? value.filter((v): v is string => typeof v === 'string').slice(0, 100)
      : []
  const tools: Record<string, ToolCapabilityId[]> = {}
  if (record.tools && typeof record.tools === 'object' && !Array.isArray(record.tools))
    for (const [name, value] of Object.entries(record.tools as Record<string, unknown>).slice(
      0,
      200
    ))
      tools[name] = ids((value as { capabilities?: unknown } | null)?.capabilities)
  return {
    capabilities: ids(record.capabilities),
    network: strings(record.network),
    env: strings(record.env),
    tools
  }
}

function manifestSummary(pkg: Record<string, unknown> | null): PackageManifestSummary {
  const str = (value: unknown): string | null =>
    typeof value === 'string' ? value.slice(0, 300) : null
  const person = (value: unknown): string | null =>
    typeof value === 'string'
      ? value.slice(0, 200)
      : value && typeof value === 'object'
        ? str((value as { name?: unknown }).name)
        : null
  const repository = pkg?.repository
  return {
    name: str(pkg?.name),
    version: str(pkg?.version),
    description: str(pkg?.description),
    author: person(pkg?.author),
    license: str(pkg?.license),
    repository:
      typeof repository === 'string'
        ? repository.slice(0, 300)
        : repository && typeof repository === 'object'
          ? str((repository as { url?: unknown }).url)
          : null,
    homepage: str(pkg?.homepage)
  }
}

/** Entry files Pi loads as extensions (package.json `pi.extensions`, or `extensions/`). */
function extensionEntries(pkg: Record<string, unknown> | null, rels: string[]): Set<string> {
  const entries = new Set<string>()
  const declared = (pkg?.pi as { extensions?: unknown } | undefined)?.extensions
  if (Array.isArray(declared))
    for (const entry of declared)
      if (typeof entry === 'string') entries.add(entry.replace(/^\.\//, '').replace(/\\/g, '/'))
  for (const rel of rels) {
    if (rel.startsWith('extensions/') && CODE_EXTENSIONS.has(path.extname(rel))) entries.add(rel)
    if (pkg === null && rels.length === 1) entries.add(rel)
  }
  return entries
}

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
}

export function verdictOf(findings: ScanFinding[], undeclared: ToolCapabilityId[]): ScanVerdict {
  if (findings.some((f) => f.severity === 'critical')) return 'dangerous'
  if (findings.some((f) => f.severity === 'high') || undeclared.length) return 'review'
  return 'clean'
}

export async function scanPackage(
  root: string,
  options: { includeDependencies?: boolean; limits?: Partial<ScanLimits> } = {}
): Promise<ToolScanReport> {
  const limits = { ...DEFAULT_SCAN_LIMITS, ...options.limits }
  const stat = await fs.lstat(root)
  const singleFile = stat.isFile()
  const base = singleFile ? path.dirname(root) : root
  const walked = singleFile
    ? { files: [{ rel: path.basename(root), abs: root, size: stat.size }], truncated: false }
    : await walk(root, false, limits)

  let pkg: Record<string, unknown> | null = null
  if (!singleFile) {
    const text = await fs.readFile(path.join(root, 'package.json'), 'utf8').catch(() => null)
    if (text && text.length < 1024 * 1024) {
      try {
        const parsed: unknown = JSON.parse(text)
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed))
          pkg = parsed as Record<string, unknown>
      } catch {
        pkg = null
      }
    }
  }

  const findings: ScanFinding[] = []
  const capabilities = new Set<ToolCapabilityId>()
  const tools = new Map<string, Set<ToolCapabilityId>>()
  const hosts = new Set<string>()
  const envVars = new Set<string>()
  const externalCallTools = new Set<string>()
  const nonToolCapabilities = new Set<ToolCapabilityId>()
  let readsAllEnv = false
  let decodes = false
  let total = 0
  let truncated = walked.truncated
  const hash = createHash('sha256')
  const entries = extensionEntries(
    pkg,
    walked.files.map((f) => f.rel)
  )
  const perRuleCount = new Map<string, number>()

  const addFinding = (finding: ScanFinding) => {
    const key = `${finding.rule}:${finding.file ?? ''}`
    const count = perRuleCount.get(key) ?? 0
    if (count >= 3) return
    perRuleCount.set(key, count + 1)
    if (findings.length < limits.maxFindings) findings.push(finding)
    else truncated = true
  }

  const addEvidence = (evidence: CodeEvidence, file: string) => {
    if (evidence.capability) capabilities.add(evidence.capability)
    if (
      evidence.capability &&
      evidence.loadTime &&
      CAPABILITY_CATALOG[evidence.capability].gating &&
      evidence.capability !== 'fs-read'
    ) {
      capabilities.add('load-time')
      addFinding({
        rule: 'load-time.capability',
        severity: 'medium',
        capability: 'load-time',
        title: 'Acts as soon as it is loaded',
        detail: `${evidence.title} runs when Pi loads the extension, before any tool is used.`,
        file,
        line: evidence.line,
        snippet: evidence.snippet
      })
    }
    addFinding({
      rule: evidence.rule,
      severity: evidence.severity,
      ...(evidence.capability ? { capability: evidence.capability } : {}),
      title: evidence.title,
      detail: evidence.detail,
      file,
      ...(evidence.line ? { line: evidence.line } : {}),
      ...(evidence.snippet ? { snippet: evidence.snippet } : {}),
      ...(evidence.tool ? { tool: evidence.tool } : {})
    })
  }

  for (const file of walked.files) {
    const ext = path.extname(file.rel).toLowerCase()
    const isManifest = file.rel === 'package.json'
    const isCode = CODE_EXTENSIONS.has(ext)
    if (NATIVE_EXTENSIONS.has(ext)) {
      capabilities.add('native')
      addFinding({
        rule: 'native.binary',
        severity: 'high',
        capability: 'native',
        title: 'Ships a compiled binary',
        detail: `${file.rel} is compiled code that cannot be reviewed as source.`,
        file: file.rel
      })
      hash.update(`${file.rel}\0${file.size}\0`)
      continue
    }
    if (!isCode && !isManifest) continue
    if (file.size > limits.maxFileBytes || total + file.size > limits.maxTotalBytes) {
      truncated = true
      addFinding({
        rule: 'scan.skipped-large',
        severity: 'medium',
        title: 'File too large to review',
        detail: `${file.rel} (${Math.round(file.size / 1024)} KB) exceeds the scan limit and was not analyzed.`,
        file: file.rel
      })
      hash.update(`${file.rel}\0${file.size}\0`)
      continue
    }
    const buffer = await fs.readFile(file.abs).catch(() => null)
    if (!buffer) continue
    total += buffer.length
    hash.update(`${file.rel}\0`)
    hash.update(createHash('sha256').update(buffer).digest('hex'))
    hash.update('\0')
    if (isManifest) continue
    const source = buffer.toString('utf8')
    const analysis = analyzeSource(source, { entry: entries.has(file.rel) || singleFile })
    for (const evidence of analysis.evidence) addEvidence(evidence, file.rel)
    for (const [name, caps] of analysis.tools) {
      const set = tools.get(name) ?? new Set()
      for (const cap of caps) set.add(cap)
      tools.set(name, set)
    }
    for (const cap of analysis.packageCapabilities) nonToolCapabilities.add(cap)
    for (const tool of analysis.toolsWithExternalCalls) externalCallTools.add(tool)
    for (const host of analysis.hosts) hosts.add(host)
    for (const name of analysis.envVars) envVars.add(name)
    readsAllEnv ||= analysis.readsAllEnv
    decodes ||= analysis.decodesBase64
    const longLines = source.split('\n').filter((line) => line.length > 2000).length
    if (source.length > 50_000 && longLines > 0)
      addFinding({
        rule: 'review.minified',
        severity: 'low',
        title: 'Minified code',
        detail: `${file.rel} is minified, which makes manual review harder.`,
        file: file.rel
      })
  }

  // npm lifecycle scripts run automatically during install.
  const installScripts: Record<string, string> = {}
  const scripts = pkg?.scripts
  if (scripts && typeof scripts === 'object' && !Array.isArray(scripts))
    for (const name of LIFECYCLE_SCRIPTS) {
      const value = (scripts as Record<string, unknown>)[name]
      if (typeof value !== 'string') continue
      installScripts[name] = value.slice(0, 500)
      capabilities.add('install-script')
      addFinding({
        rule: 'install.lifecycle-script',
        severity: 'high',
        capability: 'install-script',
        title: `Runs a "${name}" script on install`,
        detail: `npm would run: ${value.slice(0, 200)}`,
        file: 'package.json'
      })
      for (const hit of analyzeText(value))
        if (hit.rule)
          addFinding({
            rule: hit.rule,
            severity: hit.severity,
            ...(hit.capability ? { capability: hit.capability } : {}),
            title: hit.title,
            detail: `In the ${name} script: ${hit.detail}`,
            file: 'package.json'
          })
    }

  // Combinations that indicate theft rather than ordinary use.
  if (capabilities.has('secrets') && capabilities.has('network'))
    addFinding({
      rule: 'exfil.credentials',
      severity: 'critical',
      capability: 'secrets',
      title: 'May send credentials over the network',
      detail: 'Code references credential locations and also has network access.'
    })
  if (readsAllEnv && capabilities.has('network'))
    addFinding({
      rule: 'exfil.environment',
      severity: 'critical',
      capability: 'env',
      title: 'May send all environment variables over the network',
      detail:
        'Code reads the whole environment (every API key and token) and also has network access.'
    })
  if (decodes && capabilities.has('dynamic-code')) {
    capabilities.add('obfuscated')
    addFinding({
      rule: 'obfuscation.decode-and-run',
      severity: 'critical',
      capability: 'obfuscated',
      title: 'Decodes and runs hidden code',
      detail: 'Decodes base64 data and evaluates code at runtime, a common way to hide a payload.'
    })
  }

  // Attribute capabilities to tools.
  const declared = readDeclared(pkg)
  const reportTools = [...tools.entries()].map(([name, caps]) => {
    const set = new Set(caps)
    // Calls into other local files can't be followed precisely: assume the worst of the package's helpers.
    if (externalCallTools.has(name))
      for (const cap of nonToolCapabilities) if (CAPABILITY_CATALOG[cap].gating) set.add(cap)
    for (const cap of declared?.tools[name] ?? []) set.add(cap)
    for (const cap of declared?.capabilities ?? []) if (cap === 'untrusted-output') set.add(cap)
    if (set.has('network')) set.add('untrusted-output')
    return { name, capabilities: TOOL_CAPABILITY_IDS.filter((id) => set.has(id)) }
  })
  if (reportTools.some((tool) => tool.capabilities.includes('untrusted-output')))
    capabilities.add('untrusted-output')
  for (const cap of declared?.capabilities ?? []) capabilities.add(cap)

  const detectedGating = TOOL_CAPABILITY_IDS.filter(
    (id) => capabilities.has(id) && CAPABILITY_CATALOG[id].gating
  )
  const declaredSet = new Set<ToolCapabilityId>([
    ...(declared?.capabilities ?? []),
    ...Object.values(declared?.tools ?? {}).flat()
  ])
  const undeclared = declared ? detectedGating.filter((id) => !declaredSet.has(id)) : []
  for (const id of undeclared)
    addFinding({
      rule: 'manifest.undeclared',
      severity: 'high',
      capability: id,
      title: `Undeclared: ${CAPABILITY_CATALOG[id].label}`,
      detail: 'The package manifest does not declare this capability, but the code uses it.'
    })
  if (declared)
    for (const host of hosts) {
      if (
        declared.network.length &&
        !declared.network.some((allowed) => host === allowed || host.endsWith(`.${allowed}`))
      )
        addFinding({
          rule: 'manifest.undeclared-host',
          severity: 'medium',
          capability: 'network',
          title: `Undeclared host: ${host}`,
          detail: 'The code references a host that is not in the manifest’s network list.'
        })
    }

  findings.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
  return {
    digest: hash.digest('hex'),
    scannedAt: new Date().toISOString(),
    manifest: manifestSummary(pkg),
    declared,
    capabilities: TOOL_CAPABILITY_IDS.filter((id) => capabilities.has(id)),
    undeclared,
    tools: reportTools.sort((a, b) => a.name.localeCompare(b.name)),
    networkHosts: [...hosts].sort().slice(0, 100),
    envVars: [...envVars].sort().slice(0, 100),
    installScripts,
    findings: findings.filter((f) => f.severity !== 'info'),
    verdict: verdictOf(findings, undeclared),
    files: walked.files.length,
    truncated,
    ...(options.includeDependencies && !singleFile
      ? { dependencies: await scanDependencies(base, limits) }
      : {})
  }
}

/** Installed dependencies: union of capabilities and the serious findings only. */
async function scanDependencies(
  root: string,
  limits: ScanLimits
): Promise<NonNullable<ToolScanReport['dependencies']>> {
  const modulesDir = path.join(root, 'node_modules')
  const packages: string[] = []
  const entries = await fs.readdir(modulesDir, { withFileTypes: true }).catch(() => [])
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name.startsWith('.')) continue
    if (entry.name.startsWith('@')) {
      const scoped = await fs
        .readdir(path.join(modulesDir, entry.name), { withFileTypes: true })
        .catch(() => [])
      for (const child of scoped)
        if (child.isDirectory()) packages.push(`${entry.name}/${child.name}`)
    } else packages.push(entry.name)
  }
  const capabilities = new Set<ToolCapabilityId>()
  const findings: ScanFinding[] = []
  for (const name of packages.slice(0, 300)) {
    const report = await scanPackage(path.join(modulesDir, name), {
      limits: { ...limits, maxFiles: 800, maxFindings: 40 }
    }).catch(() => null)
    if (!report) continue
    for (const cap of report.capabilities) capabilities.add(cap)
    for (const finding of report.findings)
      if (finding.severity === 'critical' || finding.rule === 'install.lifecycle-script')
        findings.push({ ...finding, file: `node_modules/${name}/${finding.file ?? ''}` })
  }
  return {
    packages: packages.length,
    capabilities: TOOL_CAPABILITY_IDS.filter((id) => capabilities.has(id)),
    findings: findings.slice(0, 100),
    verdict: verdictOf(findings, [])
  }
}
