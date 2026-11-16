/**
 * Provenance (taint) tracking for live Pi sessions — the CaMeL idea applied to
 * a single-model agent loop.
 *
 * CaMeL separates a privileged planner that never sees untrusted data from a
 * quarantined model that reads it, and attaches capabilities (provenance) to
 * every value so policies can check data flow before each tool call. In a
 * normal Pi session the model sees everything, so we keep the part we can
 * enforce from outside the loop:
 *
 * 1. Every tool result is labeled with where it came from. Results of
 *    third-party tools, network commands and (by default) workspace file reads
 *    are untrusted. User messages are trusted.
 * 2. Before an exfiltration-capable call (network commands, git push, publish,
 *    third-party tools with network access) we check:
 *    - the session is tainted → `sinkWhenTainted` (ask by default), and
 *    - the arguments contain values that came from untrusted data and not
 *      from the user (URLs, hosts, emails, long tokens or copied text) →
 *      `untrustedArgument` (block by default).
 *
 * These checks do not depend on the session's permission mode: full access
 * does not pre-approve data flowing from untrusted content to the network.
 */

import type { ProvenanceSource, ProvenanceStatus } from '@shared/tool-security/types'
import { classifyGitCommand, isNetworkCommand } from '../harness/policy/policy-defaults'
import { shellCommandSegments } from '../harness/policy/shell-segments'

const MAX_CORPUS_CHARS = 1_000_000
const SHINGLE = 32
const SAMPLE_MOD = 4
const MAX_SOURCES = 200

const URL_RE = /\b(?:https?|wss?|ftp):\/\/[^\s"'<>`)\]]+/gi
const HOST_RE = /\b(?:[a-z0-9-]+\.)+(?:[a-z]{2,24})\b/gi
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
const TOKEN_RE = /[A-Za-z0-9_\-+/=]{28,}/g
const COMMON_HOSTS = new Set([
  'github.com',
  'npmjs.com',
  'www.npmjs.com',
  'registry.npmjs.org',
  'nodejs.org',
  'example.com',
  'localhost'
])
const FILE_EXTENSION_HOST =
  /\.(?:js|ts|tsx|jsx|mjs|cjs|json|md|txt|html?|css|py|go|rs|java|vue|yml|yaml|toml|lock|sh|png|jpg|svg)$/i

export interface ProvenanceOptions {
  workspaceFilesUntrusted: () => boolean
  /** Capabilities of a third-party tool, or null for built-in/app tools. */
  toolCapabilities: (toolName: string) => string[] | null
}

interface SessionState {
  tainted: boolean
  sources: ProvenanceSource[]
  untrustedIndicators: Map<string, string>
  trustedIndicators: Set<string>
  trustedText: string
  corpus: string
  shingles: Map<number, string>
  pendingArgs: Map<string, { toolName: string; args: unknown }>
}

/** Error texts produced by Pi-Harness guards and policies. */
const HARNESS_REFUSAL =
  /^(?:Blocked by tool security|Blocked by Harness Policy|Declined: |Tool approval declined|Tool access was denied by the desktop workspace policy|Tool \S+ not found$)/

export interface SinkCheck {
  /** The call could move data out of this machine. */
  sink: boolean
  /** A shell command (judged on context as well as data flow). */
  shell: boolean
  tainted: boolean
  /** Untrusted values found in the arguments, with the source they came from. */
  flows: Array<{ value: string; source: string }>
  sources: string[]
  description: string
}

export function extractIndicators(text: string): string[] {
  const out = new Set<string>()
  for (const match of text.matchAll(URL_RE)) {
    const url = match[0].replace(/[.,;:!?]+$/, '')
    out.add(url.toLowerCase())
    try {
      out.add(new URL(url).hostname.toLowerCase())
    } catch {
      // ignore malformed URL
    }
  }
  for (const match of text.matchAll(HOST_RE)) {
    const host = match[0].toLowerCase()
    if (!COMMON_HOSTS.has(host) && !FILE_EXTENSION_HOST.test(host) && host.includes('.'))
      out.add(host)
  }
  for (const match of text.matchAll(EMAIL_RE)) out.add(match[0].toLowerCase())
  for (const match of text.matchAll(IP_RE))
    if (!match[0].startsWith('127.') && match[0] !== '0.0.0.0') out.add(match[0])
  for (const match of text.matchAll(TOKEN_RE)) out.add(match[0])
  return [...out]
}

function normalize(text: string): string {
  return text.replace(/\s+/g, ' ').toLowerCase()
}

function hashShingle(text: string, start: number): number {
  let h = 2166136261
  for (let i = start; i < start + SHINGLE; i++) {
    h ^= text.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return h >>> 0
}

export function toolResultText(result: unknown): string {
  if (typeof result === 'string') return result
  if (!result || typeof result !== 'object') return ''
  const content = (result as { content?: unknown }).content
  if (Array.isArray(content))
    return content
      .map((part) =>
        part && typeof part === 'object' && (part as { type?: string }).type === 'text'
          ? String((part as { text?: unknown }).text ?? '')
          : ''
      )
      .join('\n')
  try {
    return JSON.stringify(result).slice(0, 200_000)
  } catch {
    return ''
  }
}

function messageText(message: unknown): string {
  if (!message || typeof message !== 'object') return ''
  const content = (message as { content?: unknown }).content
  if (typeof content === 'string') return content
  if (Array.isArray(content))
    return content
      .map((part) =>
        part && typeof part === 'object' && typeof (part as { text?: unknown }).text === 'string'
          ? (part as { text: string }).text
          : ''
      )
      .join('\n')
  return ''
}

function stringArg(input: unknown, keys: string[]): string | null {
  if (!input || typeof input !== 'object') return null
  for (const key of keys) {
    const value = (input as Record<string, unknown>)[key]
    if (typeof value === 'string' && value.trim()) return value
  }
  return null
}

/** Shell segments that can send data off this machine. */
export function exfiltrationSegments(command: string): string[] {
  const segments = shellCommandSegments(command)
  return segments.filter((segment) => {
    if (isNetworkCommand(segment)) return true
    const git = classifyGitCommand(segment)
    if (git === 'push' || git === 'forcePush') return true
    if (/^git\s+remote\s+(?:add|set-url)\b/.test(segment)) return true
    if (/^(?:npm|pnpm|yarn)\s+publish\b/.test(segment)) return true
    if (/^gh\s+(?:api|gist|release|issue|pr|repo)\b/.test(segment)) return true
    if (
      /^(?:python3?|node|ruby|perl|php)\s+-[ce]\b/.test(segment) &&
      /https?:\/\/|socket|request|fetch|urllib|http\./i.test(segment)
    )
      return true
    return false
  })
}

export class ProvenanceTracker {
  private readonly sessions = new Map<string, SessionState>()

  constructor(private readonly options: ProvenanceOptions) {}

  private state(sessionId: string): SessionState {
    let state = this.sessions.get(sessionId)
    if (!state) {
      state = {
        tainted: false,
        sources: [],
        untrustedIndicators: new Map(),
        trustedIndicators: new Set(),
        trustedText: '',
        corpus: '',
        shingles: new Map(),
        pendingArgs: new Map()
      }
      this.sessions.set(sessionId, state)
    }
    return state
  }

  /** Feed raw Pi agent events (wire format) for one session. */
  observe(sessionId: string, event: { type: string; [key: string]: unknown }): void {
    if (event.type === 'message_end' || event.type === 'message_start') {
      const message = event.message as { role?: string } | undefined
      if (message?.role === 'user' && event.type === 'message_end')
        this.recordTrusted(sessionId, messageText(message))
      return
    }
    if (event.type === 'tool_execution_start') {
      const id = String(event.toolCallId ?? '')
      if (id)
        this.state(sessionId).pendingArgs.set(id, {
          toolName: String(event.toolName ?? ''),
          args: event.args
        })
      return
    }
    if (event.type === 'tool_execution_end') {
      const id = String(event.toolCallId ?? '')
      const state = this.state(sessionId)
      const pending = state.pendingArgs.get(id)
      state.pendingArgs.delete(id)
      const text = toolResultText(event.result)
      // Refusals written by Pi-Harness itself are not outside data.
      if (event.isError === true && HARNESS_REFUSAL.test(text.trim())) return
      this.recordToolResult(
        sessionId,
        String(event.toolName ?? pending?.toolName ?? ''),
        pending?.args,
        text
      )
    }
  }

  recordTrusted(sessionId: string, text: string): void {
    if (!text) return
    const state = this.state(sessionId)
    for (const indicator of extractIndicators(text)) state.trustedIndicators.add(indicator)
    state.trustedText = (state.trustedText + '\n' + normalize(text)).slice(-200_000)
  }

  /** Classify a finished tool call's output and record it if untrusted. */
  recordToolResult(sessionId: string, toolName: string, args: unknown, text: string): void {
    const source = this.classifySource(toolName, args)
    if (!source || !text.trim()) return
    this.recordUntrusted(sessionId, source, text)
  }

  recordUntrusted(sessionId: string, source: Omit<ProvenanceSource, 'at'>, text: string): void {
    const state = this.state(sessionId)
    state.tainted = true
    if (!state.sources.some((existing) => existing.label === source.label)) {
      state.sources.push({ ...source, at: Date.now() })
      if (state.sources.length > MAX_SOURCES) state.sources.shift()
    }
    for (const indicator of extractIndicators(text))
      if (!state.untrustedIndicators.has(indicator))
        state.untrustedIndicators.set(indicator, source.label)
    const normalized = normalize(text)
    const offset = state.corpus.length
    state.corpus += normalized + '\n'
    for (let i = 0; i + SHINGLE <= normalized.length; i++) {
      const h = hashShingle(normalized, i)
      if (h % SAMPLE_MOD === 0 && !state.shingles.has(h)) state.shingles.set(h, source.label)
    }
    if (state.corpus.length > MAX_CORPUS_CHARS) {
      // Drop the oldest text; keep the indicators, which are what flows are judged by.
      state.corpus = state.corpus.slice(state.corpus.length - MAX_CORPUS_CHARS)
      if (state.shingles.size > MAX_CORPUS_CHARS / SAMPLE_MOD) state.shingles.clear()
    }
    void offset
  }

  private classifySource(toolName: string, args: unknown): Omit<ProvenanceSource, 'at'> | null {
    const workspaceUntrusted = this.options.workspaceFilesUntrusted()
    switch (toolName) {
      case 'read':
      case 'grep': {
        if (!workspaceUntrusted) return null
        const target = stringArg(args, ['path', 'file', 'file_path', 'pattern']) ?? 'workspace'
        return { kind: 'file', label: `file:${target}` }
      }
      case 'find':
      case 'ls':
      case 'edit':
      case 'write':
        return null
      case 'bash':
      case 'powershell': {
        const command = stringArg(args, ['command', 'cmd']) ?? ''
        const network = exfiltrationSegments(command).length > 0
        if (!network && !workspaceUntrusted) return null
        return { kind: network ? 'url' : 'command', label: `command:${command.slice(0, 80)}` }
      }
      case 'quarantined_extract':
        return {
          kind: 'extraction',
          label: `extraction:${stringArg(args, ['path', 'url']) ?? 'data'}`
        }
    }
    const capabilities = this.options.toolCapabilities(toolName)
    // App tools (architecture map) summarize workspace files.
    if (capabilities === null)
      return workspaceUntrusted ? { kind: 'tool', label: `tool:${toolName}` } : null
    return { kind: 'tool', label: `tool:${toolName}` }
  }

  /** Is this call able to move data off the machine, and does it carry untrusted data? */
  checkSink(sessionId: string, toolName: string, input: unknown): SinkCheck {
    const state = this.sessions.get(sessionId)
    const tainted = Boolean(state?.tainted)
    let sink = false
    let description = toolName
    let argumentText = ''
    if (toolName === 'bash' || toolName === 'powershell') {
      const command = stringArg(input, ['command', 'cmd']) ?? ''
      const segments = exfiltrationSegments(command)
      sink = segments.length > 0
      description = command.slice(0, 300)
      argumentText = command
    } else if (
      !['read', 'grep', 'find', 'ls', 'edit', 'write', 'quarantined_extract'].includes(toolName)
    ) {
      const capabilities = this.options.toolCapabilities(toolName)
      sink = Boolean(capabilities?.includes('network'))
      try {
        argumentText = JSON.stringify(input ?? {}).slice(0, 50_000)
      } catch {
        argumentText = ''
      }
      description = `${toolName} ${argumentText.slice(0, 200)}`
    }
    const flows: SinkCheck['flows'] = []
    if (sink && state && tainted) {
      for (const indicator of extractIndicators(argumentText)) {
        const source =
          state.untrustedIndicators.get(indicator) ??
          state.untrustedIndicators.get(indicator.toLowerCase())
        if (
          source &&
          !state.trustedIndicators.has(indicator) &&
          !state.trustedIndicators.has(indicator.toLowerCase())
        )
          flows.push({ value: indicator, source })
      }
      const normalized = normalize(argumentText)
      for (let i = 0; i + SHINGLE <= normalized.length && flows.length < 10; i++) {
        const source = state.shingles.get(hashShingle(normalized, i))
        if (!source) continue
        const window = normalized.slice(i, i + SHINGLE)
        if (!state.corpus.includes(window) || state.trustedText.includes(window)) continue
        flows.push({ value: window, source })
        i += SHINGLE
      }
    }
    return {
      shell: toolName === 'bash' || toolName === 'powershell',
      sink,
      tainted,
      flows: dedupeFlows(flows),
      sources: state?.sources.map((source) => source.label) ?? [],
      description
    }
  }

  status(sessionId: string): ProvenanceStatus {
    const state = this.sessions.get(sessionId)
    return { sessionId, tainted: Boolean(state?.tainted), sources: state ? [...state.sources] : [] }
  }

  clear(sessionId: string): void {
    this.sessions.delete(sessionId)
  }
}

function dedupeFlows(flows: SinkCheck['flows']): SinkCheck['flows'] {
  const seen = new Set<string>()
  return flows.filter((flow) => {
    if (seen.has(flow.value)) return false
    seen.add(flow.value)
    return true
  })
}
