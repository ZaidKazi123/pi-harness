/**
 * Runtime enforcement before every Pi tool call (both runtimes route here
 * through the desktop extension's tool_call hook).
 *
 * 1. Capability decisions for third-party tools (allow / ask / block per
 *    capability, per package or per tool, from Settings → Tool security).
 * 2. Provenance checks for exfiltration-capable calls (see provenance.ts).
 *
 * Neither check is relaxed by the session permission mode: these are explicit
 * user policies, not interactive convenience prompts.
 */

import type { BrowserWindow, MessageBoxOptions } from 'electron'
import { CAPABILITY_CATALOG } from '@shared/tool-security/catalog'
import type { CapabilityDecision } from '@shared/tool-security/types'
import type { ProvenanceTracker } from './provenance'
import type { ToolSecurityService } from './service'

export interface GuardPromptRequest {
  sessionId: string
  title: string
  message: string
  detail: string
  /** Offer "remember for this tool". */
  rememberable: boolean
  signal?: AbortSignal
}

export type GuardPrompt = (
  request: GuardPromptRequest
) => Promise<{ allowed: boolean; remember: boolean }>

export interface GuardReport {
  sessionId: string
  target: string
  rule: string
  decision: 'allow' | 'ask' | 'deny'
  allowed: boolean
}

export interface ToolCall {
  sessionId: string
  toolName: string
  input: unknown
  signal?: AbortSignal
}

export class ToolSecurityBlockedError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ToolSecurityBlockedError'
  }
}

function inputPreview(input: unknown): string {
  try {
    const text = JSON.stringify(input ?? {}, null, 1)
    return text.length > 600 ? `${text.slice(0, 597)}…` : text
  } catch {
    return '(arguments unavailable)'
  }
}

export class ToolSecurityGuard {
  constructor(
    private readonly service: ToolSecurityService,
    private readonly provenance: ProvenanceTracker,
    private readonly prompt: GuardPrompt,
    private readonly report: (payload: GuardReport) => void = () => {}
  ) {}

  /** Both checks, in order. Main runs Harness Policy between them. */
  async check(call: ToolCall): Promise<void> {
    await this.checkTool(call)
    await this.checkDataFlow(call)
  }

  /** What the tool is allowed to do (third-party and unreviewed tools only). */
  async checkTool(call: ToolCall): Promise<void> {
    const { sessionId, toolName, input, signal } = call
    signal?.throwIfAborted()
    const decision = this.service.decide(toolName)
    if (decision.kind === 'package' || decision.kind === 'unknown') {
      const capabilityLines = decision.capabilities
        .filter((id) => CAPABILITY_CATALOG[id].gating)
        .map((id) => `• ${CAPABILITY_CATALOG[id].label} (${CAPABILITY_CATALOG[id].risk} risk)`)
      await this.enforce(decision.decision, {
        sessionId,
        signal,
        rule: `toolSecurity.${decision.kind}`,
        target: toolName,
        blockedMessage:
          `Blocked by tool security: ${toolName}. ${decision.reasons.join(' ')}`.trim(),
        rememberable: decision.kind === 'package',
        rememberTool: toolName,
        title: 'Tool permission',
        message:
          decision.kind === 'unknown'
            ? `Pi wants to use “${toolName}”, a tool Pi-Harness has not reviewed.`
            : `Pi wants to use “${toolName}” from ${decision.packageName ?? 'a third-party package'}.`,
        detail: [
          capabilityLines.length
            ? `This tool can:\n${capabilityLines.join('\n')}`
            : 'No capabilities were detected for this tool.',
          decision.reasons.length ? `\n${decision.reasons.join('\n')}` : '',
          `\nArguments:\n${inputPreview(input)}`
        ].join('\n')
      })
    }
  }

  /**
   * Where its data could go. Any exfiltration-capable call carrying values from
   * untrusted content is checked; shell commands are also checked whenever the
   * conversation holds untrusted content, since a command can embed anything.
   */
  async checkDataFlow(call: ToolCall): Promise<void> {
    const { sessionId, toolName, input, signal } = call
    signal?.throwIfAborted()
    const settings = this.service.peekSettings().provenance
    if (!settings.enabled) return
    const sink = this.provenance.checkSink(sessionId, toolName, input)
    if (!sink.sink || !sink.tainted) return
    const flowing = sink.flows.length > 0
    if (!flowing && !sink.shell) return
    const policy: CapabilityDecision = flowing
      ? settings.untrustedArgument
      : settings.sinkWhenTainted
    const sources = [
      ...new Set(flowing ? sink.flows.map((flow) => flow.source) : sink.sources)
    ].slice(0, 6)
    await this.enforce(policy, {
      sessionId,
      signal,
      rule: flowing ? 'provenance.untrustedArgument' : 'provenance.sinkWhenTainted',
      target: sink.description,
      blockedMessage: flowing
        ? `Blocked by tool security: this action would send data that came from untrusted content (${sources.join(', ')}). If you asked for this, run it yourself or adjust Settings → Tool security.`
        : `Blocked by tool security: this conversation contains untrusted content (${sources.join(', ')}), so actions that can send data off this computer are blocked.`,
      rememberable: false,
      title: 'Untrusted data check',
      message: flowing
        ? 'This action could send data that came from untrusted content.'
        : 'This action can send data off this computer, and the conversation contains untrusted content.',
      detail: [
        `Action:\n${sink.description}`,
        flowing
          ? `\nValues taken from untrusted content:\n${sink.flows
              .slice(0, 6)
              .map((flow) => `• ${flow.value.slice(0, 120)}  (from ${flow.source})`)
              .join('\n')}`
          : `\nUntrusted sources in this conversation:\n${sources.map((source) => `• ${source}`).join('\n')}`,
        '\nText in files, web pages and tool results can contain instructions written by someone else. Allow only if you asked for this.'
      ].join('\n')
    })
  }

  private async enforce(
    decision: CapabilityDecision,
    options: {
      sessionId: string
      signal?: AbortSignal
      rule: string
      target: string
      blockedMessage: string
      rememberable: boolean
      rememberTool?: string
      title: string
      message: string
      detail: string
    }
  ): Promise<void> {
    if (decision === 'allow') return
    if (decision === 'block') {
      this.report({
        sessionId: options.sessionId,
        target: options.target,
        rule: options.rule,
        decision: 'deny',
        allowed: false
      })
      throw new ToolSecurityBlockedError(options.blockedMessage)
    }
    const answer = await this.prompt({
      sessionId: options.sessionId,
      title: options.title,
      message: options.message,
      detail: options.detail,
      rememberable: options.rememberable,
      signal: options.signal
    })
    options.signal?.throwIfAborted()
    this.report({
      sessionId: options.sessionId,
      target: options.target,
      rule: options.rule,
      decision: 'ask',
      allowed: answer.allowed
    })
    if (answer.remember && options.rememberTool)
      await this.service.rememberToolDecision(
        options.rememberTool,
        answer.allowed ? 'allow' : 'block'
      )
    if (!answer.allowed) throw new ToolSecurityBlockedError(`Declined: ${options.message}`)
  }
}

/** Native dialog owned by Main; no window means deny. */
export function electronGuardPrompt(
  getWindow: () => BrowserWindow | null,
  showMessageBox: (
    window: BrowserWindow,
    options: MessageBoxOptions
  ) => Promise<{ response: number; checkboxChecked: boolean }>
): GuardPrompt {
  return async (request) => {
    const win = getWindow()
    if (!win || win.isDestroyed()) return { allowed: false, remember: false }
    const result = await showMessageBox(win, {
      ...(request.signal ? { signal: request.signal } : {}),
      type: 'warning',
      title: request.title,
      message: request.message,
      detail: request.detail,
      buttons: ['Allow once', 'Deny'],
      defaultId: 1,
      cancelId: 1,
      noLink: true,
      ...(request.rememberable
        ? { checkboxLabel: 'Remember my choice for this tool', checkboxChecked: false }
        : {})
    })
    return {
      allowed: result.response === 0,
      remember: request.rememberable && result.checkboxChecked
    }
  }
}
