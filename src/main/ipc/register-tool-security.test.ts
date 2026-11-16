import { describe, expect, it, vi } from 'vitest'
import { IPC_INVOKE } from '@shared/ipc/channels'
import { defaultToolSecuritySettings } from '@shared/tool-security/catalog'
import type { IpcHandleRegistrar } from './trusted-ipc'
import { registerToolSecurityIpc, type ToolSecurityIpcServices } from './register-tool-security'
import { reviewedPackageMutation } from '../tool-security/install-gate'
import type { ToolSecurityService } from '../tool-security/service'

function setup() {
  const handlers = new Map<string, (event: unknown, input: unknown) => Promise<unknown>>()
  const ipc = {
    handle: (channel: string, handler: unknown) =>
      handlers.set(channel, handler as (event: unknown, input: unknown) => Promise<unknown>)
  } as IpcHandleRegistrar
  const service = {
    overview: vi.fn(async () => ({ settings: defaultToolSecuritySettings(), packages: [] })),
    updateSettings: vi.fn(async (value: unknown) => value),
    preview: vi.fn(async () => ({ token: 't' })),
    approve: vi.fn(async () => ({
      packageId: 'npm:x',
      target: { source: 'npm:x', scope: 'global' }
    })),
    setDecision: vi.fn(async () => ({})),
    approveInstalled: vi.fn(async () => ({})),
    setBlocked: vi.fn(async () => ({}))
  }
  const camel = {
    plan: vi.fn(async () => ({ planId: 'p' })),
    run: vi.fn(async () => ({ status: 'completed' }))
  }
  const services = {
    service,
    provenance: { status: vi.fn(() => ({ sessionId: 's', tainted: false, sources: [] })) },
    camel,
    authorizeFolder: vi.fn(async (folder: string) => {
      if (folder.includes('outside')) throw new Error('Path denied')
      return `/abs/${folder}`
    })
  } as unknown as ToolSecurityIpcServices
  registerToolSecurityIpc(ipc, async (fn) => ({ ok: true, data: await fn() }), services)
  const call = (channel: string, input?: unknown) => handlers.get(channel)!({}, input)
  return { call, service, camel, services }
}

describe('tool security IPC', () => {
  it('validates every request before reaching the service', async () => {
    const { call, service, camel } = setup()
    await expect(call(IPC_INVOKE.toolSecurityOverview, { extra: true })).rejects.toThrow('Invalid')
    await expect(
      call(IPC_INVOKE.toolSecurityPreview, { source: '', scope: 'global' })
    ).rejects.toThrow('Invalid')
    await expect(
      call(IPC_INVOKE.toolSecurityPreview, { source: 'npm:x', scope: 'system' })
    ).rejects.toThrow('Invalid')
    await expect(
      call(IPC_INVOKE.toolSecurityApprove, {
        token: 'short',
        decisions: {},
        allowInstallScripts: false,
        acknowledgeDanger: false
      })
    ).rejects.toThrow('Invalid')
    await expect(
      call(IPC_INVOKE.toolSecuritySetDecision, {
        packageId: 'p',
        tool: null,
        capability: 'telepathy',
        decision: 'allow'
      })
    ).rejects.toThrow('Invalid')
    await expect(
      call(IPC_INVOKE.toolSecuritySetDecision, {
        packageId: 'p',
        tool: null,
        capability: 'network',
        decision: 'maybe'
      })
    ).rejects.toThrow('Invalid')
    await expect(call(IPC_INVOKE.toolSecurityCamelRun, { planId: '../x' })).rejects.toThrow(
      'Invalid'
    )
    await expect(
      call(IPC_INVOKE.toolSecurityCamelPlan, { query: 'x', cwd: 'outside' })
    ).rejects.toThrow('Path denied')
    expect(service.preview).not.toHaveBeenCalled()
    expect(service.approve).not.toHaveBeenCalled()
    expect(service.setDecision).not.toHaveBeenCalled()
    expect(camel.plan).not.toHaveBeenCalled()
  })

  it('passes valid requests through', async () => {
    const { call, service, camel } = setup()
    await expect(call(IPC_INVOKE.toolSecurityOverview)).resolves.toMatchObject({ ok: true })
    await call(IPC_INVOKE.toolSecurityPreview, {
      source: 'npm:weather',
      scope: 'project',
      projectRoot: 'repo'
    })
    expect(service.preview).toHaveBeenCalledWith({
      source: 'npm:weather',
      scope: 'project',
      projectRoot: '/abs/repo'
    })
    await expect(
      call(IPC_INVOKE.toolSecurityApprove, {
        token: 'a'.repeat(48),
        decisions: { network: 'ask' },
        allowInstallScripts: false,
        acknowledgeDanger: false
      })
    ).resolves.toEqual({ ok: true, data: { packageId: 'npm:x' } })
    await call(IPC_INVOKE.toolSecuritySetDecision, {
      packageId: 'p',
      tool: 'weather_lookup',
      capability: 'network',
      decision: null
    })
    expect(service.setDecision).toHaveBeenCalledWith({
      packageId: 'p',
      tool: 'weather_lookup',
      capability: 'network',
      decision: null
    })
    await call(IPC_INVOKE.toolSecurityCamelPlan, { query: 'read notes', cwd: 'repo' })
    expect(camel.plan).toHaveBeenCalledWith('read notes', '/abs/repo')
    await call(IPC_INVOKE.toolSecurityCamelRun, { planId: 'f'.repeat(32) })
    expect(camel.run).toHaveBeenCalledWith('f'.repeat(32))
  })
})

describe('reviewedPackageMutation', () => {
  const result = (source: string) => ({
    source,
    scope: 'global' as const,
    action: 'install' as const,
    ok: true,
    skipped: false,
    message: 'ok',
    stdout: '',
    stderr: '',
    errorCode: null,
    logs: []
  })

  it('refuses unreviewed installs before running anything', async () => {
    const security = {
      assertInstallReviewed: vi.fn(() => {
        throw new Error('Review this package’s capabilities before installing it.')
      })
    } as unknown as ToolSecurityService
    const mutate = vi.fn()
    await expect(
      reviewedPackageMutation(security, [{ source: 'npm:x', scope: 'global' }], mutate, vi.fn())
    ).rejects.toThrow(/Review/)
    expect(mutate).not.toHaveBeenCalled()
  })

  it('rolls back an install that differs from the reviewed code', async () => {
    const security = {
      assertInstallReviewed: vi.fn(),
      verifyInstalled: vi.fn(async () => ({ ok: false, reason: 'different' }))
    } as unknown as ToolSecurityService
    const rollback = vi.fn(async () => undefined)
    const [out] = await reviewedPackageMutation(
      security,
      [{ source: 'npm:x', scope: 'global' }],
      async () => [result('npm:x')],
      rollback
    )
    expect(out).toMatchObject({ ok: false, errorCode: 'VERIFY_FAILED', message: 'different' })
    expect(rollback).toHaveBeenCalledWith({ source: 'npm:x', scope: 'global' })
  })
})
