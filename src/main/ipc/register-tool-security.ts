import { z } from 'zod'
import { IPC_INVOKE } from '@shared/ipc/channels'
import {
  camelPlanInputSchema,
  camelRunInputSchema,
  sessionTargetSchema,
  toolApprovalInputSchema,
  toolDecisionInputSchema,
  toolPackageTargetSchema,
  toolPreviewInputSchema
} from '@shared/tool-security/schema'
import { ValidationError } from '../services/errors'
import type { CamelEngine } from '../tool-security/camel/engine'
import type { ProvenanceTracker } from '../tool-security/provenance'
import type { ToolSecurityService } from '../tool-security/service'
import type { IpcHandleRegistrar } from './trusted-ipc'

type Wrap = <T>(
  fn: () => Promise<T>
) => Promise<{ ok: true; data: T } | { ok: false; error: unknown }>

export interface ToolSecurityIpcServices {
  service: ToolSecurityService
  provenance: ProvenanceTracker
  camel: CamelEngine
  /** Resolve a renderer-supplied folder to an authorized absolute path. */
  authorizeFolder: (folder: string) => Promise<string>
}

function parse<T>(schema: z.ZodType<T>, value: unknown, message: string): T {
  const result = schema.safeParse(value)
  if (!result.success) throw new ValidationError(message, { issues: result.error.issues })
  return result.data
}

const none = z.undefined()
const blockedSchema = z
  .object({ packageId: z.string().min(1).max(4200), blocked: z.boolean() })
  .strict()

export function registerToolSecurityIpc(
  ipc: IpcHandleRegistrar,
  wrap: Wrap,
  services: ToolSecurityIpcServices
): void {
  const { service, provenance, camel } = services
  ipc.handle(IPC_INVOKE.toolSecurityOverview, (_e, input: unknown) =>
    wrap(async () => {
      parse(none, input, 'Invalid tool security request')
      return service.overview()
    })
  )
  ipc.handle(IPC_INVOKE.toolSecuritySettingsUpdate, (_e, input: unknown) =>
    wrap(() => service.updateSettings(input))
  )
  ipc.handle(IPC_INVOKE.toolSecurityPreview, (_e, input: unknown) =>
    wrap(async () => {
      const parsed = parse(toolPreviewInputSchema, input, 'Invalid package to review')
      const projectRoot = parsed.projectRoot
        ? await services.authorizeFolder(parsed.projectRoot)
        : null
      return service.preview({ ...parsed, projectRoot })
    })
  )
  ipc.handle(IPC_INVOKE.toolSecurityApprove, (_e, input: unknown) =>
    wrap(async () => {
      const result = await service.approve(
        parse(toolApprovalInputSchema, input, 'Invalid approval')
      )
      return { packageId: result.packageId }
    })
  )
  ipc.handle(IPC_INVOKE.toolSecuritySetDecision, (_e, input: unknown) =>
    wrap(() =>
      service.setDecision(parse(toolDecisionInputSchema, input, 'Invalid capability decision'))
    )
  )
  ipc.handle(IPC_INVOKE.toolSecurityApproveInstalled, (_e, input: unknown) =>
    wrap(() =>
      service.approveInstalled(parse(toolPackageTargetSchema, input, 'Invalid package').packageId)
    )
  )
  ipc.handle(IPC_INVOKE.toolSecuritySetBlocked, (_e, input: unknown) =>
    wrap(async () => {
      const parsed = parse(blockedSchema, input, 'Invalid package')
      return service.setBlocked(parsed.packageId, parsed.blocked)
    })
  )
  ipc.handle(IPC_INVOKE.toolSecurityProvenance, (_e, input: unknown) =>
    wrap(async () =>
      provenance.status(parse(sessionTargetSchema, input, 'Invalid session').sessionId)
    )
  )
  ipc.handle(IPC_INVOKE.toolSecurityCamelPlan, (_e, input: unknown) =>
    wrap(async () => {
      const parsed = parse(camelPlanInputSchema, input, 'Invalid secure planner request')
      return camel.plan(parsed.query, await services.authorizeFolder(parsed.cwd))
    })
  )
  ipc.handle(IPC_INVOKE.toolSecurityCamelRun, (_e, input: unknown) =>
    wrap(() => camel.run(parse(camelRunInputSchema, input, 'Invalid plan').planId))
  )
}
