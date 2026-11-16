import { z } from 'zod'
import { TOOL_CAPABILITY_IDS } from './types'
import type { CamelPlan, CamelValue, ToolSecuritySettings } from './types'

export const capabilityIdSchema = z.enum(TOOL_CAPABILITY_IDS)
export const capabilityDecisionSchema = z.enum(['allow', 'ask', 'block'])
export const capabilityDecisionMapSchema = z
  .partialRecord(capabilityIdSchema, capabilityDecisionSchema)
  .optional()
  .default({})

const toolNameSchema = z.string().trim().min(1).max(128)
const sourceSchema = z
  .string()
  .trim()
  .min(1)
  .max(4096)
  .refine((value) => !value.includes('\0'))

export const toolSecuritySettingsSchema: z.ZodType<ToolSecuritySettings> = z
  .object({
    schemaVersion: z.literal(1),
    capabilityDefaults: z.record(capabilityIdSchema, capabilityDecisionSchema),
    unreviewedTools: capabilityDecisionSchema,
    requireReviewBeforeInstall: z.boolean(),
    blockInstallScripts: z.boolean(),
    quarantineDangerous: z.boolean(),
    provenance: z
      .object({
        enabled: z.boolean(),
        workspaceFilesUntrusted: z.boolean(),
        sinkWhenTainted: capabilityDecisionSchema,
        untrustedArgument: capabilityDecisionSchema
      })
      .strict(),
    camel: z
      .object({
        enabled: z.boolean(),
        model: z
          .object({
            providerKey: z.string().min(1).max(128),
            modelId: z.string().min(1).max(256)
          })
          .strict()
          .nullable()
      })
      .strict()
  })
  .strict() as z.ZodType<ToolSecuritySettings>

export const toolPreviewInputSchema = z
  .object({
    source: sourceSchema,
    scope: z.enum(['global', 'project']),
    projectRoot: z.string().min(1).max(4096).nullable().optional()
  })
  .strict()

export const toolApprovalInputSchema = z
  .object({
    token: z.string().regex(/^[a-f0-9]{48}$/),
    decisions: capabilityDecisionMapSchema,
    allowInstallScripts: z.boolean(),
    acknowledgeDanger: z.boolean()
  })
  .strict()

export const toolDecisionInputSchema = z
  .object({
    packageId: z.string().min(1).max(4200),
    tool: toolNameSchema.nullable(),
    capability: capabilityIdSchema,
    decision: capabilityDecisionSchema.nullable()
  })
  .strict()

export const toolPackageTargetSchema = z.object({ packageId: z.string().min(1).max(4200) }).strict()

export const sessionTargetSchema = z.object({ sessionId: z.string().min(1).max(200) }).strict()

// ------------------------------------------------------------------ CaMeL

const STEP_ID = /^[a-z][a-z0-9_]{0,31}$/

export const camelValueSchema: z.ZodType<CamelValue> = z.lazy(() =>
  z.union([
    z.string().max(20_000),
    z.number(),
    z.boolean(),
    z.null(),
    z.object({ ref: z.string().regex(STEP_ID), field: z.string().max(64).optional() }).strict(),
    z.object({ concat: z.array(camelValueSchema).max(50) }).strict(),
    z.object({ list: z.array(camelValueSchema).max(50) }).strict()
  ])
)

const camelFieldTypeSchema = z.union([
  z.enum(['string', 'number', 'boolean']),
  z.object({ enum: z.array(z.string().min(1).max(100)).min(1).max(30) }).strict(),
  z.object({ list: z.literal('string') }).strict()
])

const camelToolStepSchema = z
  .object({
    id: z.string().regex(STEP_ID),
    tool: z.string().min(1).max(64),
    args: z.record(z.string().min(1).max(64), camelValueSchema)
  })
  .strict()

const camelExtractStepSchema = z
  .object({
    id: z.string().regex(STEP_ID),
    extract: z
      .object({
        from: camelValueSchema,
        instructions: z.string().min(1).max(2000),
        schema: z.record(z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]{0,31}$/), camelFieldTypeSchema)
      })
      .strict()
  })
  .strict()

export const camelPlanSchema: z.ZodType<CamelPlan> = z
  .object({
    goal: z.string().min(1).max(2000),
    steps: z.array(z.union([camelToolStepSchema, camelExtractStepSchema])).max(30),
    output: camelValueSchema
  })
  .strict() as z.ZodType<CamelPlan>

export const camelPlanInputSchema = z
  .object({ query: z.string().trim().min(1).max(8000), cwd: z.string().min(1).max(4096) })
  .strict()

export const camelRunInputSchema = z.object({ planId: z.string().regex(/^[a-f0-9]{32}$/) }).strict()
