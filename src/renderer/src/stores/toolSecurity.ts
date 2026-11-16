import { defineStore } from 'pinia'
import { ref } from 'vue'
import { getApi } from '@renderer/composables/useApi'
import type {
  CamelPlanResult,
  CamelRunResult,
  CamelStepEvent,
  CapabilityDecision,
  ToolCapabilityId,
  ToolPackageRecord,
  ToolSecuritySettings
} from '@shared/tool-security/types'

function errorText(error: unknown): string {
  return (
    (error as { userMessage?: string })?.userMessage ??
    (error as { message?: string })?.message ??
    String(error)
  )
}

export const useToolSecurityStore = defineStore('toolSecurity', () => {
  const settings = ref<ToolSecuritySettings | null>(null)
  const packages = ref<ToolPackageRecord[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)

  const plan = ref<CamelPlanResult | null>(null)
  const run = ref<CamelRunResult | null>(null)
  const steps = ref<Record<string, CamelStepEvent>>({})
  const planning = ref(false)
  const running = ref(false)
  const plannerError = ref<string | null>(null)
  let unsubscribe: (() => void) | null = null

  async function load(): Promise<void> {
    loading.value = true
    error.value = null
    try {
      const overview = await getApi().toolSecurity.overview()
      settings.value = overview.settings
      packages.value = overview.packages
    } catch (e) {
      error.value = errorText(e)
    } finally {
      loading.value = false
    }
  }

  async function saveSettings(next: ToolSecuritySettings): Promise<void> {
    settings.value = await getApi().toolSecurity.updateSettings(JSON.parse(JSON.stringify(next)))
  }

  function replace(record: ToolPackageRecord): void {
    packages.value = packages.value.map((existing) =>
      existing.id === record.id ? record : existing
    )
  }

  async function setDecision(
    packageId: string,
    tool: string | null,
    capability: ToolCapabilityId,
    decision: CapabilityDecision | null
  ): Promise<void> {
    replace(await getApi().toolSecurity.setDecision({ packageId, tool, capability, decision }))
  }

  async function approveInstalled(packageId: string): Promise<void> {
    replace(await getApi().toolSecurity.approveInstalled(packageId))
  }

  async function setBlocked(packageId: string, blocked: boolean): Promise<void> {
    replace(await getApi().toolSecurity.setBlocked(packageId, blocked))
  }

  function listen(): void {
    unsubscribe ??= getApi().toolSecurity.onCamelStep((event) => {
      if (plan.value && event.planId === plan.value.planId)
        steps.value = { ...steps.value, [event.stepId]: event }
    })
  }

  async function createPlan(query: string, cwd: string): Promise<void> {
    listen()
    planning.value = true
    plannerError.value = null
    run.value = null
    steps.value = {}
    try {
      plan.value = await getApi().toolSecurity.camelPlan({ query, cwd })
    } catch (e) {
      plannerError.value = errorText(e)
      plan.value = null
    } finally {
      planning.value = false
    }
  }

  async function runPlan(): Promise<void> {
    if (!plan.value) return
    listen()
    running.value = true
    plannerError.value = null
    steps.value = {}
    try {
      run.value = await getApi().toolSecurity.camelRun(plan.value.planId)
    } catch (e) {
      plannerError.value = errorText(e)
    } finally {
      running.value = false
    }
  }

  return {
    settings,
    packages,
    loading,
    error,
    load,
    saveSettings,
    setDecision,
    approveInstalled,
    setBlocked,
    plan,
    run,
    steps,
    planning,
    running,
    plannerError,
    createPlan,
    runPlan
  }
})
