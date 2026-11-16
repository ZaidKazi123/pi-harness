<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { ChevronDown, ChevronRight, RefreshCw, ShieldAlert, Wrench } from '@lucide/vue'
import Button from '@renderer/components/ui/Button.vue'
import Select from '@renderer/components/ui/Select.vue'
import Switch from '@renderer/components/ui/Switch.vue'
import { toast } from 'vue-sonner'
import { useToolSecurityStore } from '@renderer/stores/toolSecurity'
import { CAPABILITY_CATALOG } from '@shared/tool-security/catalog'
import {
  TOOL_CAPABILITY_IDS,
  type CapabilityDecision,
  type ToolCapabilityId,
  type ToolPackageRecord,
  type ToolSecuritySettings
} from '@shared/tool-security/types'

const { t } = useI18n()
const router = useRouter()
const store = useToolSecurityStore()
const expanded = ref<Record<string, boolean>>({})
const findingsOpen = ref<Record<string, boolean>>({})

onMounted(() => void store.load())

const gating = TOOL_CAPABILITY_IDS.filter((id) => CAPABILITY_CATALOG[id].gating)

const decisionOptions = computed(() =>
  (['allow', 'ask', 'block'] as CapabilityDecision[]).map((value) => ({
    value,
    label: t(`toolSecurity.decision.${value}`)
  }))
)

function inheritOptions(inherited: CapabilityDecision) {
  return [
    {
      value: '',
      label: t('toolSecurity.decision.inherit', { value: t(`toolSecurity.decision.${inherited}`) })
    },
    ...decisionOptions.value
  ]
}

async function update(mutator: (draft: ToolSecuritySettings) => void): Promise<void> {
  if (!store.settings) return
  const draft = JSON.parse(JSON.stringify(store.settings)) as ToolSecuritySettings
  mutator(draft)
  try {
    await store.saveSettings(draft)
  } catch (error) {
    toast.error((error as { message?: string }).message ?? t('toolSecurity.loadFailed'))
  }
}

function packageName(record: ToolPackageRecord): string {
  return record.report?.manifest.name ?? record.source
}

function packageCaps(record: ToolPackageRecord): ToolCapabilityId[] {
  return (record.report?.capabilities ?? []).filter((id) => CAPABILITY_CATALOG[id].gating)
}

function packageInherited(id: ToolCapabilityId): CapabilityDecision {
  return store.settings?.capabilityDefaults[id] ?? 'ask'
}

function toolInherited(record: ToolPackageRecord, id: ToolCapabilityId): CapabilityDecision {
  return record.decisions[id] ?? packageInherited(id)
}

async function setPackageDecision(
  record: ToolPackageRecord,
  tool: string | null,
  id: ToolCapabilityId,
  value: string
) {
  try {
    await store.setDecision(
      record.id,
      tool,
      id,
      value === '' ? null : (value as CapabilityDecision)
    )
    toast.success(t('toolSecurity.saved'))
  } catch (error) {
    toast.error((error as { message?: string }).message ?? String(error))
  }
}

async function run(action: () => Promise<void>): Promise<void> {
  try {
    await action()
    toast.success(t('toolSecurity.saved'))
  } catch (error) {
    toast.error(
      (error as { userMessage?: string; message?: string }).userMessage ??
        (error as { message?: string }).message ??
        String(error)
    )
  }
}

const STATUS_CLASS: Record<string, string> = {
  approved: 'text-[var(--success)] border-[color-mix(in_srgb,var(--success)_40%,transparent)]',
  unreviewed: 'text-[var(--warning)] border-[color-mix(in_srgb,var(--warning)_40%,transparent)]',
  changed: 'text-[var(--warning)] border-[color-mix(in_srgb,var(--warning)_40%,transparent)]',
  blocked: 'text-[var(--danger)] border-[color-mix(in_srgb,var(--danger)_40%,transparent)]'
}
const VERDICT_CLASS: Record<string, string> = {
  clean: 'text-[var(--text-tertiary)]',
  review: 'text-[var(--warning)]',
  dangerous: 'text-[var(--danger)] font-semibold'
}
const RISK_CLASS: Record<string, string> = {
  low: 'text-[var(--text-tertiary)]',
  medium: 'text-[var(--warning)]',
  high: 'text-[var(--danger)]',
  critical: 'text-[var(--danger)] font-semibold'
}

const sectionClass =
  'overflow-hidden rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-surface)]'
const rowClass =
  'flex flex-wrap items-center gap-3 border-t border-[var(--border-subtle)] px-3 py-2 first:border-t-0'
</script>

<template>
  <div class="flex flex-col gap-4" data-testid="tool-security-settings">
    <p v-if="store.error" role="alert" class="text-[12px] text-[var(--danger)]">
      {{ t('toolSecurity.loadFailed') }} {{ store.error }}
    </p>

    <template v-if="store.settings">
      <!-- Install review -->
      <section :class="sectionClass">
        <div :class="rowClass">
          <div class="min-w-0 flex-1">
            <div class="text-[12.5px] text-[var(--text-primary)]">
              {{ t('toolSecurity.requireReview') }}
            </div>
            <p class="text-[11px] text-[var(--text-tertiary)]">
              {{ t('toolSecurity.requireReviewHint') }}
            </p>
          </div>
          <Switch
            :model-value="store.settings.requireReviewBeforeInstall"
            :label="t('toolSecurity.requireReview')"
            @update:model-value="(v: boolean) => update((d) => (d.requireReviewBeforeInstall = v))"
          />
        </div>
        <div :class="rowClass">
          <div class="min-w-0 flex-1">
            <div class="text-[12.5px] text-[var(--text-primary)]">
              {{ t('toolSecurity.blockInstallScripts') }}
            </div>
            <p class="text-[11px] text-[var(--text-tertiary)]">
              {{ t('toolSecurity.blockInstallScriptsHint') }}
            </p>
          </div>
          <Switch
            :model-value="store.settings.blockInstallScripts"
            :label="t('toolSecurity.blockInstallScripts')"
            @update:model-value="(v: boolean) => update((d) => (d.blockInstallScripts = v))"
          />
        </div>
        <div :class="rowClass">
          <div class="min-w-0 flex-1">
            <div class="text-[12.5px] text-[var(--text-primary)]">
              {{ t('toolSecurity.quarantineDangerous') }}
            </div>
            <p class="text-[11px] text-[var(--text-tertiary)]">
              {{ t('toolSecurity.quarantineDangerousHint') }}
            </p>
          </div>
          <Switch
            :model-value="store.settings.quarantineDangerous"
            :label="t('toolSecurity.quarantineDangerous')"
            @update:model-value="(v: boolean) => update((d) => (d.quarantineDangerous = v))"
          />
        </div>
        <div :class="rowClass">
          <div class="min-w-0 flex-1 text-[12.5px] text-[var(--text-primary)]">
            {{ t('toolSecurity.unreviewedTools') }}
          </div>
          <Select
            class="w-[120px]"
            size="sm"
            :aria-label="t('toolSecurity.unreviewedTools')"
            :options="decisionOptions"
            :model-value="store.settings.unreviewedTools"
            @update:model-value="
              (v: string) => update((d) => (d.unreviewedTools = v as CapabilityDecision))
            "
          />
        </div>
      </section>

      <!-- Capability defaults -->
      <section>
        <h3 class="mb-0.5 text-[12.5px] font-semibold text-[var(--text-primary)]">
          {{ t('toolSecurity.defaultsTitle') }}
        </h3>
        <p class="mb-2 text-[11px] text-[var(--text-tertiary)]">
          {{ t('toolSecurity.defaultsHint') }}
        </p>
        <div :class="sectionClass">
          <div
            v-for="id in gating"
            :key="id"
            :class="rowClass"
            :data-testid="`tool-security-default-${id}`"
          >
            <div class="min-w-0 flex-1">
              <div class="text-[12.5px] text-[var(--text-primary)]">
                {{ CAPABILITY_CATALOG[id].label }}
                <span class="ml-1 text-[10.5px]" :class="RISK_CLASS[CAPABILITY_CATALOG[id].risk]">
                  {{ t(`toolSecurity.risk.${CAPABILITY_CATALOG[id].risk}`) }}
                </span>
              </div>
              <p class="text-[11px] text-[var(--text-tertiary)]">
                {{ CAPABILITY_CATALOG[id].description }}
              </p>
            </div>
            <Select
              class="w-[120px]"
              size="sm"
              :aria-label="CAPABILITY_CATALOG[id].label"
              :options="decisionOptions"
              :model-value="store.settings.capabilityDefaults[id]"
              @update:model-value="
                (v: string) => update((d) => (d.capabilityDefaults[id] = v as CapabilityDecision))
              "
            />
          </div>
        </div>
      </section>

      <!-- Untrusted data -->
      <section>
        <h3 class="mb-0.5 text-[12.5px] font-semibold text-[var(--text-primary)]">
          {{ t('toolSecurity.provenanceTitle') }}
        </h3>
        <p class="mb-2 text-[11px] text-[var(--text-tertiary)]">
          {{ t('toolSecurity.provenanceHint') }}
        </p>
        <div :class="sectionClass">
          <div :class="rowClass">
            <div class="min-w-0 flex-1 text-[12.5px] text-[var(--text-primary)]">
              {{ t('toolSecurity.provenanceEnabled') }}
            </div>
            <Switch
              :model-value="store.settings.provenance.enabled"
              :label="t('toolSecurity.provenanceEnabled')"
              @update:model-value="(v: boolean) => update((d) => (d.provenance.enabled = v))"
            />
          </div>
          <div :class="rowClass">
            <div class="min-w-0 flex-1">
              <div class="text-[12.5px] text-[var(--text-primary)]">
                {{ t('toolSecurity.workspaceUntrusted') }}
              </div>
              <p class="text-[11px] text-[var(--text-tertiary)]">
                {{ t('toolSecurity.workspaceUntrustedHint') }}
              </p>
            </div>
            <Switch
              :model-value="store.settings.provenance.workspaceFilesUntrusted"
              :label="t('toolSecurity.workspaceUntrusted')"
              @update:model-value="
                (v: boolean) => update((d) => (d.provenance.workspaceFilesUntrusted = v))
              "
            />
          </div>
          <div :class="rowClass">
            <div class="min-w-0 flex-1 text-[12.5px] text-[var(--text-primary)]">
              {{ t('toolSecurity.sinkWhenTainted') }}
            </div>
            <Select
              class="w-[120px]"
              size="sm"
              :aria-label="t('toolSecurity.sinkWhenTainted')"
              :options="decisionOptions"
              :model-value="store.settings.provenance.sinkWhenTainted"
              @update:model-value="
                (v: string) =>
                  update((d) => (d.provenance.sinkWhenTainted = v as CapabilityDecision))
              "
            />
          </div>
          <div :class="rowClass">
            <div class="min-w-0 flex-1 text-[12.5px] text-[var(--text-primary)]">
              {{ t('toolSecurity.untrustedArgument') }}
            </div>
            <Select
              class="w-[120px]"
              size="sm"
              :aria-label="t('toolSecurity.untrustedArgument')"
              :options="decisionOptions"
              :model-value="store.settings.provenance.untrustedArgument"
              @update:model-value="
                (v: string) =>
                  update((d) => (d.provenance.untrustedArgument = v as CapabilityDecision))
              "
            />
          </div>
        </div>
      </section>

      <!-- Secure planner -->
      <section :class="sectionClass">
        <div :class="rowClass">
          <div class="min-w-0 flex-1">
            <div class="text-[12.5px] text-[var(--text-primary)]">
              {{ t('toolSecurity.plannerToggle') }}
            </div>
            <p class="text-[11px] text-[var(--text-tertiary)]">
              {{ t('toolSecurity.plannerHint') }} {{ t('toolSecurity.plannerToggleHint') }}
            </p>
          </div>
          <Button
            v-if="store.settings.camel.enabled"
            variant="ghost"
            size="sm"
            @click="router.push('/settings/secure-planner')"
          >
            {{ t('toolSecurity.navPlanner') }}
          </Button>
          <Switch
            :model-value="store.settings.camel.enabled"
            :label="t('toolSecurity.plannerToggle')"
            data-testid="tool-security-camel-toggle"
            @update:model-value="(v: boolean) => update((d) => (d.camel.enabled = v))"
          />
        </div>
      </section>

      <!-- Installed packages -->
      <section>
        <div class="mb-2 flex items-center justify-between gap-2">
          <h3 class="text-[12.5px] font-semibold text-[var(--text-primary)]">
            {{ t('toolSecurity.packagesTitle') }}
          </h3>
          <Button variant="ghost" size="sm" :loading="store.loading" @click="store.load()">
            <RefreshCw class="size-3.5" :stroke-width="1.75" />
            {{ t('toolSecurity.refresh') }}
          </Button>
        </div>
        <p
          v-if="!store.packages.length && !store.loading"
          class="text-[12px] text-[var(--text-tertiary)]"
        >
          {{ t('toolSecurity.packagesEmpty') }}
        </p>
        <ul class="flex flex-col gap-2">
          <li
            v-for="record in store.packages"
            :key="record.id"
            :class="sectionClass"
            :data-testid="`tool-security-package-${packageName(record)}`"
          >
            <div class="flex flex-wrap items-center gap-2 px-3 py-2">
              <button
                type="button"
                class="flex min-w-0 flex-1 items-center gap-1.5 text-left"
                :aria-expanded="Boolean(expanded[record.id])"
                @click="expanded = { ...expanded, [record.id]: !expanded[record.id] }"
              >
                <ChevronDown
                  v-if="expanded[record.id]"
                  class="size-3.5 shrink-0"
                  :stroke-width="1.75"
                />
                <ChevronRight v-else class="size-3.5 shrink-0" :stroke-width="1.75" />
                <span class="truncate text-[12.5px] font-medium text-[var(--text-primary)]">{{
                  packageName(record)
                }}</span>
                <span
                  v-if="record.report?.manifest.version"
                  class="text-[11px] text-[var(--text-tertiary)]"
                >
                  {{ record.report.manifest.version }}
                </span>
              </button>
              <span
                class="rounded-full border px-1.5 py-px text-[10.5px]"
                :class="STATUS_CLASS[record.status]"
              >
                {{ t(`toolSecurity.status.${record.status}`) }}
              </span>
              <span
                v-if="record.report"
                class="text-[10.5px]"
                :class="VERDICT_CLASS[record.report.verdict]"
              >
                <ShieldAlert
                  v-if="record.report.verdict !== 'clean'"
                  class="mr-0.5 inline size-3"
                  :stroke-width="1.75"
                />
                {{ t(`toolSecurity.verdict.${record.report.verdict}`) }}
              </span>
              <span
                v-if="record.quarantined"
                class="text-[10.5px] font-semibold text-[var(--danger)]"
                data-testid="tool-security-quarantined"
                >{{ t('toolSecurity.quarantined') }}</span
              >
              <span
                v-else-if="!record.installPath && record.status !== 'blocked'"
                class="text-[10.5px] text-[var(--text-tertiary)]"
                >(not installed)</span
              >
              <Button
                v-if="record.status === 'unreviewed' || record.status === 'changed'"
                size="sm"
                variant="secondary"
                @click="run(() => store.approveInstalled(record.id))"
              >
                {{ t('toolSecurity.approveCurrent') }}
              </Button>
              <Button
                v-if="record.quarantined"
                size="sm"
                variant="secondary"
                @click="run(() => store.approveInstalled(record.id))"
              >
                {{ t('toolSecurity.approveAndEnable') }}
              </Button>
              <Button
                v-else
                size="sm"
                :variant="record.status === 'blocked' ? 'secondary' : 'ghost'"
                @click="run(() => store.setBlocked(record.id, record.status !== 'blocked'))"
              >
                {{
                  record.status === 'blocked' ? t('toolSecurity.unblock') : t('toolSecurity.block')
                }}
              </Button>
            </div>

            <div
              v-if="expanded[record.id]"
              class="border-t border-[var(--border-subtle)] px-3 py-2"
            >
              <p class="mb-2 break-all font-mono text-[10.5px] text-[var(--text-tertiary)]">
                {{ record.source }} · {{ t('toolSecurity.digest') }}
                {{ record.report?.digest.slice(0, 12) ?? '—' }}
              </p>

              <!-- Package-wide decisions -->
              <div v-if="packageCaps(record).length" class="mb-3">
                <div class="mb-1 text-[11.5px] font-semibold text-[var(--text-secondary)]">
                  {{ t('toolSecurity.packageDefaults') }}
                </div>
                <div class="flex flex-wrap gap-2">
                  <label
                    v-for="id in packageCaps(record)"
                    :key="id"
                    class="flex items-center gap-1.5 text-[11.5px] text-[var(--text-primary)]"
                  >
                    {{ CAPABILITY_CATALOG[id].label }}
                    <Select
                      class="w-[132px]"
                      size="sm"
                      :aria-label="`${packageName(record)} ${CAPABILITY_CATALOG[id].label}`"
                      :options="inheritOptions(packageInherited(id))"
                      :model-value="record.decisions[id] ?? ''"
                      @update:model-value="(v: string) => setPackageDecision(record, null, id, v)"
                    />
                  </label>
                </div>
              </div>

              <!-- Per-tool decisions -->
              <div class="mb-1 text-[11.5px] font-semibold text-[var(--text-secondary)]">
                {{ t('toolSecurity.tools') }}
              </div>
              <p
                v-if="!record.report?.tools.length"
                class="text-[11.5px] text-[var(--text-tertiary)]"
              >
                {{ t('toolSecurity.noTools') }}
              </p>
              <div
                v-for="tool in record.report?.tools ?? []"
                :key="tool.name"
                class="mb-2 rounded-[var(--radius-sm)] border border-[var(--border-subtle)] px-2 py-1.5"
                :data-testid="`tool-security-tool-${tool.name}`"
              >
                <div
                  class="mb-1 flex items-center gap-1.5 text-[12px] font-mono text-[var(--text-primary)]"
                >
                  <Wrench class="size-3.5 text-[var(--text-tertiary)]" :stroke-width="1.75" />
                  {{ tool.name }}
                </div>
                <div class="flex flex-wrap gap-2">
                  <label
                    v-for="id in tool.capabilities.filter((cap) => CAPABILITY_CATALOG[cap].gating)"
                    :key="id"
                    class="flex items-center gap-1.5 text-[11.5px] text-[var(--text-secondary)]"
                  >
                    {{ CAPABILITY_CATALOG[id].label }}
                    <Select
                      class="w-[132px]"
                      size="sm"
                      :aria-label="`${tool.name} ${CAPABILITY_CATALOG[id].label}`"
                      :options="inheritOptions(toolInherited(record, id))"
                      :model-value="record.toolDecisions[tool.name]?.[id] ?? ''"
                      @update:model-value="
                        (v: string) => setPackageDecision(record, tool.name, id, v)
                      "
                    />
                  </label>
                </div>
              </div>

              <div
                v-if="record.report?.networkHosts.length"
                class="text-[11px] text-[var(--text-tertiary)]"
              >
                {{ t('toolSecurity.hosts') }}:
                <span class="font-mono">{{
                  record.report.networkHosts.slice(0, 10).join(', ')
                }}</span>
              </div>
              <div
                v-if="record.report?.envVars.length"
                class="text-[11px] text-[var(--text-tertiary)]"
              >
                {{ t('toolSecurity.envVars') }}:
                <span class="font-mono">{{ record.report.envVars.slice(0, 12).join(', ') }}</span>
              </div>
              <div
                v-if="record.report?.dependencies"
                class="text-[11px] text-[var(--text-tertiary)]"
              >
                {{ t('toolSecurity.dependencies', { count: record.report.dependencies.packages }) }}
                ·
                <span :class="VERDICT_CLASS[record.report.dependencies.verdict]">
                  {{ t(`toolSecurity.verdict.${record.report.dependencies.verdict}`) }}
                </span>
              </div>

              <template v-if="record.report?.findings.length">
                <button
                  type="button"
                  class="mt-2 text-[11.5px] text-[var(--accent)]"
                  @click="findingsOpen = { ...findingsOpen, [record.id]: !findingsOpen[record.id] }"
                >
                  {{
                    findingsOpen[record.id]
                      ? t('toolSecurity.hideFindings')
                      : t('toolSecurity.showFindings')
                  }}
                  ({{
                    t(
                      'toolSecurity.findingsCount',
                      { count: record.report.findings.length },
                      record.report.findings.length
                    )
                  }})
                </button>
                <ul v-if="findingsOpen[record.id]" class="mt-1 flex flex-col gap-1">
                  <li
                    v-for="(finding, index) in record.report.findings"
                    :key="index"
                    class="text-[11px]"
                  >
                    <span :class="RISK_CLASS[finding.severity] ?? ''"
                      >[{{ finding.severity }}]</span
                    >
                    <span class="ml-1 text-[var(--text-primary)]">{{ finding.title }}</span>
                    <span v-if="finding.file" class="ml-1 font-mono text-[var(--text-tertiary)]">
                      {{ finding.file }}<template v-if="finding.line">:{{ finding.line }}</template>
                    </span>
                  </li>
                </ul>
              </template>
            </div>
          </li>
        </ul>
      </section>
    </template>
  </div>
</template>
