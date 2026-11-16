<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  AlertOctagon,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Loader2,
  ShieldCheck,
  Wrench
} from '@lucide/vue'
import Dialog from '@renderer/components/ui/Dialog.vue'
import Button from '@renderer/components/ui/Button.vue'
import Select from '@renderer/components/ui/Select.vue'
import Switch from '@renderer/components/ui/Switch.vue'
import { useToolInstallReview } from '@renderer/composables/useToolInstallReview'
import { CAPABILITY_CATALOG, RISK_ORDER } from '@shared/tool-security/catalog'
import type {
  CapabilityDecision,
  FindingSeverity,
  ToolCapabilityId
} from '@shared/tool-security/types'

const { t } = useI18n()
const { state, mutable, confirmReview, cancelReview } = useToolInstallReview()
const showFindings = ref(false)

const open = computed({
  get: () => state.open,
  set: (value) => {
    if (!value) cancelReview()
  }
})

const report = computed(() => state.preview?.report ?? null)
const title = computed(() =>
  t('toolSecurity.review.title', { name: report.value?.manifest.name ?? state.source })
)

const capabilities = computed(() =>
  [...(report.value?.capabilities ?? [])].sort(
    (a, b) => RISK_ORDER[CAPABILITY_CATALOG[b].risk] - RISK_ORDER[CAPABILITY_CATALOG[a].risk]
  )
)

const decisionOptions = computed(() =>
  (['allow', 'ask', 'block'] as CapabilityDecision[]).map((value) => ({
    value,
    label: t(`toolSecurity.decision.${value}`)
  }))
)

function decisionFor(id: ToolCapabilityId): string {
  return mutable.decisions[id] ?? 'ask'
}
function setDecision(id: ToolCapabilityId, value: string): void {
  mutable.decisions = { ...mutable.decisions, [id]: value as CapabilityDecision }
}

const scripts = computed(() => Object.entries(report.value?.installScripts ?? {}))
const dangerous = computed(() => report.value?.verdict === 'dangerous')
const canConfirm = computed(
  () =>
    Boolean(state.preview) &&
    !state.loading &&
    !state.submitting &&
    (!dangerous.value || state.acknowledge)
)

const RISK_CLASS: Record<string, string> = {
  low: 'text-[var(--text-tertiary)] border-[var(--border-subtle)]',
  medium:
    'text-[var(--warning,#b7791f)] border-[color-mix(in_srgb,var(--warning,#b7791f)_40%,transparent)]',
  high: 'text-[var(--danger)] border-[color-mix(in_srgb,var(--danger)_40%,transparent)]',
  critical: 'text-white bg-[var(--danger)] border-[var(--danger)]'
}

const SEVERITY_CLASS: Record<FindingSeverity, string> = {
  info: 'text-[var(--text-tertiary)]',
  low: 'text-[var(--text-tertiary)]',
  medium: 'text-[var(--warning,#b7791f)]',
  high: 'text-[var(--danger)]',
  critical: 'text-[var(--danger)] font-semibold'
}

const verdictClass = computed(() => {
  switch (report.value?.verdict) {
    case 'dangerous':
      return 'border-[var(--danger)] bg-[color-mix(in_srgb,var(--danger)_10%,transparent)] text-[var(--danger)]'
    case 'review':
      return 'border-[color-mix(in_srgb,var(--warning,#b7791f)_50%,transparent)] bg-[color-mix(in_srgb,var(--warning,#b7791f)_10%,transparent)] text-[var(--warning,#b7791f)]'
    default:
      return 'border-[color-mix(in_srgb,var(--success,#2f7a3a)_45%,transparent)] bg-[color-mix(in_srgb,var(--success,#2f7a3a)_10%,transparent)] text-[var(--success,#2f7a3a)]'
  }
})
</script>

<template>
  <Dialog v-model:open="open" :title="title" large close-on-escape>
    <div
      class="flex min-h-0 flex-col gap-4 overflow-y-auto px-5 pb-2"
      data-testid="tool-install-review"
    >
      <div
        v-if="state.loading"
        class="flex items-center gap-2 py-8 text-[12.5px] text-[var(--text-secondary)]"
      >
        <Loader2 class="size-4 animate-spin" :stroke-width="1.75" />
        {{ t('toolSecurity.review.scanning') }}
      </div>

      <p
        v-else-if="state.error && !report"
        role="alert"
        class="py-4 text-[12.5px] text-[var(--danger)]"
      >
        {{ t('toolSecurity.review.failed') }} {{ state.error }}
      </p>

      <template v-if="report">
        <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[12px]">
          <dt class="text-[var(--text-tertiary)]">{{ t('toolSecurity.review.publisher') }}</dt>
          <dd class="text-[var(--text-primary)]">{{ report.manifest.author ?? '—' }}</dd>
          <dt class="text-[var(--text-tertiary)]">{{ t('toolSecurity.review.version') }}</dt>
          <dd class="text-[var(--text-primary)]">{{ report.manifest.version ?? '—' }}</dd>
          <dt class="text-[var(--text-tertiary)]">{{ t('toolSecurity.review.license') }}</dt>
          <dd class="text-[var(--text-primary)]">{{ report.manifest.license ?? '—' }}</dd>
          <dt class="text-[var(--text-tertiary)]">{{ t('toolSecurity.review.source') }}</dt>
          <dd class="break-all font-mono text-[11.5px] text-[var(--text-secondary)]">
            {{ state.source }}
          </dd>
        </dl>

        <div
          class="flex items-start gap-2 rounded-[var(--radius-md)] border px-3 py-2 text-[12.5px]"
          :class="verdictClass"
          data-testid="tool-review-verdict"
        >
          <AlertOctagon
            v-if="report.verdict === 'dangerous'"
            class="mt-0.5 size-4 shrink-0"
            :stroke-width="1.75"
          />
          <AlertTriangle
            v-else-if="report.verdict === 'review'"
            class="mt-0.5 size-4 shrink-0"
            :stroke-width="1.75"
          />
          <ShieldCheck v-else class="mt-0.5 size-4 shrink-0" :stroke-width="1.75" />
          <div>
            <div class="font-semibold">{{ t(`toolSecurity.verdict.${report.verdict}`) }}</div>
            <div class="text-[11.5px] opacity-90">
              {{
                t(
                  'toolSecurity.findingsCount',
                  { count: report.findings.length },
                  report.findings.length
                )
              }}
              ·
              {{ t('toolSecurity.review.filesScanned', { count: report.files }) }}
              <span v-if="report.truncated"> · {{ t('toolSecurity.review.truncated') }}</span>
            </div>
          </div>
        </div>

        <section>
          <h3 class="mb-1 text-[12.5px] font-semibold text-[var(--text-primary)]">
            {{ t('toolSecurity.review.canDo') }}
          </h3>
          <p class="mb-2 text-[11.5px] text-[var(--text-tertiary)]">
            {{ t('toolSecurity.review.decisionsHint') }}
          </p>
          <p v-if="!capabilities.length" class="text-[12px] text-[var(--text-secondary)]">
            {{ t('toolSecurity.review.nothing') }}
          </p>
          <ul
            class="divide-y divide-[var(--border-subtle)] rounded-[var(--radius-md)] border border-[var(--border-subtle)]"
          >
            <li
              v-for="id in capabilities"
              :key="id"
              class="flex flex-wrap items-center gap-3 px-3 py-2"
              :data-testid="`tool-review-capability-${id}`"
            >
              <div class="min-w-0 flex-1">
                <div
                  class="flex flex-wrap items-center gap-1.5 text-[12.5px] font-medium text-[var(--text-primary)]"
                >
                  {{ CAPABILITY_CATALOG[id].label }}
                  <span
                    class="rounded-full border px-1.5 py-px text-[10px] font-medium"
                    :class="RISK_CLASS[CAPABILITY_CATALOG[id].risk]"
                  >
                    {{ t(`toolSecurity.risk.${CAPABILITY_CATALOG[id].risk}`) }}
                  </span>
                  <span
                    v-if="report.undeclared.includes(id)"
                    class="rounded-full border border-[var(--danger)] px-1.5 py-px text-[10px] text-[var(--danger)]"
                  >
                    {{ t('toolSecurity.review.undeclared') }}
                  </span>
                </div>
                <p class="text-[11.5px] text-[var(--text-secondary)]">
                  {{ CAPABILITY_CATALOG[id].description }}
                </p>
                <p
                  v-if="id === 'network' && report.networkHosts.length"
                  class="mt-0.5 break-all font-mono text-[10.5px] text-[var(--text-tertiary)]"
                >
                  {{ report.networkHosts.slice(0, 8).join(', ') }}
                </p>
                <p
                  v-if="id === 'env' && report.envVars.length"
                  class="mt-0.5 break-all font-mono text-[10.5px] text-[var(--text-tertiary)]"
                >
                  {{ report.envVars.slice(0, 12).join(', ') }}
                </p>
              </div>
              <Select
                v-if="CAPABILITY_CATALOG[id].gating"
                class="w-[110px]"
                size="sm"
                :aria-label="CAPABILITY_CATALOG[id].label"
                :options="decisionOptions"
                :model-value="decisionFor(id)"
                @update:model-value="(value: string) => setDecision(id, value)"
              />
            </li>
          </ul>
        </section>

        <section
          v-if="scripts.length"
          class="rounded-[var(--radius-md)] border border-[var(--border-subtle)] px-3 py-2"
        >
          <div class="flex items-center justify-between gap-3">
            <div class="min-w-0">
              <div class="text-[12.5px] font-medium text-[var(--text-primary)]">
                {{ t('toolSecurity.review.allowScripts') }}
              </div>
              <p class="break-all font-mono text-[10.5px] text-[var(--text-tertiary)]">
                {{
                  t('toolSecurity.review.allowScriptsHint', {
                    scripts: scripts.map(([name, cmd]) => `${name}: ${cmd}`).join(' · ')
                  })
                }}
              </p>
            </div>
            <Switch v-model="mutable.allowScripts" :label="t('toolSecurity.review.allowScripts')" />
          </div>
        </section>

        <section v-if="report.tools.length">
          <h3 class="mb-1 text-[12.5px] font-semibold text-[var(--text-primary)]">
            {{ t('toolSecurity.review.perTool') }}
          </h3>
          <ul class="flex flex-col gap-1">
            <li
              v-for="tool in report.tools"
              :key="tool.name"
              class="flex flex-wrap items-center gap-1.5 text-[12px]"
            >
              <Wrench class="size-3.5 text-[var(--text-tertiary)]" :stroke-width="1.75" />
              <span class="font-mono text-[var(--text-primary)]">{{ tool.name }}</span>
              <span
                v-for="cap in tool.capabilities"
                :key="cap"
                class="rounded-full border px-1.5 py-px text-[10px]"
                :class="RISK_CLASS[CAPABILITY_CATALOG[cap].risk]"
              >
                {{ CAPABILITY_CATALOG[cap].label }}
              </span>
            </li>
          </ul>
        </section>

        <section v-if="report.findings.length">
          <button
            type="button"
            class="flex items-center gap-1 text-[12.5px] font-semibold text-[var(--text-primary)]"
            :aria-expanded="showFindings"
            @click="showFindings = !showFindings"
          >
            <ChevronDown v-if="showFindings" class="size-3.5" :stroke-width="1.75" />
            <ChevronRight v-else class="size-3.5" :stroke-width="1.75" />
            {{ t('toolSecurity.findings') }} ({{ report.findings.length }})
          </button>
          <ul
            v-if="showFindings"
            class="mt-1 flex flex-col gap-1.5"
            data-testid="tool-review-findings"
          >
            <li v-for="(finding, index) in report.findings" :key="index" class="text-[11.5px]">
              <span :class="SEVERITY_CLASS[finding.severity]">[{{ finding.severity }}]</span>
              <span class="ml-1 font-medium text-[var(--text-primary)]">{{ finding.title }}</span>
              <span v-if="finding.tool" class="ml-1 font-mono text-[var(--text-tertiary)]"
                >({{ finding.tool }})</span
              >
              <div class="text-[var(--text-secondary)]">{{ finding.detail }}</div>
              <div
                v-if="finding.file"
                class="break-all font-mono text-[10.5px] text-[var(--text-tertiary)]"
              >
                {{ finding.file }}<template v-if="finding.line">:{{ finding.line }}</template>
                <template v-if="finding.snippet"> — {{ finding.snippet }}</template>
              </div>
            </li>
          </ul>
        </section>

        <label
          v-if="dangerous"
          class="flex items-start gap-2 rounded-[var(--radius-md)] border border-[var(--danger)] px-3 py-2 text-[12px] text-[var(--danger)]"
        >
          <input
            id="tool-review-acknowledge"
            v-model="mutable.acknowledge"
            type="checkbox"
            class="mt-0.5"
            data-testid="tool-review-acknowledge"
          />
          {{ t('toolSecurity.review.acknowledge') }}
        </label>

        <p v-if="state.error" role="alert" class="text-[12px] text-[var(--danger)]">
          {{ state.error }}
        </p>
      </template>
    </div>

    <template #footer>
      <Button variant="ghost" @click="cancelReview()">{{ t('toolSecurity.review.cancel') }}</Button>
      <Button
        :variant="dangerous ? 'danger' : 'primary'"
        :disabled="!canConfirm"
        :loading="state.submitting"
        data-testid="tool-review-confirm"
        @click="confirmReview()"
      >
        {{
          state.action === 'update'
            ? t('toolSecurity.review.update')
            : t('toolSecurity.review.install')
        }}
      </Button>
    </template>
  </Dialog>
</template>
