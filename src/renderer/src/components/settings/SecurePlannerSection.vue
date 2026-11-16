<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Lock, Play, ShieldQuestion, Sparkles } from '@lucide/vue'
import Button from '@renderer/components/ui/Button.vue'
import { useToolSecurityStore } from '@renderer/stores/toolSecurity'
import { useWorkspaceStore } from '@renderer/stores/workspace'
import type { CamelStep, CamelValue } from '@shared/tool-security/types'

const { t } = useI18n()
const store = useToolSecurityStore()
const workspace = useWorkspaceStore()
const query = ref('')
const folder = ref('')

onMounted(async () => {
  await store.load()
  folder.value = workspace.currentCwd ?? ''
})

const enabled = computed(() => Boolean(store.settings?.camel.enabled))

function describeValue(value: CamelValue): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if ('ref' in value) return value.field ? `⟨${value.ref}.${value.field}⟩` : `⟨${value.ref}⟩`
  if ('concat' in value) return value.concat.map(describeValue).join(' + ')
  return `[${value.list.map(describeValue).join(', ')}]`
}

function describeStep(step: CamelStep): string {
  if ('extract' in step)
    return `${t('toolSecurity.planner.extract')} ${describeValue(step.extract.from)} → { ${Object.keys(step.extract.schema).join(', ')} }`
  return `${step.tool}(${Object.entries(step.args)
    .map(([key, value]) => `${key}: ${describeValue(value)}`)
    .join(', ')})`
}

const STATUS_CLASS: Record<string, string> = {
  pending: 'text-[var(--text-tertiary)]',
  running: 'text-[var(--accent)]',
  done: 'text-[var(--success)]',
  blocked: 'text-[var(--danger)] font-semibold',
  failed: 'text-[var(--danger)]',
  skipped: 'text-[var(--text-tertiary)]'
}

async function plan(): Promise<void> {
  if (!query.value.trim() || !folder.value.trim()) return
  await store.createPlan(query.value.trim(), folder.value.trim())
}

const sectionClass =
  'overflow-hidden rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-3'
const inputClass =
  'w-full rounded-[var(--radius-sm)] border border-[var(--control-border)] bg-[var(--control-bg)] px-2.5 py-1.5 text-[12.5px] text-[var(--text-primary)] focus:border-[var(--accent)] focus:outline-none focus:shadow-[var(--focus-ring)]'
</script>

<template>
  <div class="flex flex-col gap-4" data-testid="secure-planner">
    <p v-if="!enabled" class="text-[12.5px] text-[var(--text-secondary)]">
      {{ t('toolSecurity.planner.disabled') }}
    </p>

    <template v-else>
      <section :class="sectionClass" class="flex flex-col gap-2">
        <label class="text-[11.5px] font-medium text-[var(--text-secondary)]" for="camel-folder">
          {{ t('toolSecurity.planner.folder') }}
        </label>
        <input id="camel-folder" v-model="folder" :class="inputClass" class="font-mono" />
        <p v-if="!folder" class="text-[11px] text-[var(--text-tertiary)]">
          {{ t('toolSecurity.planner.noFolder') }}
        </p>
        <label
          class="mt-1 text-[11.5px] font-medium text-[var(--text-secondary)]"
          for="camel-query"
        >
          {{ t('toolSecurity.planner.request') }}
        </label>
        <textarea
          id="camel-query"
          v-model="query"
          rows="3"
          :class="inputClass"
          :placeholder="t('toolSecurity.planner.requestPlaceholder')"
          data-testid="secure-planner-query"
        />
        <div class="flex gap-2">
          <Button
            variant="primary"
            size="sm"
            :loading="store.planning"
            :disabled="!query.trim() || !folder.trim()"
            data-testid="secure-planner-plan"
            @click="plan()"
          >
            <Sparkles class="size-3.5" :stroke-width="1.75" />
            {{
              store.planning ? t('toolSecurity.planner.planning') : t('toolSecurity.planner.plan')
            }}
          </Button>
        </div>
        <p v-if="store.plannerError" role="alert" class="text-[12px] text-[var(--danger)]">
          {{ store.plannerError }}
        </p>
      </section>

      <section
        v-if="store.plan"
        :class="sectionClass"
        class="flex flex-col gap-2"
        data-testid="secure-planner-plan-view"
      >
        <div class="flex items-center justify-between gap-2">
          <h3 class="text-[12.5px] font-semibold text-[var(--text-primary)]">
            {{ t('toolSecurity.planner.planTitle') }}
          </h3>
          <span class="font-mono text-[10.5px] text-[var(--text-tertiary)]">{{
            store.plan.model
          }}</span>
        </div>
        <p class="text-[12.5px] text-[var(--text-primary)]">{{ store.plan.plan.goal }}</p>
        <p class="flex items-start gap-1.5 text-[11px] text-[var(--text-tertiary)]">
          <Lock class="mt-0.5 size-3 shrink-0" :stroke-width="1.75" />
          {{ t('toolSecurity.planner.planHint') }}
        </p>
        <ol class="flex flex-col gap-1">
          <li
            v-for="step in store.plan.plan.steps"
            :key="step.id"
            class="rounded-[var(--radius-sm)] border border-[var(--border-subtle)] px-2 py-1.5"
            :data-testid="`secure-planner-step-${step.id}`"
          >
            <div class="flex flex-wrap items-center gap-2 text-[12px]">
              <span class="font-mono text-[var(--text-tertiary)]">{{ step.id }}</span>
              <span class="min-w-0 flex-1 break-all font-mono text-[var(--text-primary)]">{{
                describeStep(step)
              }}</span>
              <span :class="STATUS_CLASS[store.steps[step.id]?.status ?? 'pending']">
                {{ t(`toolSecurity.planner.status.${store.steps[step.id]?.status ?? 'pending'}`) }}
              </span>
            </div>
            <div
              v-if="store.steps[step.id]?.sources.length"
              class="mt-0.5 text-[10.5px] text-[var(--warning)]"
            >
              <ShieldQuestion class="mr-0.5 inline size-3" :stroke-width="1.75" />
              {{
                t('toolSecurity.planner.untrusted', {
                  sources: store.steps[step.id]!.sources.join(', ')
                })
              }}
            </div>
            <div
              v-if="store.steps[step.id]?.reason"
              class="mt-0.5 text-[11px] text-[var(--danger)]"
            >
              {{ store.steps[step.id]!.reason }}
            </div>
          </li>
        </ol>
        <div>
          <Button
            variant="primary"
            size="sm"
            :loading="store.running"
            data-testid="secure-planner-run"
            @click="store.runPlan()"
          >
            <Play class="size-3.5" :stroke-width="1.75" />
            {{ store.running ? t('toolSecurity.planner.running') : t('toolSecurity.planner.run') }}
          </Button>
        </div>
      </section>

      <section
        v-if="store.run"
        :class="sectionClass"
        class="flex flex-col gap-1"
        data-testid="secure-planner-result"
      >
        <h3 class="text-[12.5px] font-semibold text-[var(--text-primary)]">
          {{ t('toolSecurity.planner.output') }}
        </h3>
        <p v-if="store.run.error" class="text-[12px] text-[var(--danger)]">{{ store.run.error }}</p>
        <template v-if="store.run.output">
          <pre
            class="whitespace-pre-wrap break-words rounded-[var(--radius-sm)] bg-[var(--bg-subtle,transparent)] p-2 font-mono text-[12px] text-[var(--text-primary)]"
            >{{ store.run.output.text }}</pre>
          <p
            class="text-[11px]"
            :class="store.run.output.trusted ? 'text-[var(--success)]' : 'text-[var(--warning)]'"
          >
            {{
              store.run.output.trusted
                ? t('toolSecurity.planner.trusted')
                : t('toolSecurity.planner.untrusted', {
                    sources: store.run.output.sources.join(', ')
                  })
            }}
          </p>
        </template>
      </section>
    </template>
  </div>
</template>
