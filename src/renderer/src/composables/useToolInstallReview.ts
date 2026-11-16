/**
 * App-store style review before a Pi package is installed or updated.
 * Mounted once via <ToolInstallReviewDialog />. Main scans the package without
 * running it; the user sees its capabilities and findings, chooses decisions,
 * and Main records the approval that the install request is then checked
 * against.
 */

import { reactive, readonly } from 'vue'
import { getApi } from '@renderer/composables/useApi'
import type { CapabilityDecisionMap, ToolInstallPreview } from '@shared/tool-security/types'

interface ReviewState {
  open: boolean
  loading: boolean
  submitting: boolean
  error: string
  action: 'install' | 'update'
  source: string
  preview: ToolInstallPreview | null
  decisions: CapabilityDecisionMap
  allowScripts: boolean
  acknowledge: boolean
  pending: ((approved: boolean) => void) | null
}

const state = reactive<ReviewState>({
  open: false,
  loading: false,
  submitting: false,
  error: '',
  action: 'install',
  source: '',
  preview: null,
  decisions: {},
  allowScripts: false,
  acknowledge: false,
  pending: null
})

function message(error: unknown): string {
  return (
    (error as { userMessage?: string; message?: string })?.userMessage ??
    (error as { message?: string })?.message ??
    String(error)
  )
}

/** Resolves true once the user approved (Main now allows this install). */
export function reviewPackage(input: {
  source: string
  scope: 'global' | 'project'
  projectRoot?: string | null
  action?: 'install' | 'update'
}): Promise<boolean> {
  state.pending?.(false)
  Object.assign(state, {
    open: true,
    loading: true,
    submitting: false,
    error: '',
    action: input.action ?? 'install',
    source: input.source,
    preview: null,
    decisions: {},
    allowScripts: false,
    acknowledge: false
  })
  const result = new Promise<boolean>((resolve) => {
    state.pending = resolve
  })
  void getApi()
    .toolSecurity.preview({
      source: input.source,
      scope: input.scope,
      projectRoot: input.projectRoot ?? null
    })
    .then((preview) => {
      if (state.source !== input.source) return
      state.preview = preview
      state.decisions = { ...preview.suggested }
    })
    .catch((error) => {
      state.error = message(error)
    })
    .finally(() => {
      state.loading = false
    })
  return result
}

export async function confirmReview(): Promise<void> {
  if (!state.preview || state.submitting) return
  state.submitting = true
  state.error = ''
  try {
    await getApi().toolSecurity.approve({
      token: state.preview.token,
      decisions: { ...state.decisions },
      allowInstallScripts: state.allowScripts,
      acknowledgeDanger: state.acknowledge
    })
    finish(true)
  } catch (error) {
    state.error = message(error)
  } finally {
    state.submitting = false
  }
}

export function cancelReview(): void {
  finish(false)
}

function finish(approved: boolean): void {
  const pending = state.pending
  state.pending = null
  state.open = false
  pending?.(approved)
}

export function useToolInstallReview() {
  return { state: readonly(state), mutable: state, confirmReview, cancelReview }
}
