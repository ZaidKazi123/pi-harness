import { reactive, ref } from 'vue'
import type { NodeRuntimeInfo } from '@shared/ipc/api-types'

export type StartupPhase = 'settings' | 'services' | 'ready'

export const STARTUP_MINIMUM_VISIBLE_MS = 5000

/** Cold process launch only. A later window in the same process passes startup=0. */
export function shouldPlayStartupAnimation(search: string): boolean {
  const query = search.startsWith('?') ? search.slice(1) : search
  return new URLSearchParams(query).get('startup') !== '0'
}

export const startupPhase = ref<StartupPhase>('settings')
export const startupAnimationVisible = ref(
  shouldPlayStartupAnimation(typeof location === 'undefined' ? '' : location.search)
)

export type StartupCheckState = 'checking' | 'healthy' | 'warning' | 'error'

export const startupChecks = reactive({
  node: { state: 'checking' as StartupCheckState, detail: 'Checking…' },
  npm: { state: 'checking' as StartupCheckState, detail: 'Checking…' },
  pi: { state: 'checking' as StartupCheckState, detail: 'Checking…' },
  config: { state: 'checking' as StartupCheckState, detail: 'Checking…' }
})

export function runtimeStartupChecks(runtime: NodeRuntimeInfo | null): {
  node: { state: StartupCheckState; detail: string }
  npm: { state: StartupCheckState; detail: string }
} {
  if (!runtime) {
    return {
      node: { state: 'error', detail: 'Check failed' },
      npm: { state: 'error', detail: 'Check failed' }
    }
  }
  return {
    node: runtime.nodeSupported
      ? { state: 'healthy', detail: `Ready · ${runtime.nodeVersion}` }
      : runtime.nodeInstalled
        ? { state: 'warning', detail: `Version too old · ${runtime.nodeVersion ?? 'unknown'}` }
        : { state: 'warning', detail: 'Not found' },
    npm: runtime.npmInstalled
      ? { state: 'healthy', detail: `Ready · ${runtime.npmVersion}` }
      : { state: 'warning', detail: 'Not found' }
  }
}
