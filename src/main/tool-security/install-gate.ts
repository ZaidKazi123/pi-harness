import type { PiPackageActionResult, PiPackageTarget } from '@shared/ipc/api-types'
import type { ToolSecurityService } from './service'

/**
 * Install or update packages only after review, then confirm that what got
 * installed is what was reviewed. A mismatch is rolled back.
 */
export async function reviewedPackageMutation(
  security: ToolSecurityService,
  targets: PiPackageTarget[],
  mutate: (targets: PiPackageTarget[]) => Promise<PiPackageActionResult[]>,
  rollback: (target: PiPackageTarget) => Promise<unknown>
): Promise<PiPackageActionResult[]> {
  for (const target of targets) security.assertInstallReviewed(target)
  const results = await mutate(targets)
  const checked: PiPackageActionResult[] = []
  for (const result of results) {
    if (!result.ok || result.skipped) {
      checked.push(result)
      continue
    }
    const target = targets.find((candidate) => candidate.source === result.source) ?? {
      source: result.source,
      scope: result.scope
    }
    const verdict = await security.verifyInstalled(target)
    if (verdict.ok) {
      checked.push(result)
      continue
    }
    await rollback(target).catch(() => undefined)
    checked.push({
      ...result,
      ok: false,
      message: verdict.reason,
      errorCode: 'VERIFY_FAILED',
      logs: [...result.logs, { phase: 'verify', ok: false, message: verdict.reason }]
    })
  }
  return checked
}
