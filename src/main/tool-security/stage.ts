/**
 * Stage a package for review without installing or running it.
 *
 * - npm: resolve the version on the registry, download the tarball, verify its
 *   sha512 integrity, and extract it with symlinks, hard links and path
 *   traversal rejected. npm lifecycle scripts never run.
 * - git: shallow clone with hooks disabled and no submodules.
 * - local: scan the directory (or single extension file) in place.
 */

import { createHash, randomUUID } from 'node:crypto'
import { execFile } from 'node:child_process'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import * as tar from 'tar'
import { parseGitSource, parseNpmSource } from '../packages/package-source'
import { NetworkError, ValidationError } from '../services/errors'

const execFileAsync = promisify(execFile)
const MAX_TARBALL_BYTES = 50 * 1024 * 1024
const MAX_EXTRACTED_BYTES = 150 * 1024 * 1024
const MAX_ENTRIES = 20_000

export type Fetcher = (input: string, init?: RequestInit) => Promise<Response>

export interface StagedPackage {
  kind: 'npm' | 'git' | 'local'
  /** Directory (or single file for a local extension) to scan. */
  root: string
  version: string | null
  /** Removes temporary files; a no-op for local sources. */
  cleanup(): Promise<void>
}

export interface StageOptions {
  fetcher: Fetcher
  registry?: string
  /** Resolves a local source to an absolute, authorized path. */
  resolveLocal: (source: string) => Promise<string>
  tempRoot?: string
}

export async function stagePackage(source: string, options: StageOptions): Promise<StagedPackage> {
  if (source.startsWith('npm:')) return stageNpm(source, options)
  if (parseGitSource(source)) return stageGit(source, options)
  const root = await options.resolveLocal(source)
  return { kind: 'local', root, version: null, cleanup: async () => {} }
}

async function tempDir(options: StageOptions, prefix: string): Promise<string> {
  const base = options.tempRoot ?? os.tmpdir()
  const dir = await fs.mkdtemp(path.join(base, `pih-review-${prefix}-`))
  await fs.chmod(dir, 0o700).catch(() => undefined)
  return dir
}

function registryUrl(options: StageOptions): string {
  const configured =
    options.registry ?? process.env.npm_config_registry ?? 'https://registry.npmjs.org/'
  const url = new URL(configured)
  if (url.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(url.hostname))
    throw new ValidationError('The npm registry must use HTTPS')
  return url.href.endsWith('/') ? url.href : `${url.href}/`
}

async function stageNpm(source: string, options: StageOptions): Promise<StagedPackage> {
  const parsed = parseNpmSource(source)
  if (!parsed) throw new ValidationError('Invalid npm package source')
  const registry = registryUrl(options)
  const metaResponse = await options.fetcher(`${registry}${parsed.name.replace('/', '%2F')}`, {
    headers: { accept: 'application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8' }
  })
  if (!metaResponse.ok)
    throw new NetworkError(`The npm registry returned ${metaResponse.status} for ${parsed.name}`)
  const meta = (await metaResponse.json()) as {
    'dist-tags'?: Record<string, string>
    versions?: Record<string, { dist?: { tarball?: string; integrity?: string } }>
  }
  const requested = parsed.version ?? 'latest'
  const version = meta.versions?.[requested] ? requested : meta['dist-tags']?.[requested]
  const dist = version ? meta.versions?.[version]?.dist : undefined
  if (!version || !dist?.tarball)
    throw new ValidationError(`Version ${requested} of ${parsed.name} was not found`)
  if (!dist.integrity?.startsWith('sha512-'))
    throw new ValidationError(
      'The registry did not provide a sha512 integrity hash for this package'
    )
  const tarballUrl = new URL(dist.tarball)
  if (tarballUrl.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(tarballUrl.hostname))
    throw new ValidationError('Package tarballs must be downloaded over HTTPS')

  const dir = await tempDir(options, 'npm')
  const cleanup = () => fs.rm(dir, { recursive: true, force: true, maxRetries: 3 })
  try {
    const response = await options.fetcher(tarballUrl.href)
    if (!response.ok || !response.body)
      throw new NetworkError(`Download failed (${response.status})`)
    const declared = Number(response.headers.get('content-length') ?? 0)
    if (declared > MAX_TARBALL_BYTES)
      throw new ValidationError('Package tarball is too large to review')
    const chunks: Buffer[] = []
    let size = 0
    const reader = response.body.getReader()
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.byteLength
      if (size > MAX_TARBALL_BYTES) {
        await reader.cancel()
        throw new ValidationError('Package tarball is too large to review')
      }
      chunks.push(Buffer.from(value))
    }
    const tarball = Buffer.concat(chunks)
    const digest = `sha512-${createHash('sha512').update(tarball).digest('base64')}`
    if (digest !== dist.integrity)
      throw new ValidationError(
        'Package integrity check failed: the download does not match the registry hash'
      )
    const file = path.join(dir, 'package.tgz')
    await fs.writeFile(file, tarball, { mode: 0o600 })
    const out = path.join(dir, 'package')
    await fs.mkdir(out)
    await extractTarball(file, out)
    return { kind: 'npm', root: out, version, cleanup }
  } catch (error) {
    await cleanup()
    throw error
  }
}

/** Extract regular files and directories only, inside `out`, within size limits. */
export async function extractTarball(file: string, out: string): Promise<void> {
  let total = 0
  let entries = 0
  let rejected: string | null = null
  await tar.x({
    file,
    cwd: out,
    strip: 1,
    preservePaths: false,
    noChmod: true,
    filter: (entryPath, entry) => {
      entries++
      const type = (entry as { type?: string }).type
      const normalized = entryPath.replace(/\\/g, '/')
      if (normalized.split('/').includes('..') || path.isAbsolute(entryPath)) {
        rejected = `unsafe path ${entryPath}`
        return false
      }
      if (
        type &&
        type !== 'File' &&
        type !== 'Directory' &&
        type !== 'OldFile' &&
        type !== 'ContiguousFile'
      )
        return false
      total += (entry as { size?: number }).size ?? 0
      if (total > MAX_EXTRACTED_BYTES || entries > MAX_ENTRIES) {
        rejected = 'package is too large to review'
        return false
      }
      return true
    }
  })
  if (rejected) throw new ValidationError(`Package archive rejected: ${rejected}`)
}

async function stageGit(source: string, options: StageOptions): Promise<StagedPackage> {
  const parsed = parseGitSource(source)!
  const value = source.startsWith('git:') ? source.slice(4) : source
  const refAt = value.lastIndexOf('@')
  const ref =
    refAt > value.indexOf('/') && !value.startsWith('git@') ? value.slice(refAt + 1) : null
  if (ref && !/^[A-Za-z0-9._/-]{1,200}$/.test(ref)) throw new ValidationError('Invalid git ref')
  const url = value.includes('://')
    ? value.replace(/@[^/@]+$/, '')
    : `https://${parsed.host}/${parsed.packagePath}.git`
  if (!/^https:\/\//i.test(url))
    throw new ValidationError('Only HTTPS git sources can be reviewed before install')
  const dir = await tempDir(options, 'git')
  const cleanup = () => fs.rm(dir, { recursive: true, force: true, maxRetries: 3 })
  const out = path.join(dir, `repo-${randomUUID().slice(0, 8)}`)
  try {
    await execFileAsync(
      'git',
      [
        '-c',
        `core.hooksPath=${path.join(dir, 'no-hooks')}`,
        '-c',
        'protocol.file.allow=never',
        '-c',
        'core.symlinks=false',
        'clone',
        '--depth',
        '1',
        '--no-recurse-submodules',
        '--single-branch',
        ...(ref ? ['--branch', ref] : []),
        '--',
        url,
        out
      ],
      {
        timeout: 120_000,
        maxBuffer: 4 * 1024 * 1024,
        env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_LFS_SKIP_SMUDGE: '1', LC_ALL: 'C' }
      }
    )
    await fs.rm(path.join(out, '.git'), { recursive: true, force: true })
    return { kind: 'git', root: out, version: ref, cleanup }
  } catch (error) {
    await cleanup()
    throw error instanceof ValidationError
      ? error
      : new NetworkError('Could not download the git repository for review')
  }
}
