import { createHash } from 'node:crypto'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import * as tar from 'tar'
import { afterEach, describe, expect, it } from 'vitest'
import { stagePackage, type Fetcher } from './stage'

const dirs: string[] = []
afterEach(async () => {
  while (dirs.length) await fs.rm(dirs.pop()!, { recursive: true, force: true })
})

async function tarball(files: Record<string, string>): Promise<Buffer> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pih-tgz-'))
  dirs.push(root)
  for (const [rel, content] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(root, 'package', rel)), { recursive: true })
    await fs.writeFile(path.join(root, 'package', rel), content)
  }
  const file = path.join(root, 'out.tgz')
  await tar.c({ gzip: true, file, cwd: root, portable: true }, ['package'])
  return fs.readFile(file)
}

function registry(
  tgz: Buffer,
  integrity = `sha512-${createHash('sha512').update(tgz).digest('base64')}`
): {
  fetcher: Fetcher
  requests: string[]
} {
  const requests: string[] = []
  const fetcher: Fetcher = async (url) => {
    requests.push(url)
    if (url.endsWith('/weather-helper'))
      return new Response(
        JSON.stringify({
          'dist-tags': { latest: '1.2.0' },
          versions: {
            '1.2.0': {
              dist: { tarball: 'https://registry.test/weather-helper-1.2.0.tgz', integrity }
            }
          }
        }),
        { status: 200 }
      )
    if (url.endsWith('.tgz')) return new Response(new Uint8Array(tgz), { status: 200 })
    return new Response('not found', { status: 404 })
  }
  return { fetcher, requests }
}

const resolveLocal = async (source: string) => source

describe('stagePackage', () => {
  it('downloads, verifies and extracts an npm tarball without running it', async () => {
    const tgz = await tarball({
      'package.json': JSON.stringify({
        name: 'weather-helper',
        scripts: { postinstall: 'node x.js' }
      }),
      'index.js': 'module.exports = 1'
    })
    const { fetcher, requests } = registry(tgz)
    const staged = await stagePackage('npm:weather-helper', {
      fetcher,
      registry: 'https://registry.test/',
      resolveLocal
    })
    dirs.push(path.dirname(staged.root))
    expect(staged).toMatchObject({ kind: 'npm', version: '1.2.0' })
    expect(await fs.readFile(path.join(staged.root, 'index.js'), 'utf8')).toBe('module.exports = 1')
    expect(requests).toEqual([
      'https://registry.test/weather-helper',
      'https://registry.test/weather-helper-1.2.0.tgz'
    ])
    await staged.cleanup()
    await expect(fs.access(staged.root)).rejects.toThrow()
  })

  it('rejects a tarball whose hash does not match the registry', async () => {
    const tgz = await tarball({ 'index.js': 'x' })
    const { fetcher } = registry(tgz, 'sha512-AAAA')
    await expect(
      stagePackage('npm:weather-helper', {
        fetcher,
        registry: 'https://registry.test/',
        resolveLocal
      })
    ).rejects.toThrow(/integrity/i)
  })

  it('refuses a plain-HTTP registry', async () => {
    const { fetcher } = registry(Buffer.from(''))
    await expect(
      stagePackage('npm:weather-helper', {
        fetcher,
        registry: 'http://registry.test/',
        resolveLocal
      })
    ).rejects.toThrow(/HTTPS/)
  })

  it('scans local sources in place', async () => {
    const staged = await stagePackage('/some/local/dir', {
      fetcher: registry(Buffer.from('')).fetcher,
      resolveLocal
    })
    expect(staged).toMatchObject({ kind: 'local', root: '/some/local/dir' })
  })
})
