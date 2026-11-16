/**
 * Tools available to the CaMeL secure planner. They run in Main (not in Pi),
 * so every argument's provenance is known before the call. File tools are
 * confined to the plan's workspace folder.
 */

import { spawn } from 'node:child_process'
import fs from 'node:fs/promises'
import path from 'node:path'
import type { CapabilityDecision } from '@shared/tool-security/types'
import { PathDeniedError, ValidationError } from '../../services/errors'
import type { CamelToolSpec } from './engine'

const MAX_READ_BYTES = 512 * 1024
const MAX_FETCH_BYTES = 2 * 1024 * 1024
const MAX_COMMAND_OUTPUT = 200 * 1024
const SKIP = new Set(['node_modules', '.git', 'dist', 'out', 'build', '.next'])

export interface CamelToolDeps {
  fetcher: (url: string, init?: RequestInit) => Promise<Response>
  /** Shell policy (deny / ask / allow) from the Harness policy engine. */
  shellDecision: (command: string) => { decision: 'allow' | 'ask' | 'deny'; rule: string }
}

async function inside(cwd: string, target: unknown, mustExist = true): Promise<string> {
  if (typeof target !== 'string' || !target.trim() || target.includes('\0'))
    throw new ValidationError('A path is required.')
  const root = await fs.realpath(cwd)
  const resolved = path.resolve(root, target)
  const rel = path.relative(root, resolved)
  if (rel.startsWith('..') || path.isAbsolute(rel))
    throw new PathDeniedError('The secure planner can only use files inside the workspace folder.')
  if (mustExist) {
    const real = await fs.realpath(resolved)
    const realRel = path.relative(root, real)
    if (realRel.startsWith('..') || path.isAbsolute(realRel))
      throw new PathDeniedError('The path leaves the workspace folder.')
    return real
  }
  const parent = await fs.realpath(path.dirname(resolved)).catch(() => null)
  if (!parent || path.relative(root, parent).startsWith('..'))
    throw new PathDeniedError('The path leaves the workspace folder.')
  return resolved
}

function htmlToText(html: string): string {
  return html
    .replace(/<(script|style|noscript)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/\s+/g, ' ')
    .trim()
}

function mapShell(decision: 'allow' | 'ask' | 'deny'): CapabilityDecision {
  return decision === 'deny' ? 'block' : decision
}

export function camelTools(deps: CamelToolDeps): CamelToolSpec[] {
  return [
    {
      name: 'read_file',
      description: 'Read a text file in the workspace. Returns its contents (untrusted).',
      args: { path: 'string' },
      capabilities: ['fs-read'],
      controlArgs: ['path'],
      sink: false,
      source: (args) => `file:${String(args.path)}`,
      run: async (args, { cwd }) => {
        const file = await inside(cwd, args.path)
        const stat = await fs.stat(file)
        if (stat.size > MAX_READ_BYTES)
          throw new ValidationError('The file is too large for the secure planner.')
        return fs.readFile(file, 'utf8')
      }
    },
    {
      name: 'list_files',
      description: 'List the entries of a workspace folder ("." for the root).',
      args: { path: 'string' },
      capabilities: ['fs-read'],
      controlArgs: ['path'],
      sink: false,
      source: (args) => `dir:${String(args.path)}`,
      run: async (args, { cwd }) => {
        const dir = await inside(cwd, args.path)
        const entries = await fs.readdir(dir, { withFileTypes: true })
        return entries
          .slice(0, 500)
          .map((entry) => (entry.isDirectory() ? `${entry.name}/` : entry.name))
      }
    },
    {
      name: 'search_text',
      description:
        'Find lines containing a text (case-insensitive) in workspace files under a folder.',
      args: { text: 'string', path: 'string' },
      capabilities: ['fs-read'],
      controlArgs: ['path'],
      sink: false,
      source: (args) => `search:${String(args.text)}`,
      run: async (args, { cwd, signal }) => {
        const needle = String(args.text ?? '').toLowerCase()
        if (!needle) throw new ValidationError('Search text is required.')
        const root = await inside(cwd, args.path)
        const matches: string[] = []
        const queue = [root]
        let files = 0
        while (queue.length && matches.length < 200 && files < 5000) {
          signal.throwIfAborted()
          const dir = queue.shift()!
          for (const entry of await fs.readdir(dir, { withFileTypes: true }).catch(() => [])) {
            if (entry.isSymbolicLink() || SKIP.has(entry.name)) continue
            const full = path.join(dir, entry.name)
            if (entry.isDirectory()) queue.push(full)
            else if (entry.isFile()) {
              files++
              const stat = await fs.stat(full).catch(() => null)
              if (!stat || stat.size > MAX_READ_BYTES) continue
              const text = await fs.readFile(full, 'utf8').catch(() => '')
              text.split(/\r?\n/).forEach((line, index) => {
                if (matches.length < 200 && line.toLowerCase().includes(needle))
                  matches.push(
                    `${path.relative(root, full)}:${index + 1}: ${line.trim().slice(0, 200)}`
                  )
              })
            }
          }
        }
        return matches
      }
    },
    {
      name: 'write_file',
      description: 'Create or replace a text file in the workspace.',
      args: { path: 'string', content: 'string' },
      capabilities: ['fs-write'],
      controlArgs: ['path'],
      sink: false,
      source: (args) => `write:${String(args.path)}`,
      run: async (args, { cwd }) => {
        const file = await inside(cwd, args.path, false)
        const content = String(args.content ?? '')
        if (content.length > MAX_READ_BYTES) throw new ValidationError('The content is too large.')
        await fs.writeFile(file, content, 'utf8')
        return `Wrote ${content.length} characters to ${String(args.path)}`
      }
    },
    {
      name: 'fetch_url',
      description: 'Download a web page or API response over HTTP(S). Returns text (untrusted).',
      args: { url: 'string' },
      capabilities: ['network'],
      controlArgs: ['url'],
      sink: true,
      source: (args) => `url:${String(args.url)}`,
      run: async (args, { signal }) => {
        const url = new URL(String(args.url))
        if (url.protocol !== 'https:' && url.protocol !== 'http:')
          throw new ValidationError('Only HTTP(S) URLs can be fetched.')
        const response = await deps.fetcher(url.href, { signal, redirect: 'follow' })
        const reader = response.body?.getReader()
        const chunks: Uint8Array[] = []
        let size = 0
        if (reader)
          for (;;) {
            const { done, value } = await reader.read()
            if (done) break
            size += value.byteLength
            if (size > MAX_FETCH_BYTES) {
              await reader.cancel()
              break
            }
            chunks.push(value)
          }
        const text = Buffer.concat(chunks).toString('utf8')
        const type = response.headers.get('content-type') ?? ''
        return {
          status: response.status,
          text: type.includes('html') ? htmlToText(text).slice(0, 200_000) : text.slice(0, 200_000)
        }
      }
    },
    {
      name: 'run_command',
      description: 'Run a shell command in the workspace folder and return its output (untrusted).',
      args: { command: 'string' },
      capabilities: ['process'],
      controlArgs: ['command'],
      sink: true,
      source: (args) => `command:${String(args.command).slice(0, 60)}`,
      policy: (args) => {
        const evaluation = deps.shellDecision(String(args.command ?? ''))
        return {
          decision: mapShell(evaluation.decision),
          reason: `Harness shell policy (${evaluation.rule}): ${evaluation.decision}.`
        }
      },
      run: (args, { cwd, signal }) =>
        new Promise((resolve, reject) => {
          const command = String(args.command ?? '')
          const [file, argv] =
            process.platform === 'win32'
              ? ['powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command]]
              : ['/bin/sh', ['-c', command]]
          const child = spawn(file, argv, { cwd, signal, windowsHide: true, timeout: 60_000 })
          let output = ''
          const add = (chunk: Buffer) => {
            if (output.length < MAX_COMMAND_OUTPUT) output += chunk.toString('utf8')
          }
          child.stdout.on('data', add)
          child.stderr.on('data', add)
          child.on('error', reject)
          child.on('close', (code) =>
            resolve({ exitCode: code, output: output.slice(0, MAX_COMMAND_OUTPUT) })
          )
        })
    }
  ]
}
