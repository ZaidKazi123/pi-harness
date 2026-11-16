/**
 * Shell command segmentation for policy evaluation.
 *
 * Policy rules classify a command by its leading tokens. Evaluating only the
 * first token of a whole script lets `cd . && git push --force` or
 * `/usr/bin/git push -f` slip past `git.forcePush = deny`. This module splits a
 * script into the simple commands it would run and normalizes each one so every
 * segment is evaluated on its own:
 *
 * - control operators: `&&`, `||`, `;`, `|`, `&`, newlines
 * - command and process substitution: `$(…)`, backticks, `<(…)`, `>(…)`
 * - nested interpreters: `bash -c "…"`, `sh -c`, `zsh -c`, `cmd /c`,
 *   `powershell -Command "…"`, `pwsh -c`
 * - prefixes that don't change what runs: `VAR=value`, `env`, `command`,
 *   `exec`, `nohup`, `time`, `xargs`, `timeout N`, `nice`, `stdbuf`
 * - executable paths and Windows suffixes: `/usr/bin/git`, `git.exe`
 *
 * It is a conservative tokenizer, not a shell. Quoting is honored well enough
 * that separators inside quoted strings stay inside their segment. Anything it
 * cannot parse is still evaluated as a whole, so splitting can only add
 * checks, never remove the original one.
 */

const MAX_DEPTH = 3
const MAX_SEGMENTS = 64

const PREFIX_COMMANDS = new Set(['env', 'command', 'exec', 'nohup', 'time', 'builtin', 'xargs'])
const PREFIX_WITH_ARG = new Set(['timeout', 'nice', 'stdbuf', 'ionice', 'chrt'])
const SHELL_INTERPRETERS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'fish'])
const POWERSHELL = new Set(['powershell', 'pwsh'])

/** Split one level of a script on unquoted control operators. */
function splitTopLevel(script: string): { parts: string[]; substitutions: string[] } {
  const parts: string[] = []
  const substitutions: string[] = []
  let current = ''
  let quote: '"' | "'" | null = null
  let i = 0
  const push = () => {
    if (current.trim()) parts.push(current.trim())
    current = ''
  }
  while (i < script.length) {
    const c = script[i]
    const next = script[i + 1]
    if (c === '\\' && quote !== "'") {
      current += c + (next ?? '')
      i += 2
      continue
    }
    if (quote) {
      if (c === quote) quote = null
      // Substitutions inside double quotes still execute.
      if (quote === '"' && c === '$' && next === '(') {
        const end = matchParen(script, i + 1)
        substitutions.push(script.slice(i + 2, end))
        current += script.slice(i, end + 1)
        i = end + 1
        continue
      }
      if (quote === '"' && c === '`') {
        const end = script.indexOf('`', i + 1)
        if (end > i) {
          substitutions.push(script.slice(i + 1, end))
          current += script.slice(i, end + 1)
          i = end + 1
          continue
        }
      }
      current += c
      i++
      continue
    }
    if (c === '"' || c === "'") {
      quote = c
      current += c
      i++
      continue
    }
    if ((c === '$' || c === '<' || c === '>') && next === '(') {
      const end = matchParen(script, i + 1)
      substitutions.push(script.slice(i + 2, end))
      current += script.slice(i, end + 1)
      i = end + 1
      continue
    }
    if (c === '`') {
      const end = script.indexOf('`', i + 1)
      if (end > i) {
        substitutions.push(script.slice(i + 1, end))
        current += script.slice(i, end + 1)
        i = end + 1
        continue
      }
    }
    if (c === '(' || c === ')' || c === '{' || c === '}') {
      // Subshells and groups: their contents are ordinary segments.
      push()
      i++
      continue
    }
    if (c === '\n' || c === '\r' || c === ';') {
      push()
      i++
      continue
    }
    if ((c === '&' && next === '&') || (c === '|' && next === '|')) {
      push()
      i += 2
      continue
    }
    if (c === '|' || (c === '&' && next !== '>' && script[i - 1] !== '>')) {
      push()
      i++
      continue
    }
    current += c
    i++
  }
  push()
  return { parts, substitutions }
}

function matchParen(script: string, open: number): number {
  let depth = 0
  for (let i = open; i < script.length; i++) {
    if (script[i] === '(') depth++
    else if (script[i] === ')') {
      depth--
      if (depth === 0) return i
    }
  }
  return script.length
}

/** Whitespace tokenizer that keeps quoted strings together and strips their quotes. */
export function shellTokens(segment: string): string[] {
  const tokens: string[] = []
  let current = ''
  let quote: '"' | "'" | null = null
  let started = false
  for (let i = 0; i < segment.length; i++) {
    const c = segment[i]
    if (c === '\\' && quote !== "'" && i + 1 < segment.length) {
      current += segment[++i]
      started = true
      continue
    }
    if (quote) {
      if (c === quote) quote = null
      else current += c
      continue
    }
    if (c === '"' || c === "'") {
      quote = c
      started = true
      continue
    }
    if (/\s/.test(c)) {
      if (started) tokens.push(current)
      current = ''
      started = false
      continue
    }
    current += c
    started = true
  }
  if (started) tokens.push(current)
  return tokens
}

/** `/usr/bin/git` → `git`, `C:\Git\git.EXE` → `git`. */
export function executableName(token: string): string {
  const base = token.split(/[\\/]/).pop() ?? token
  return base.replace(/\.(?:exe|cmd|bat|com|ps1)$/i, '').toLowerCase()
}

/** Remove prefixes that run the real command unchanged. */
function stripPrefixes(tokens: string[]): string[] {
  let rest = [...tokens]
  for (let guard = 0; guard < 8 && rest.length; guard++) {
    const first = rest[0]
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(first)) {
      rest = rest.slice(1)
      continue
    }
    const name = executableName(first)
    if (PREFIX_COMMANDS.has(name)) {
      rest = rest.slice(1)
      // `env -i`, `xargs -0`, `command -p`: drop option flags too.
      while (rest[0]?.startsWith('-')) rest = rest.slice(1)
      continue
    }
    if (PREFIX_WITH_ARG.has(name)) {
      rest = rest.slice(1)
      while (rest[0]?.startsWith('-')) rest = rest.slice(1)
      if (rest[0] && /^[\d.]+[smhd]?$/.test(rest[0])) rest = rest.slice(1)
      continue
    }
    break
  }
  return rest
}

/** If the segment launches an interpreter with an inline script, return that script. */
function inlineScript(tokens: string[]): string | null {
  if (!tokens.length) return null
  const name = executableName(tokens[0])
  if (SHELL_INTERPRETERS.has(name)) {
    const flag = tokens.findIndex((token, index) => index > 0 && /^-[a-z]*c[a-z]*$/i.test(token))
    return flag > 0 && tokens[flag + 1] !== undefined ? tokens[flag + 1] : null
  }
  if (name === 'cmd') {
    const flag = tokens.findIndex((token, index) => index > 0 && /^\/[ck]$/i.test(token))
    return flag > 0 ? tokens.slice(flag + 1).join(' ') : null
  }
  if (POWERSHELL.has(name)) {
    const flag = tokens.findIndex((token, index) => index > 0 && /^-(?:c|command)$/i.test(token))
    return flag > 0 ? tokens.slice(flag + 1).join(' ') : null
  }
  return null
}

/**
 * Every simple command a script would run, normalized to `name arg arg…`
 * (executable basename, prefixes removed). Includes nested substitutions and
 * inline interpreter scripts.
 */
export function shellCommandSegments(command: string, depth = 0): string[] {
  const out: string[] = []
  const { parts, substitutions } = splitTopLevel(command)
  for (const part of parts) {
    const tokens = stripPrefixes(shellTokens(part))
    if (!tokens.length) continue
    const normalized = [executableName(tokens[0]), ...tokens.slice(1)].join(' ')
    out.push(normalized)
    const inner = inlineScript(tokens)
    if (inner && depth < MAX_DEPTH) out.push(...shellCommandSegments(inner, depth + 1))
    if (out.length >= MAX_SEGMENTS) break
  }
  if (depth < MAX_DEPTH)
    for (const sub of substitutions) out.push(...shellCommandSegments(sub, depth + 1))
  return out.slice(0, MAX_SEGMENTS)
}
