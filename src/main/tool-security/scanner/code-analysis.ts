/**
 * Static analysis of one JavaScript/TypeScript source file.
 *
 * Finds what the code can do (capabilities) and where (which tool's `execute`,
 * a helper it calls, or extension code that runs without any tool call), plus
 * indicators of malicious intent. Nothing is executed. The analysis is
 * deliberately conservative: when attribution is uncertain, a capability is
 * attributed more widely rather than dropped.
 */

import { parse } from '@babel/parser'
import type { FindingSeverity, ToolCapabilityId } from '@shared/tool-security/types'
import { analyzeText, type TextHit } from './text-rules'

export interface CodeEvidence {
  rule: string
  severity: FindingSeverity
  capability?: ToolCapabilityId
  title: string
  detail: string
  line?: number
  snippet?: string
  /** Tool whose execute path contains this evidence. */
  tool?: string
  /** Executed when the extension loads (top level or extension body, not inside a tool). */
  loadTime: boolean
}

export interface FileAnalysis {
  evidence: CodeEvidence[]
  /** Capabilities per tool name, including same-file helpers it calls. */
  tools: Map<string, Set<ToolCapabilityId>>
  /** Capabilities found outside any tool's execute path. */
  packageCapabilities: Set<ToolCapabilityId>
  hosts: Set<string>
  envVars: Set<string>
  readsAllEnv: boolean
  decodesBase64: boolean
  /** Tools whose execute calls something imported from another local file. */
  toolsWithExternalCalls: Set<string>
  parsed: boolean
}

type AnyNode = { type: string; loc?: { start: { line: number } } | null; [key: string]: unknown }

const PROCESS_MODULES = new Set([
  'child_process',
  'execa',
  'cross-spawn',
  'shelljs',
  'cluster',
  'worker_threads',
  'node-pty',
  'zx'
])
const NETWORK_MODULES = new Set([
  'http',
  'https',
  'http2',
  'net',
  'tls',
  'dgram',
  'dns',
  'undici',
  'node-fetch',
  'axios',
  'got',
  'ws',
  'request',
  'superagent',
  'ky',
  'cross-fetch',
  'isomorphic-fetch',
  'socket.io-client',
  'needle',
  'phin'
])
const FS_MODULES = new Set(['fs', 'fs/promises', 'fs-extra', 'graceful-fs', 'original-fs'])
const SECRET_MODULES = new Set(['keytar', '@napi-rs/keyring', 'node-keytar', 'keychain'])
const NATIVE_MODULES = new Set(['bindings', 'node-gyp-build', 'ffi-napi', 'ffi-rs', 'koffi'])
const FS_WRITE_MEMBERS =
  /^(?:write|append|rm|rmdir|unlink|rename|mkdir|mkdtemp|copy|cp|symlink|link|chmod|chown|truncate|utimes|createWriteStream|outputFile|outputJson|remove|move|emptyDir|ensureFile|ensureDir)/i
const NETWORK_GLOBALS = new Set(['fetch'])
const NETWORK_CONSTRUCTORS = new Set(['WebSocket', 'XMLHttpRequest', 'EventSource'])

function moduleName(source: string): string {
  const bare = source.replace(/^node:/, '')
  if (bare.startsWith('@')) return bare.split('/').slice(0, 2).join('/')
  return bare === 'fs/promises' ? bare : (bare.split('/')[0] ?? bare)
}

function moduleCapability(mod: string, member?: string): ToolCapabilityId | null {
  if (PROCESS_MODULES.has(mod)) return 'process'
  if (NETWORK_MODULES.has(mod)) return 'network'
  if (SECRET_MODULES.has(mod)) return 'secrets'
  if (NATIVE_MODULES.has(mod)) return 'native'
  if (mod === 'vm') return 'dynamic-code'
  if (FS_MODULES.has(mod)) {
    if (!member) return null
    return FS_WRITE_MEMBERS.test(member) ? 'fs-write' : 'fs-read'
  }
  return null
}

const CAPABILITY_SEVERITY: Record<ToolCapabilityId, FindingSeverity> = {
  network: 'medium',
  'fs-read': 'low',
  'fs-write': 'medium',
  process: 'high',
  env: 'medium',
  secrets: 'critical',
  'dynamic-code': 'high',
  native: 'high',
  'install-script': 'high',
  'load-time': 'medium',
  obfuscated: 'high',
  'untrusted-output': 'medium'
}

function isFunction(node: AnyNode): boolean {
  return (
    node.type === 'FunctionDeclaration' ||
    node.type === 'FunctionExpression' ||
    node.type === 'ArrowFunctionExpression' ||
    node.type === 'ObjectMethod' ||
    node.type === 'ClassMethod' ||
    node.type === 'ClassPrivateMethod'
  )
}

function keyName(node: AnyNode | undefined): string | null {
  if (!node) return null
  if (node.type === 'Identifier') return node.name as string
  if (node.type === 'StringLiteral') return node.value as string
  return null
}

function stringValue(node: AnyNode | undefined): string | null {
  if (!node) return null
  if (node.type === 'StringLiteral') return node.value as string
  if (node.type === 'TemplateLiteral' && (node.expressions as unknown[]).length === 0)
    return ((node.quasis as AnyNode[])[0]?.value as { cooked?: string })?.cooked ?? null
  return null
}

function snippetAt(lines: string[], line: number | undefined): string | undefined {
  if (!line) return undefined
  const text = (lines[line - 1] ?? '').trim()
  return text.length > 160 ? `${text.slice(0, 157)}…` : text
}

interface Context {
  tool: string | null
  fn: string | null
  /** Inside some function that is not a tool or a named top-level helper. */
  nestedFunction: boolean
}

export function analyzeSource(source: string, options: { entry?: boolean } = {}): FileAnalysis {
  const result: FileAnalysis = {
    evidence: [],
    tools: new Map(),
    packageCapabilities: new Set(),
    hosts: new Set(),
    envVars: new Set(),
    readsAllEnv: false,
    decodesBase64: false,
    toolsWithExternalCalls: new Set(),
    parsed: false
  }
  const lines = source.split(/\r?\n/)
  let ast: AnyNode
  try {
    ast = parse(source, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx'],
      errorRecovery: true,
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
      allowImportExportEverywhere: true
    }) as unknown as AnyNode
    result.parsed = true
  } catch {
    // Unparseable code is still scanned as text, and flagged for review.
    result.evidence.push({
      rule: 'parse.failed',
      severity: 'medium',
      title: 'Code could not be parsed',
      detail: 'This file could not be analyzed structurally, so only text patterns were checked.',
      loadTime: false
    })
    addTextHits(result, analyzeText(source), null, false)
    return result
  }

  // ---------------------------------------------------------------- bindings
  const bindings = new Map<string, { mod: string; member?: string }>()
  const localModules = new Set<string>()
  const helperFunctions = new Map<string, AnyNode>()
  const program = (ast.program ?? ast) as AnyNode
  for (const statement of (program.body as AnyNode[]) ?? []) {
    collectBindings(statement)
    collectHelpers(statement)
  }

  function bindModule(local: string, source: string, member?: string): void {
    if (source.startsWith('.') || source.startsWith('/')) {
      localModules.add(local)
      return
    }
    bindings.set(local, { mod: moduleName(source), member })
  }

  function collectBindings(node: AnyNode): void {
    if (node.type === 'ImportDeclaration') {
      const source = (node.source as AnyNode).value as string
      for (const spec of node.specifiers as AnyNode[]) {
        const local = (spec.local as AnyNode).name as string
        if (spec.type === 'ImportSpecifier')
          bindModule(local, source, keyName(spec.imported as AnyNode) ?? undefined)
        else bindModule(local, source)
      }
    }
    if (node.type === 'VariableDeclaration') {
      for (const decl of node.declarations as AnyNode[]) {
        const init = decl.init as AnyNode | null
        const required = init && requireSource(init)
        if (!required) continue
        const id = decl.id as AnyNode
        if (id.type === 'Identifier') bindModule(id.name as string, required)
        if (id.type === 'ObjectPattern')
          for (const prop of id.properties as AnyNode[]) {
            if (prop.type !== 'ObjectProperty') continue
            const value = prop.value as AnyNode
            if (value.type === 'Identifier')
              bindModule(value.name as string, required, keyName(prop.key as AnyNode) ?? undefined)
          }
      }
    }
    if (node.type === 'ExportNamedDeclaration' && node.declaration)
      collectBindings(node.declaration as AnyNode)
  }

  function requireSource(node: AnyNode): string | null {
    let target = node
    if (target.type === 'AwaitExpression') target = target.argument as AnyNode
    if (target.type === 'MemberExpression') target = target.object as AnyNode
    if (target.type !== 'CallExpression') return null
    const callee = target.callee as AnyNode
    const isRequire = callee.type === 'Identifier' && callee.name === 'require'
    const isImport = callee.type === 'Import'
    if (!isRequire && !isImport) return null
    return stringValue((target.arguments as AnyNode[])[0])
  }

  function collectHelpers(node: AnyNode): void {
    const decl =
      node.type === 'ExportNamedDeclaration' || node.type === 'ExportDefaultDeclaration'
        ? (node.declaration as AnyNode | null)
        : node
    if (!decl) return
    if (decl.type === 'FunctionDeclaration' && decl.id)
      helperFunctions.set((decl.id as AnyNode).name as string, decl)
    if (decl.type === 'VariableDeclaration')
      for (const d of decl.declarations as AnyNode[]) {
        const init = d.init as AnyNode | null
        if ((d.id as AnyNode).type === 'Identifier' && init && isFunction(init))
          helperFunctions.set((d.id as AnyNode).name as string, init)
      }
  }

  // ---------------------------------------------------------------- walk
  const helperOwner = new Map<AnyNode, string>()
  for (const [name, node] of helperFunctions) helperOwner.set(node, name)
  const toolExecutes = new Map<AnyNode, string>()
  const toolExecuteRefs: Array<{ tool: string; fn: string }> = []
  const helperCaps = new Map<string, Set<ToolCapabilityId>>()
  const calls = new Map<string, Set<string>>() // context key → called identifiers
  const contextKey = (ctx: Context) =>
    ctx.tool ? `tool:${ctx.tool}` : ctx.fn ? `fn:${ctx.fn}` : ''

  const record = (
    ctx: Context,
    node: AnyNode,
    evidence: Omit<CodeEvidence, 'loadTime' | 'tool' | 'line' | 'snippet'>
  ) => {
    const line = node.loc?.start.line
    const loadTime = !ctx.tool && !ctx.fn && !ctx.nestedFunction
    result.evidence.push({
      ...evidence,
      line,
      snippet: snippetAt(lines, line),
      ...(ctx.tool ? { tool: ctx.tool } : {}),
      loadTime
    })
    if (!evidence.capability) return
    if (ctx.tool) {
      const set = result.tools.get(ctx.tool) ?? new Set()
      set.add(evidence.capability)
      result.tools.set(ctx.tool, set)
    } else if (ctx.fn) {
      const set = helperCaps.get(ctx.fn) ?? new Set()
      set.add(evidence.capability)
      helperCaps.set(ctx.fn, set)
      result.packageCapabilities.add(evidence.capability)
    } else {
      result.packageCapabilities.add(evidence.capability)
    }
  }

  const capabilityEvidence = (
    ctx: Context,
    node: AnyNode,
    capability: ToolCapabilityId,
    rule: string,
    title: string,
    detail: string
  ) =>
    record(ctx, node, {
      rule,
      capability,
      severity: CAPABILITY_SEVERITY[capability],
      title,
      detail
    })

  function visit(node: AnyNode, ctx: Context): void {
    if (!node || typeof node.type !== 'string') return
    let next = ctx
    if (isFunction(node)) {
      const tool = toolExecutes.get(node)
      const helper = helperOwner.get(node)
      if (tool) next = { tool, fn: null, nestedFunction: false }
      else if (helper && !ctx.tool) next = { tool: null, fn: helper, nestedFunction: false }
      else if (!ctx.tool && !ctx.fn)
        next = {
          ...ctx,
          nestedFunction: ctx.nestedFunction || !options.entry || !isExtensionBody(node)
        }
    }

    switch (node.type) {
      case 'CallExpression':
      case 'OptionalCallExpression':
        inspectCall(node, next)
        break
      case 'NewExpression':
        inspectNew(node, next)
        break
      case 'MemberExpression':
      case 'OptionalMemberExpression':
        inspectMember(node, next)
        break
      case 'StringLiteral':
        addTextHits(result, analyzeText(node.value as string), node, false, next, record)
        break
      case 'TemplateLiteral':
        for (const quasi of node.quasis as AnyNode[]) {
          const cooked = (quasi.value as { cooked?: string }).cooked ?? ''
          addTextHits(result, analyzeText(cooked), quasi, false, next, record)
        }
        break
      case 'ImportDeclaration': {
        const source = (node.source as AnyNode).value as string
        const capability = moduleCapability(moduleName(source))
        if (capability)
          record({ tool: null, fn: '#import', nestedFunction: false }, node, {
            rule: `import.${capability}`,
            capability,
            severity: CAPABILITY_SEVERITY[capability],
            title: `Imports ${moduleName(source)}`,
            detail: `The ${moduleName(source)} module provides ${capability.replace('-', ' ')} access.`
          })
        break
      }
    }

    for (const key of Object.keys(node)) {
      if (
        key === 'loc' ||
        key === 'start' ||
        key === 'end' ||
        key === 'extra' ||
        key === 'leadingComments' ||
        key === 'trailingComments' ||
        key === 'innerComments'
      )
        continue
      const child = node[key] as unknown
      if (Array.isArray(child)) for (const item of child) visitChild(item, next)
      else visitChild(child, next)
    }
  }

  function visitChild(child: unknown, ctx: Context): void {
    if (child && typeof child === 'object' && typeof (child as AnyNode).type === 'string')
      visit(child as AnyNode, ctx)
  }

  /** The exported extension function body runs when Pi loads the extension. */
  function isExtensionBody(fn: AnyNode): boolean {
    return extensionBodies.has(fn)
  }
  const extensionBodies = new Set<AnyNode>()
  for (const statement of (program.body as AnyNode[]) ?? []) {
    if (statement.type === 'ExportDefaultDeclaration') {
      const decl = statement.declaration as AnyNode
      if (isFunction(decl)) extensionBodies.add(decl)
      if (decl.type === 'Identifier') {
        const fn = helperFunctions.get(decl.name as string)
        if (fn) {
          extensionBodies.add(fn)
          helperOwner.delete(fn)
        }
      }
    }
  }

  function noteToolRegistration(call: AnyNode): void {
    const callee = call.callee as AnyNode
    const name =
      callee.type === 'MemberExpression' ? keyName(callee.property as AnyNode) : keyName(callee)
    if (name !== 'registerTool' && name !== 'defineTool' && name !== 'tool') return
    const arg = (call.arguments as AnyNode[])[0]
    if (!arg || arg.type !== 'ObjectExpression') return
    let toolName: string | null = null
    let execute: AnyNode | null = null
    let executeRef: string | null = null
    for (const prop of arg.properties as AnyNode[]) {
      const key = keyName(prop.key as AnyNode)
      if (key === 'name' && prop.type === 'ObjectProperty')
        toolName = stringValue(prop.value as AnyNode)
      if (key === 'execute') {
        if (prop.type === 'ObjectMethod') execute = prop
        else if (prop.type === 'ObjectProperty') {
          const value = prop.value as AnyNode
          if (isFunction(value)) execute = value
          else if (value.type === 'Identifier') executeRef = value.name as string
        }
      }
    }
    if (name === 'tool' && !toolName) return
    const resolved = toolName ?? '<dynamic name>'
    if (!result.tools.has(resolved)) result.tools.set(resolved, new Set())
    if (execute) toolExecutes.set(execute, resolved)
    if (executeRef) toolExecuteRefs.push({ tool: resolved, fn: executeRef })
  }

  function inspectCall(node: AnyNode, ctx: Context): void {
    const callee = node.callee as AnyNode
    const args = node.arguments as AnyNode[]
    noteToolRegistration(node)
    if (callee.type === 'Identifier') {
      const name = callee.name as string
      const key = contextKey(ctx)
      if (key) {
        const set = calls.get(key) ?? new Set()
        set.add(name)
        calls.set(key, set)
        if (ctx.tool && localModules.has(name)) result.toolsWithExternalCalls.add(ctx.tool)
      }
      if (name === 'require') {
        const source = stringValue(args[0])
        if (source === null)
          capabilityEvidence(
            ctx,
            node,
            'dynamic-code',
            'code.dynamic-require',
            'Loads a module chosen at runtime',
            'require() with a computed name can load code that is not visible here.'
          )
        else {
          const capability = moduleCapability(moduleName(source))
          // Loading a module is not using it: only a tool's own require counts toward that tool.
          const importCtx: Context = ctx.tool
            ? ctx
            : { tool: null, fn: '#import', nestedFunction: false }
          if (capability)
            capabilityEvidence(
              importCtx,
              node,
              capability,
              `require.${capability}`,
              `Loads ${moduleName(source)}`,
              `The ${moduleName(source)} module provides ${capability.replace('-', ' ')} access.`
            )
        }
        return
      }
      if (NETWORK_GLOBALS.has(name))
        return capabilityEvidence(
          ctx,
          node,
          'network',
          'network.fetch',
          'Makes network requests',
          'Calls fetch() to send or receive data over the network.'
        )
      if (name === 'eval')
        return capabilityEvidence(
          ctx,
          node,
          'dynamic-code',
          'code.eval',
          'Evaluates code from a string',
          'eval() runs arbitrary code that is assembled at runtime.'
        )
      if (name === 'Function')
        return capabilityEvidence(
          ctx,
          node,
          'dynamic-code',
          'code.function-constructor',
          'Builds a function from a string',
          'Function() compiles and runs code assembled at runtime.'
        )
      if (
        (name === 'setTimeout' || name === 'setInterval') &&
        args[0] &&
        stringValue(args[0]) !== null
      )
        return capabilityEvidence(
          ctx,
          node,
          'dynamic-code',
          'code.string-timer',
          'Runs a string as code',
          `${name}() with a string argument evaluates it as code.`
        )
      if (name === 'atob') result.decodesBase64 = true
      const bound = bindings.get(name)
      if (bound) {
        const capability = moduleCapability(bound.mod, bound.member)
        if (capability)
          capabilityEvidence(
            ctx,
            node,
            capability,
            `call.${capability}`,
            `Calls ${bound.mod}${bound.member ? `.${bound.member}` : ''}`,
            `This call uses ${capability.replace('-', ' ')} access.`
          )
      }
      return
    }
    if (callee.type === 'Import') {
      if (stringValue(args[0]) === null)
        capabilityEvidence(
          ctx,
          node,
          'dynamic-code',
          'code.dynamic-import',
          'Imports a module chosen at runtime',
          'import() with a computed specifier can load code that is not visible here.'
        )
      return
    }
    if (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression') {
      const object = callee.object as AnyNode
      const property = keyName(callee.property as AnyNode)
      if (object.type === 'Identifier') {
        const objectName = object.name as string
        if (
          objectName === 'process' &&
          (property === 'binding' || property === 'dlopen' || property === '_linkedBinding')
        )
          return capabilityEvidence(
            ctx,
            node,
            'native',
            'native.binding',
            'Loads native bindings',
            `process.${property}() loads native code.`
          )
        if (objectName === 'Buffer' && property === 'from' && stringValue(args[1]) === 'base64')
          result.decodesBase64 = true
        if (objectName === 'navigator' && property === 'sendBeacon')
          return capabilityEvidence(
            ctx,
            node,
            'network',
            'network.beacon',
            'Sends data in the background',
            'navigator.sendBeacon() posts data to a server.'
          )
        const bound = bindings.get(objectName)
        if (bound && property) {
          const capability = moduleCapability(bound.mod, property)
          if (capability)
            capabilityEvidence(
              ctx,
              node,
              capability,
              `call.${capability}`,
              `Calls ${bound.mod}.${property}`,
              `This call uses ${capability.replace('-', ' ')} access.`
            )
        }
      }
    }
  }

  function inspectNew(node: AnyNode, ctx: Context): void {
    const callee = node.callee as AnyNode
    if (callee.type !== 'Identifier') return
    const name = callee.name as string
    if (name === 'Function')
      capabilityEvidence(
        ctx,
        node,
        'dynamic-code',
        'code.function-constructor',
        'Builds a function from a string',
        'new Function() compiles and runs code assembled at runtime.'
      )
    else if (NETWORK_CONSTRUCTORS.has(name))
      capabilityEvidence(
        ctx,
        node,
        'network',
        'network.socket',
        `Opens a ${name} connection`,
        `${name} sends and receives data over the network.`
      )
  }

  function inspectMember(node: AnyNode, ctx: Context): void {
    const object = node.object as AnyNode
    // process.env.X / process.env['X']
    if (
      object.type === 'MemberExpression' &&
      (object.object as AnyNode).type === 'Identifier' &&
      ((object.object as AnyNode).name as string) === 'process' &&
      keyName(object.property as AnyNode) === 'env'
    ) {
      const name = node.computed
        ? stringValue(node.property as AnyNode)
        : keyName(node.property as AnyNode)
      if (name) {
        result.envVars.add(name)
        capabilityEvidence(
          ctx,
          node,
          'env',
          'env.read',
          `Reads ${name}`,
          `Reads the ${name} environment variable.`
        )
      }
    }
  }

  // Seed tool registrations so their execute functions are known before walking.
  preScanRegistrations(program)
  function preScanRegistrations(node: AnyNode): void {
    if (!node || typeof node.type !== 'string') return
    if (node.type === 'CallExpression') noteToolRegistration(node)
    for (const key of Object.keys(node)) {
      if (key === 'loc') continue
      const child = node[key] as unknown
      if (Array.isArray(child)) {
        for (const item of child)
          if (item && typeof item === 'object') preScanRegistrations(item as AnyNode)
      } else if (child && typeof child === 'object') preScanRegistrations(child as AnyNode)
    }
  }
  for (const ref of toolExecuteRefs) {
    const fn = helperFunctions.get(ref.fn)
    if (fn) {
      toolExecutes.set(fn, ref.tool)
      helperOwner.delete(fn)
    }
  }

  visit(program, { tool: null, fn: null, nestedFunction: false })
  findWholeEnvReads(program)

  // Tools inherit capabilities of same-file helpers they call (transitively).
  for (const [tool, caps] of result.tools) {
    const seen = new Set<string>()
    const queue = [...(calls.get(`tool:${tool}`) ?? [])]
    while (queue.length) {
      const name = queue.shift()!
      if (seen.has(name)) continue
      seen.add(name)
      for (const cap of helperCaps.get(name) ?? []) caps.add(cap)
      for (const next of calls.get(`fn:${name}`) ?? []) queue.push(next)
      if (localModules.has(name)) result.toolsWithExternalCalls.add(tool)
    }
  }

  return result

  function findWholeEnvReads(root: AnyNode): void {
    // `process.env` used as a value (spread, passed, serialized) rather than one key.
    const walk = (node: AnyNode, parent: AnyNode | null, ctx: Context) => {
      if (!node || typeof node.type !== 'string') return
      let next = ctx
      if (isFunction(node)) {
        const tool = toolExecutes.get(node)
        if (tool) next = { tool, fn: null, nestedFunction: false }
      }
      if (
        node.type === 'MemberExpression' &&
        (node.object as AnyNode).type === 'Identifier' &&
        ((node.object as AnyNode).name as string) === 'process' &&
        keyName(node.property as AnyNode) === 'env' &&
        !(parent && parent.type === 'MemberExpression' && parent.object === node)
      ) {
        const passedToSpawnEnv =
          parent?.type === 'ObjectProperty' && keyName(parent.key as AnyNode) === 'env'
        if (!passedToSpawnEnv) {
          result.readsAllEnv = true
          record(next, node, {
            rule: 'env.read-all',
            capability: 'env',
            severity: 'high',
            title: 'Reads all environment variables',
            detail:
              'Uses the whole process.env object, which contains every API key and token in the environment.'
          })
        }
      }
      for (const key of Object.keys(node)) {
        if (key === 'loc') continue
        const child = node[key] as unknown
        if (Array.isArray(child)) {
          for (const item of child)
            if (item && typeof item === 'object') walk(item as AnyNode, node, next)
        } else if (child && typeof child === 'object') walk(child as AnyNode, node, next)
      }
    }
    walk(root, null, { tool: null, fn: null, nestedFunction: false })
  }
}

type Recorder = (
  ctx: Context,
  node: AnyNode,
  evidence: Omit<CodeEvidence, 'loadTime' | 'tool' | 'line' | 'snippet'>
) => void

function addTextHits(
  result: FileAnalysis,
  hits: TextHit[],
  node: AnyNode | null,
  _loadTime: boolean,
  ctx: Context = { tool: null, fn: '#text', nestedFunction: false },
  record?: Recorder
): void {
  for (const hit of hits) {
    if (hit.host) result.hosts.add(hit.host)
    if (!hit.rule) continue
    const evidence = {
      rule: hit.rule,
      severity: hit.severity,
      ...(hit.capability ? { capability: hit.capability } : {}),
      title: hit.title,
      detail: hit.detail
    }
    // String literals describe what code may do; they never count as load-time execution.
    const textCtx: Context = {
      tool: ctx.tool,
      fn: ctx.tool ? null : '#text',
      nestedFunction: false
    }
    if (record && node) record(textCtx, node, evidence)
    else result.evidence.push({ ...evidence, loadTime: false })
    if (!record && hit.capability) result.packageCapabilities.add(hit.capability)
  }
}
