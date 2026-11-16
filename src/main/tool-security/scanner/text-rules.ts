/**
 * Text heuristics applied to string literals, npm scripts and unparseable code.
 * Each rule is a known indicator of credential theft, exfiltration, remote
 * shells, crypto-mining or hidden payloads.
 */

import type { FindingSeverity, ToolCapabilityId } from '@shared/tool-security/types'

export interface TextHit {
  rule?: string
  severity: FindingSeverity
  capability?: ToolCapabilityId
  title: string
  detail: string
  /** Hostname referenced by a URL in the text. */
  host?: string
}

/** Services commonly used to receive stolen data or host second-stage payloads. */
export const EXFIL_HOSTS: ReadonlyArray<{ pattern: RegExp; name: string }> = [
  { pattern: /(^|\.)webhook\.site$/i, name: 'webhook.site' },
  { pattern: /(^|\.)requestbin\.(?:net|com)$/i, name: 'RequestBin' },
  { pattern: /(^|\.)pipedream\.net$/i, name: 'Pipedream' },
  { pattern: /(^|\.)ngrok(?:-free)?\.(?:io|app|dev)$/i, name: 'ngrok' },
  { pattern: /(^|\.)pastebin\.com$/i, name: 'Pastebin' },
  { pattern: /(^|\.)transfer\.sh$/i, name: 'transfer.sh' },
  {
    pattern: /(^|\.)(?:interact\.sh|oast\.(?:fun|pro|live|site|online|me))$/i,
    name: 'an out-of-band interaction server'
  },
  { pattern: /(^|\.)burpcollaborator\.net$/i, name: 'Burp Collaborator' },
  { pattern: /(^|\.)canarytokens\.com$/i, name: 'Canarytokens' },
  { pattern: /(^|\.)hookbin\.com$/i, name: 'Hookbin' },
  { pattern: /(^|\.)beeceptor\.com$/i, name: 'Beeceptor' }
]

const PATH_EXFIL = [
  { pattern: /discord(?:app)?\.com\/api\/webhooks\//i, name: 'a Discord webhook' },
  { pattern: /api\.telegram\.org\/bot/i, name: 'a Telegram bot' },
  { pattern: /hooks\.slack\.com\/services\//i, name: 'a Slack webhook' }
]

const SECRET_PATHS: ReadonlyArray<{ pattern: RegExp; what: string }> = [
  { pattern: /(?:^|[\\/"'`\s])\.ssh(?:[\\/]|$)|id_(?:rsa|ed25519|ecdsa|dsa)\b/i, what: 'SSH keys' },
  { pattern: /\.aws[\\/](?:credentials|config)|AWS_SECRET_ACCESS_KEY/i, what: 'AWS credentials' },
  {
    pattern: /\.config[\\/]gcloud|application_default_credentials\.json/i,
    what: 'Google Cloud credentials'
  },
  { pattern: /\.azure[\\/]|accessTokens\.json/i, what: 'Azure credentials' },
  {
    pattern:
      /(?:^|[\\/"'`\s])\.npmrc\b|(?:^|[\\/"'`\s])\.pypirc\b|(?:^|[\\/"'`\s])\.netrc\b|\.git-credentials\b|\.docker[\\/]config\.json/i,
    what: 'package registry or git credentials'
  },
  { pattern: /\.kube[\\/]config/i, what: 'Kubernetes credentials' },
  { pattern: /\.gnupg\b/i, what: 'GPG keys' },
  {
    pattern:
      /Login Data|Cookies\.binarycookies|(?:Chrome|Chromium|Brave|Edge)[\\/]User Data|Firefox[\\/]Profiles/i,
    what: 'browser passwords or cookies'
  },
  { pattern: /Local Storage[\\/]leveldb/i, what: 'app session tokens' },
  {
    pattern: /wallet\.dat|\.electrum|Exodus[\\/]exodus\.wallet|MetaMask/i,
    what: 'cryptocurrency wallets'
  },
  {
    pattern: /security\s+find-(?:generic|internet)-password|login\.keychain/i,
    what: 'the macOS keychain'
  },
  { pattern: /CredentialManager|cmdkey\s+\/list|vaultcmd/i, what: 'the Windows credential store' },
  {
    pattern:
      /(?:^|[\\/])\.pi[\\/]agent[\\/](?:auth|models)\.json|\.codex[\\/]auth\.json|\.claude[\\/]\.credentials/i,
    what: 'AI provider credentials'
  }
]

const REMOTE_SHELL = [
  /\/dev\/tcp\/[\w.-]+\/\d+/i,
  /\bnc(?:at)?\s+(?:-\w+\s+)*-[ec]\s/i,
  /\b(?:bash|sh)\s+-i\s*>&/i,
  /\bmkfifo\b.*\bnc\b/i,
  /New-Object\s+System\.Net\.Sockets\.TCPClient/i,
  /\bsocat\b.*\bexec:/i
]

const MINER = /stratum\+(?:tcp|ssl):\/\/|\bxmrig\b|\bcryptonight\b|\bminergate\b|\bnicehash\b/i

const DOWNLOAD_AND_RUN =
  /\b(?:curl|wget)\b[^|;&\n]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|;\n]{0,200}\|\s*(?:iex|Invoke-Expression)\b|powershell(?:\.exe)?\s+(?:-\w+\s+)*-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}/i

const URL = /\b(?:https?|wss?|ftp):\/\/([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?/gi

const BASE64_BLOB = /[A-Za-z0-9+/]{400,}={0,2}/
const HEX_BLOB = /(?:\\x[0-9a-f]{2}){60,}|\b[0-9a-f]{600,}\b/i

export function analyzeText(text: string): TextHit[] {
  if (!text || text.length < 3) return []
  const hits: TextHit[] = []
  const sample = text.length > 200_000 ? text.slice(0, 200_000) : text

  for (const match of sample.matchAll(URL)) {
    const host = match[1].toLowerCase()
    hits.push({ severity: 'info', title: 'URL', detail: host, host })
    const exfil = EXFIL_HOSTS.find((entry) => entry.pattern.test(host))
    if (exfil)
      hits.push({
        rule: 'exfil.collector-host',
        severity: 'critical',
        capability: 'network',
        title: `Sends data to ${exfil.name}`,
        detail: `${host} is a service commonly used to collect stolen data or serve payloads.`,
        host
      })
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) && !/^(?:127\.|10\.|192\.168\.|0\.)/.test(host))
      hits.push({
        rule: 'network.raw-ip',
        severity: 'high',
        capability: 'network',
        title: 'Connects to a raw IP address',
        detail: `Hard-coded public IP ${host} instead of a named service.`,
        host
      })
  }
  for (const entry of PATH_EXFIL)
    if (entry.pattern.test(sample))
      hits.push({
        rule: 'exfil.chat-webhook',
        severity: 'critical',
        capability: 'network',
        title: `Sends data to ${entry.name}`,
        detail: 'Chat webhooks are a common way to receive stolen data.'
      })
  for (const entry of SECRET_PATHS)
    if (entry.pattern.test(sample))
      hits.push({
        rule: 'secrets.path',
        severity: 'critical',
        capability: 'secrets',
        title: `References ${entry.what}`,
        detail: `Mentions a location used to store ${entry.what}. Tools rarely need these.`
      })
  if (REMOTE_SHELL.some((pattern) => pattern.test(sample)))
    hits.push({
      rule: 'malware.reverse-shell',
      severity: 'critical',
      capability: 'process',
      title: 'Remote shell pattern',
      detail: 'Contains a command that gives another machine control of this one.'
    })
  if (MINER.test(sample))
    hits.push({
      rule: 'malware.miner',
      severity: 'critical',
      capability: 'process',
      title: 'Cryptocurrency miner',
      detail: 'References mining pools or miner software.'
    })
  if (DOWNLOAD_AND_RUN.test(sample))
    hits.push({
      rule: 'malware.download-execute',
      severity: 'critical',
      capability: 'process',
      title: 'Downloads and runs code',
      detail:
        'Pipes content from the internet straight into a shell, or runs an encoded PowerShell command.'
    })
  if (BASE64_BLOB.test(sample) && !/^data:image\//.test(sample.trimStart()))
    hits.push({
      rule: 'obfuscation.base64-blob',
      severity: 'high',
      capability: 'obfuscated',
      title: 'Large encoded blob',
      detail: 'Contains a long base64 string that may hide code or data.'
    })
  if (HEX_BLOB.test(sample))
    hits.push({
      rule: 'obfuscation.hex-blob',
      severity: 'high',
      capability: 'obfuscated',
      title: 'Large hex-encoded blob',
      detail: 'Contains a long hex-escaped string that may hide code.'
    })
  return hits
}
