# Tool security

Pi-Harness reviews add-on tools before they are installed, enforces what each tool may do when it runs, tracks untrusted data in conversations, and offers an opt-in secure planner based on Google DeepMind's CaMeL design ([Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813), Debenedetti et al., 2025).

Settings live in **Settings → Security → Tool security**. The planner is in **Settings → Security → Secure planner**.

## 1. Review before install

Installing or updating a Pi package from the app opens a review screen, similar to the permission screen of a mobile app store:

- The package is downloaded and scanned **without running it**. npm tarballs are checked against the registry's sha512 integrity hash and extracted without symlinks, hard links or path traversal. Git sources are shallow-cloned with hooks disabled. Local folders are scanned in place.
- The screen lists what the package can do, highest risk first, with a plain-language description, the hosts and environment variables it references, the tools it registers and what each tool can do on its own.
- Capabilities the package uses but does not declare in its manifest are flagged.
- You choose **Allow**, **Ask** or **Block** for each capability before installing. Critical findings start at Block.
- A package with signs of malicious behavior needs an explicit acknowledgement before it can be installed.

Main enforces the review: an install or update request for a package without a fresh approval is refused, npm lifecycle scripts are blocked (`npm_config_ignore_scripts`) unless you allowed them, and after installing, the installed code is scanned again. If it differs from what you reviewed, the install is rolled back.

### Capabilities

| Capability | Risk | Default |
| --- | --- | --- |
| Read files | low | Allow |
| Internet and network access | medium | Ask |
| Create, change or delete files | medium | Ask |
| Read environment variables | medium | Ask |
| Run programs and shell commands | high | Ask |
| Run code generated at runtime | high | Ask |
| Native binaries | high | Ask |
| Hidden or encoded code | high | Ask |
| Access credentials | critical | Block |
| Runs scripts during installation | high | Blocked during install |
| Runs code when loaded | medium | Informational |
| Brings outside data into the conversation | medium | Tracked as untrusted |

### Optional manifest

Packages can declare their capabilities in `package.json`. Undeclared use is shown as a finding.

```json
"piHarness": {
  "capabilities": ["network", "env"],
  "network": ["api.example.com"],
  "env": ["EXAMPLE_API_KEY"],
  "tools": { "weather_lookup": { "capabilities": ["network", "untrusted-output"] } }
}
```

### What the scanner looks for

The scanner parses JavaScript and TypeScript with Babel and attributes evidence to the tool whose `execute` path contains it (following same-file helpers), or to extension code that runs on load. It reports:

- module and API use: `child_process`, `fetch`/`http`/sockets, `fs` reads and writes, `process.env` (single keys and the whole object), `eval`/`new Function`/computed `require` or `import()`, `vm`, native bindings and binaries
- known malicious indicators: data-collection endpoints (webhook.site, RequestBin, ngrok, Discord/Telegram/Slack webhooks, …), raw public IP addresses, credential locations (SSH keys, cloud and registry credentials, browser data, keychains, AI provider credentials), reverse shells, crypto miners, download-and-run commands, large encoded blobs, decode-then-eval
- combinations: credentials plus network, the whole environment plus network
- npm lifecycle scripts and what they run, and dependencies after install

Each finding has a severity, file, line and excerpt. The verdict is **No problems found**, **Needs your attention** (high findings or undeclared capabilities) or **Signs of malicious behavior** (any critical finding).

## 2. Runtime enforcement

Every Pi tool call passes through the desktop extension's `tool_call` hook, in both runtimes:

1. **Capability decisions** for third-party tools: per-tool setting, then per-package setting, then the default for the capability. The strictest wins.
2. **Harness Policy** (shell, git, file and network rules). Compound commands are now evaluated segment by segment, so `cd . && git push --force`, `/usr/bin/git push -f`, `bash -c "…"` and `sudo …` no longer hide behind a harmless first command.
3. **Data flow** (see section 3).

Packages whose code changed since you approved them, and packages installed outside the app (for example with `pi install` in a terminal), are treated as unreviewed. **Quarantine dangerous packages** (on by default) disables unreviewed packages whose scan shows malicious indicators before a session loads them, so their load-time code never runs. Blocking a package unregisters it from Pi while keeping its files. Approving it enables it again.

These checks do not depend on the session permission mode. Full access pre-approves ordinary actions, not untrusted data flowing to the network.

## 3. Untrusted data in conversations (CaMeL applied to Pi sessions)

In a normal Pi session one model sees everything, so the CaMeL separation cannot be enforced inside the loop. Pi-Harness applies the parts that can be enforced from outside it:

- **Provenance.** Tool results are labeled by source. Third-party tool output, network command output and (by default) workspace file contents are untrusted. User messages are trusted.
- **Policies on data flow.** Before an action that can send data off the computer (network commands, `git push`, `npm publish`, `gh`, inline interpreters that make requests, third-party tools with network access), Pi-Harness checks whether its arguments contain values that came from untrusted content and not from you: URLs, hosts, emails, IP addresses, long tokens or copied text.
  - Values from untrusted content → **Block** by default.
  - A shell network command in a conversation that contains untrusted content, without such values → **Ask** by default.
- **Quarantined extraction.** The `quarantined_extract` tool lets the agent read untrusted files or URLs through a separate model that has no tools and cannot see the conversation. Only the requested fields come back (schema-checked, length-limited) and they stay labeled as untrusted.

Decisions appear in the Harness timeline.

## 4. Secure planner (opt-in)

The secure planner is a separate mode that follows CaMeL directly:

| CaMeL | Pi-Harness secure planner |
| --- | --- |
| Privileged LLM writes a program from the user query only | The planner model sees only your request and the workspace path, and returns a JSON plan. It never sees tool results. |
| Quarantined LLM parses untrusted data, no tools | `extract` steps send data to a tool-less model that must return the fields defined in the plan. |
| Interpreter with capabilities on every value | Every value carries its sources. Literals in the plan are trusted, and anything derived from a tool result is untrusted, including extracted fields. |
| Security policies checked before each tool call | Untrusted values may not choose commands, URLs or file paths, and may not reach tools that can send data off the computer (Block by default). Capability defaults and Harness shell policy also apply. |

The plan language is JSON rather than CaMeL's restricted Python: sequential steps, references to earlier results, string concatenation and lists, with no loops or branches. Available tools: `read_file`, `list_files`, `search_text`, `write_file` (all confined to the workspace folder), `fetch_url` and `run_command`. Third-party Pi tools are not available in this mode.

## Limitations

- **Pi runs extension code in its own process.** Capability decisions gate tool calls. They cannot stop code inside an approved tool from doing more than it declared. Review, the scanner, quarantine and blocking are the defenses against that.
- **Static analysis can be evaded** by sufficiently obfuscated code. Obfuscation itself is flagged, and the scan is conservative when attribution is uncertain.
- **Data-flow detection is indicator-based.** Data that is transformed (for example re-encoded) before it is sent may not be recognized. The tainted-conversation check on shell network commands is the backstop.
- **In SDK mode** (`PI_HARNESS_AGENT_MODE=sdk`) packages are loaded before the quarantine check of a new session runs, so quarantine takes effect from the next session.
- **The secure planner** has no control flow and only built-in tools. Like CaMeL, it does not protect against text in the final answer being misleading. It only ensures that untrusted data cannot choose actions.
