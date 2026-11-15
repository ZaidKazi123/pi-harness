# AGENTS.md

This file applies to every AI / agent working in this repository (Cursor, Claude, Codex, Copilot, and so on).

> **Fork note:** this repository is ZaidKazi123's fork of [wangmiaozero/pi-harness](https://github.com/wangmiaozero/pi-harness). The authorship and release rules in sections 5 and 7 describe the upstream project and apply to changes contributed back upstream.

The maintainer also keeps `wangmiao-ai-docs/` (detailed rules) and `wangmiao-task/` (task plans) locally. Neither is committed to the repository. When they exist, read them in full before starting work, beginning with `wangmiao-ai-docs/README.md`. When they don't exist, follow this file and do not invent their contents. Never `git add -f` either directory.

## 1. Project

- Pi-Harness is an Electron + Vue 3 desktop app that serves as the console and workspace for Pi Coding Agent. **Pi Coding Agent is the only agent runtime.** Do not implement a second runtime or agent loop. (The opt-in CaMeL secure planner is a separate planning/interpreter mode; it does not replace Pi's loop.)
- Toolchain: Node 24.22.1 (`>=24.22.1 <25`), pnpm 9.12.1. If your versions differ, switch versions first; do not change code or loosen `engines`.

```bash
pnpm install --frozen-lockfile
pnpm dev
```

## 2. Scope of work

- Do only what is currently requested. Do not expand scope or refactor unrelated code along the way.
- Check `git status` before starting and keep any unrelated uncommitted changes.
- Do not remove existing features. Do not break compatibility with Pi's Session, JSONL, Skills, Provider, Model or existing configuration; preserve unknown fields when reading or writing Pi configuration.
- Do not replace the stack: Electron, Vue, Pinia, Vitest, Playwright, electron-vite.

## 3. Architecture

```text
Vue Renderer → typed preload API → validated IPC → Main service → Domain/Adapter → Pi SDK or operating system
```

- The renderer must not use Node.js, the file system, process execution or the Pi SDK directly.
- Keep `contextIsolation: true` and `nodeIntegration: false`.
- A new IPC channel must update `src/shared/ipc/channels.ts`, `src/shared/ipc/api-types.ts`, preload, and the runtime validation in the Main handler, and include positive and negative tests.
- Run commands with `spawn` / `execFile` and an argument array. Never concatenate user input into a shell command.
- Secrets are never returned to the renderer, and logs must be redacted. Never commit `.env`, private keys, certificates, API keys or tokens.

## 4. Verification

Verify in proportion to the change:

| Change                                   | Verification                                              |
| ---------------------------------------- | --------------------------------------------------------- |
| Documentation only                       | Content and links are correct                             |
| Ordinary code                            | `pnpm typecheck` + relevant unit tests                    |
| Main / Preload / IPC / UI flows          | Also the relevant Electron E2E tests                      |
| Configuration, security, install, update | `pnpm lint` + `pnpm test` + `pnpm compile` + relevant E2E |

```bash
pnpm typecheck
pnpm lint
pnpm test
pnpm compile
pnpm test:e2e:only
```

- If you change existing UI behavior, update the affected old test assertions as well.
- Never make tests pass with sleeps, retries, skips or longer timeouts; wait for the real completion signal.
- Tests use isolated directories and mocks, no real credentials, and no real model requests.
- Report checks you did not run as "not run", never as passed.

## 5. Authorship and commits (upstream, mandatory)

- The only author is wangmiao `<tuziling84@gmail.com>`.
- No AI may appear in Git author, committer, `Co-authored-by`, `Made-with`, README contributors, LICENSE, or the `author` field of `package.json`.
- Before pushing, check every commit to be pushed: `git log origin/main..HEAD --format=fuller`.
- External contributors' original commits and attribution must be preserved.
- Keep commit titles short, use `feat:` / `fix:`, and describe only user-visible changes.

## 6. Public content

README, CHANGELOG, GitHub Releases, commit messages and UI copy describe only released, user-visible additions and fixes. Do not mention internal implementation, debugging history, unreleased plans, local paths, or AI/tool information. Do not create `CONTRIBUTING.md`.

## 7. Releases (upstream)

1. Update the `package.json` version and `CHANGELOG.md` (`## X.Y.Z — YYYY-MM-DD`, using only `### Added` / `### Fixed`).
2. Local verification passes, and `pnpm security:node --source-only --online --audit --release` exits 0 with a `PASS` result.
3. **Push only main**, and wait for all CI on that commit to pass.
4. Then create an annotated tag `vX.Y.Z` on that CI-passing commit and push it.

Never push main and a tag together, never tag a commit whose CI has not passed, and never move or overwrite a pushed tag or a published release. If a release fails after the tag is pushed, fix it and publish the next patch version.
