# Agent settings

Available in v2.2.10 and later. Older installers may not include every settings page.

[English README](../README.md#agent-settings) · [Simplified Chinese README](../README.zh-CN.md#agent-settings) · [Screenshots](README.md)

## AI preferences

Open **Settings → AI** to choose default thinking, automatic context compaction, retry behavior, and workspace defaults. Save changes; the page indicates when a setting applies to new sessions.

## Realtime voice

1. Open **Settings → Realtime voice**, enable voice, choose **OpenAI Realtime, Gemini Live, or Codex Live**, and save your settings.
2. Choose a supported service account or supply a separate API key. Codex Live uses your existing Codex sign-in in Pi. Availability and charges depend on your account.
3. Open a workspace conversation and click the waveform button beside the composer. Check the target conversation before starting.
4. Choose whether to share recent context. Sharing is off by default. When enabled, it includes only the last six plain-text messages, excluding attachments and tool results.
5. Start the call and allow microphone access. The floating controls let you mute, view transcripts, or end the call, including after navigating to another page.
6. Review any voice work request and choose **Send to conversation** or **Dismiss request**. Sending a work request starts work with the conversation's configured coding agent.

In **Settings → Shortcuts**, click a shortcut and press the desired combination for the command palette, settings, a new session, or closing a tab. Escape cancels recording; Backspace clears the selected shortcut. Restore defaults when needed. Editor save and find shortcuts are listed separately.

## Instructions

Open **Settings → Instructions**, choose **Global** or a project folder, edit the instructions, and save. Check the selected scope before saving. If you leave with unsaved edits, the app asks whether to discard them.

## MCP servers and marketplace

Open **Settings → MCP**. Use **All / Global / Project** and the project selector to choose which servers to view. Servers with the same name in different scopes can be edited independently.

- **Add a server:** choose the destination scope and enter a local command or HTTP endpoint. Review its configuration before saving and enabling it.
- **Marketplace:** browse 15 built-in templates or search the official MCP registry. Review the server configuration and destination before installing. Registry results support pagination.
- **Scan other tools:** review discovered configurations before importing. Imported and official-registry entries are saved disabled; complete the account or environment configuration before enabling them.

The templates are available to install; they do not represent 15 running connections. Required tools and service credentials depend on the selected server.

## Reusable subagents

In **Settings → Subagents**, create or edit a template with a name, role, instructions, model, thinking level, and tools. Choose a shared workspace or an isolated worktree and optionally mark it as a reviewer. To start a task, choose the project and enter the task. Templates can also be reused in teams under **Workspace → Tools → Agents**.

## Remote hosts

Start **pi-host** on the target host first. In **Settings → Remote hosts**, enter the address and pairing token supplied by that service. Once paired, connect to browse projects and sessions, view conversation history, send prompts, and respond to approval requests. Disconnect or remove a host when needed.

## Common questions

| Symptom                            | What to check                                                                            |
| ---------------------------------- | ---------------------------------------------------------------------------------------- |
| A settings page is missing         | Check whether your version includes it; v2.2.10 and later contain all seven pages.       |
| Voice start is disabled            | Enable voice, choose a supported account or API key, and save.                           |
| Microphone access fails            | Check the application's microphone permission and device availability.                   |
| An imported MCP server is disabled | This is expected; review and complete its configuration before enabling.                 |
| Project servers are missing        | Select the intended project and check the scope filter.                                  |
| A remote host cannot connect       | Check that pi-host is running and reachable, and that the address and token are correct. |

## Sponsors

<table>
  <tr>
    <td width="580" align="center" valign="middle">
      <a href="https://infistar.cc/register?aff=S26RFM4B&ref_source=link" style="color:transparent;background-color:transparent;text-decoration:none;border:none;"><img src="assets/infistar-banner.png" width="560" alt="Pi-Harness × Infistar.cc" style="color:transparent;background-color:transparent;text-decoration:none;border:none;" /></a>
    </td>
    <td valign="middle">
      Pi-Harness × Infistar.cc: Claude, GPT, Gemini, Grok, DeepSeek and more with one key, for a fraction of the official price (up to 99% off, as low as 1% of the official price). 100% official models, each verifiable; thousands of redundant routes with automatic failover; 200+ models from 16 brands with one key.<br>
      Pi-Harness users who register through the <a href="https://infistar.cc/register?aff=S26RFM4B&ref_source=link">dedicated link</a> receive a CNY 5 credit: <a href="https://infistar.cc/register?aff=S26RFM4B&ref_source=link">https://infistar.cc/register?aff=S26RFM4B&ref_source=link</a>
    </td>
  </tr>
  <tr>
    <td width="580" align="center" valign="middle">
      <a href="https://cloud.tencent.com/act/cps/redirect?redirect=6871&amp;cps_key=ece2099a1da90c2f7a4a4c437ad623f8&amp;from=console" style="color:transparent;background-color:transparent;text-decoration:none;border:none;"><img src="assets/workbuddy-banner.jpg" width="560" alt="Tencent Cloud WorkBuddy" style="color:transparent;background-color:transparent;text-decoration:none;border:none;" /></a>
    </td>
    <td valign="middle">
      [Tencent Cloud] WorkBuddy, an all-scenario AI office workspace. Team flagship edition from CNY 198/month.<br>
      <a href="https://cloud.tencent.com/act/cps/redirect?redirect=6871&amp;cps_key=ece2099a1da90c2f7a4a4c437ad623f8&amp;from=console">https://cloud.tencent.com/act/cps/redirect?redirect=6871&amp;cps_key=ece2099a1da90c2f7a4a4c437ad623f8&amp;from=console</a>
    </td>
  </tr>
</table>
