# Approving AI tools

Baseline finds the AI tools installed on a device: assistants, coding agents, local model runners and their extensions, AI browsers and AI browser extensions (the list is in `config/ai-tools.json`). The approvals register, `config/ai-approvals.json`, records your organisation's decision on each one, so a report can separate the tools you've approved from the ones nobody has looked at.

The point is to know what people are using and decide, not to ban AI by default. A tool someone reached for on their own is often a good tool; it just needs a decision, and the account it uses needs protecting.

## What the checks do

**SC-14 (AI tools on the device have been approved)** looks at every recognised AI tool on the device, chat-only and local tools included:

| The tool is | SC-14 |
|---|---|
| Approved, and the approval is current | Pass |
| Approved, but the approval is older than `maxApprovalAgeDays`, or doesn't say who approved it and when | Warn (due for review) |
| Not listed in the register | Warn (not reviewed) |
| Listed as `not-approved` | Fail |

SC-14 counts towards the NCSC framework only. It never affects the Cyber Essentials judgement, because Cyber Essentials doesn't require an AI register.

**SC-09** (unnecessary software removed) is a Cyber Essentials check. It warns about every AI agent that can run commands or change files, much like remote access software. An agent with a current approval drops out of that warning, because the approval is the record that the organisation needs it.

## The register

```json
{
  "maxApprovalAgeDays": 365,
  "tools": [
    { "id": "claude-desktop", "decision": "approved", "decidedBy": "A. Person", "decidedOn": "2026-09-01", "reason": "Claude Team plan, organisation accounts only" },
    { "id": "cursor", "decision": "not-approved", "decidedBy": "A. Person", "decidedOn": "2026-09-01", "reason": "Use GitHub Copilot instead" }
  ]
}
```

- **`id`:** a tool's `id` from `config/ai-tools.json`, such as `claude-code`, `github-copilot-vscode` or `ollama`.
- **`decision`:** `approved` or `not-approved`.
- **`decidedBy` and `decidedOn`** (`yyyy-MM-dd`): who decided, and when. An approval needs both.
- **`reason`:** optional, and shown in the report. Say what the approval covers, for example which plan or which accounts.
- **`maxApprovalAgeDays`:** how long an approval lasts before it is due for review. The default is 365.

SC-14 reports entries it can't use, and ignores them until they're fixed: an unknown `id`, the same `id` listed twice, or a `decision` other than the two above. The tools they name count as not reviewed meanwhile.

Decisions apply to everyone on the device. To decide differently for some devices, for example allowing Cursor for developers only, deploy a different copy of the file to those devices.

## Deploying it

Put your copy in `%ProgramData%\EngramicBaseline\config\ai-approvals.json`, where it replaces the shipped (empty) file. The folder must be writable only by administrators, or elevated audits ignore it. With Intune, deploy it as you would `cloud-services.json` (see [INTUNE.md](INTUNE.md)).

## Where the results appear

- **The report and the app's AI tab:** each tool shows *approved*, *not approved*, *due for review* or *not reviewed*, alongside a count of each.
- **`user-status.json` (`ai` block):**
  - `approval` on each agent: `approved`, `stale`, `not-approved` or `unreviewed`;
  - the counts `approved`, `approvalStale`, `unapproved` and `unreviewed`.

  These are separate from `contained` and `deviations`: an unapproved tool isn't a containment failure. Key a remediation or compliance rule off them deliberately.

## AI browser extensions and AI browsers

Baseline recognises AI browser extensions, such as Claude in Chrome, the ChatGPT extension, Sider and Monica, and AI browsers, such as Comet, Opera Neon and Genspark. They're in `config/ai-tools.json` like any other tool, so you approve them by `id` in the register in the same way (for example `claude-in-chrome` or `perplexity-comet`), and UA-07 asks for MFA on the account they use.

It looks in the profiles of Chrome, Edge, Brave, Vivaldi, Opera, Arc, Comet, Genspark and Firefox, including their Beta, Dev and Canary builds; `config/browser-profiles.json` says where each keeps them. It reads only the names of folders and files there, and never opens a file, so it never reads browsing history, cookies, browser settings or anything an extension has stored.

Some limits:

- **Installed is not the same as turned on.** An extension that has been turned off still counts, and so does one removed since the browser was last started.
- **Leftover profiles.** When a browser has been uninstalled but its profile folder is still there, extensions in it are labelled a leftover. SC-14 then asks you to delete that folder, and UA-07 doesn't count it as a service in use.
- **What isn't seen:** extensions loaded in developer mode, portable browsers, browsers started with their own user data folder, Opera side profiles, Opera Beta and Developer, Firefox forks, and Firefox profiles kept outside the usual `Profiles` folder.
- **Whose profile.** An audit run as SYSTEM looks only at the signed-in user's profile, and at none when no one is signed in; SC-14 says so. Each user's own probe covers their profile.
- **What an extension can do** (its permissions, or whether it can act on web pages by itself) isn't judged. Every recognised extension is listed as not able to act on the device.

### After upgrading

New catalog entries can add services to UA-07, which then needs an MFA attestation in `cloud-services.json`, and can raise SC-14 "not reviewed" results. A copy of `ai-tools.json` in `%ProgramData%` replaces the shipped one, so merge new entries into it.

## What Baseline can't see

Baseline finds recognised AI apps and browser extensions installed on a device. It can't see AI websites used in a browser tab, such as a chatbot's website, or AI built into the browser itself, such as Copilot in Edge, Gemini in Chrome or Brave Leo. For those, use browser policy (Edge or Chrome URL allow and block lists, and the browser's own settings for its built-in AI), DNS filtering, or Microsoft Defender for Cloud Apps.
