# Approving AI tools

Baseline finds the AI tools installed on a device: assistants, coding agents, local model runners and their extensions (the list is in `config/ai-tools.json`). The approvals register, `config/ai-approvals.json`, records your organisation's decision on each one, so a report can separate the tools you've approved from the ones nobody has looked at.

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

## What Baseline can't see

Baseline finds AI installed on a device. It can't see AI used in a browser tab, such as a chatbot's website. For that, use browser policy (Edge or Chrome URL allow and block lists), DNS filtering, or Microsoft Defender for Cloud Apps.
