# Deploying with Microsoft Intune

This guide gets Engramic Baseline onto every managed Windows device. Each device checks itself daily and reports the result to Intune as a **compliance** state, which you can use in Conditional Access. It can also give you a per-device breakdown in the **Remediations** report.

Allow about 30 minutes for the first rollout.

## How it fits together

```
Win32 app (install once)
  ├─ Scheduled task \EngramicBaseline\Audit   runs as SYSTEM, daily + after start-up
  │    └─ Invoke-CEScheduledAudit.ps1                device (Machine-scope) audit, read-only
  │         ├─ %ProgramData%\EngramicBaseline\status.json   compact result
  │         ├─ ...\reports\<device>-<time>\                        HTML / Markdown / JSON + changeset
  │         └─ Application event log, source EngramicBaseline (IDs 1000-1003)
  └─ Scheduled task \EngramicBaseline\User probe   runs as each signed-in user, at logon + daily
       └─ Invoke-CEUserProbe.ps1                     shadow-AI & WSL (User-scope checks)
            └─ %LOCALAPPDATA%\EngramicBaseline\user-status.json   per-user result

Custom compliance (every 8 hours, Intune's schedule)
  └─ Discover-CECompliance.ps1   reads status.json in well under a second → compliance-rules.json

Remediations (optional, daily)
  ├─ Detect-CECompliance.ps1     one-line summary per device in the Remediations report
  └─ Remediate-CECompliance.ps1  refreshes the audit; optionally applies fixes you allow
```

The full audit doesn't run inside the compliance script, because checking Windows Update can take minutes and discovery scripts have a 10-minute limit. The compliance script only reads the result of the last scheduled audit. If that result is more than a day old, the compliance script starts the audit task, so the next evaluation has fresh data. If no audit has succeeded for 72 hours, the device reports as **not compliant**. A broken install therefore can't pass silently.

### Shadow AI is per-user

The AI agents, WSL distributions and MCP servers a person uses live in **their** profile and **their** WSL VM, which the SYSTEM audit cannot see - each user gets their own WSL session. So those checks are **User-scope** (`Register-CECheck -Scope User`) and run as the signed-in user via `Invoke-CEUserProbe.ps1`, which writes `%LOCALAPPDATA%\EngramicBaseline\user-status.json` in the same shape as the device `status.json` (self-describing `checks`, derived `frameworks`) plus an **`ai`** block: the agents found, whether they are `contained` (none running as admin, no root distribution) and a `deviations` count, the `environments` they run in (WSL distributions, containers), the **MCP servers** each recognised agent is wired to (`ai.mcpServers`), and a `ai.credentialsPlaintext` count of agent credentials found stored in plaintext (never the values themselves - see [SECURITY.md](../SECURITY.md)). A user-context Intune remediation can key off `ai.deviations` / `ai.contained` (a plaintext credential also counts as a deviation) or the standalone `ai.credentialsPlaintext`. The installer registers a second scheduled task, `\EngramicBaseline\User probe`, with a **Users-group principal** so each signed-in user runs their own instance in their own session (at logon and daily). Pass `-NoUserProbeTask` to `Install-CEChecker.ps1` to skip it.

For Intune specifically, you can also deploy `Invoke-CEUserProbe.ps1` as a **user-context** platform script or proactive remediation ("Run this script using the logged-on credentials: **Yes**"), which returns each user's AI posture per device without a file merge. The SYSTEM audit stays machine-only and never guesses at shadow AI.

## Requirements

- Windows 11 or Windows Server 2016 to 2025, x64, enrolled in Intune (custom compliance needs the Intune Management Extension, which Intune installs automatically when you assign a Win32 app or script). Windows 10 devices still audit, but report as out of support.
- Windows PowerShell 5.1 (built in). PowerShell 7 isn't needed.
- **Remediations** requires Windows Enterprise E3/E5 (or equivalent) licensing. Everything else works with standard Intune.

## Network access

The audit itself runs locally. One check calls out: **SU-08** asks the firmware catalog at `https://baseline.engramic.ai` for the latest BIOS/UEFI release for the device's model, so it can tell whether a firmware update is outstanding.

- **What is sent:** only the vendor and the 4-character model id in the URL, e.g. `GET /v1/firmware/dell/0CF1`. No serial number, device name, user or audit results.
- **When:** at most every 12 hours per device (answers are cached in `%ProgramData%\EngramicBaseline\cache`), and only for Dell, HP and Lenovo hardware that isn't a virtual machine.
- **Firewall and proxy:** allow outbound HTTPS (TCP 443) to `baseline.engramic.ai`. The audit runs as **SYSTEM**, which doesn't pick up proxy settings configured for signed-in users, so on networks that only reach the internet through a proxy, set a machine-wide proxy or allow the domain directly.
- **If it can't connect:** nothing fails. SU-08 uses the cached answer if it has one, otherwise it falls back to judging the BIOS by its release date, and records the reason in the finding's evidence.
- **To turn it off** or point it at your own firmware catalog service, deploy `%ProgramData%\EngramicBaseline\config\firmware-catalog.json` with `baseUrl` set to `""` or to your own https address. Like every file in that folder, it replaces the packaged copy rather than merging with it, so include every setting:

  ```json
  { "baseUrl": "", "timeoutSeconds": 20, "cacheHours": 12, "maxRecordAgeDays": 7 }
  ```

## 1. Test on one machine first

From an **elevated** PowerShell prompt in the repo folder:

```powershell
Get-ChildItem -Recurse | Unblock-File        # only if you downloaded a zip
.\intune\Test-IntuneDeployment.ps1
```

The script rehearses the whole deployment the way Intune does it:

1. **Install:** installs from a 32-bit host, to prove the switch to 64-bit works.
2. **Detection:** checks the Win32 detection script reports the app as installed.
3. **Audit:** runs the scheduled audit **as SYSTEM** and waits for `status.json`.
4. **Discovery:** runs the compliance discovery script as SYSTEM in both the **32-bit and 64-bit** hosts, and checks the output is valid single-line JSON under 1 MB.
5. **Rules:** evaluates both rules files against that output, using the same operators and data types as Intune.
6. **Remediations:** runs the Remediations detection script.
7. **Uninstall:** removes everything again (add `-KeepInstalled` to leave it in place).

It prints `Deployment test: PASSED` if the package works. It also shows separately what Intune would report for **this** device, so a device that isn't compliant yet doesn't fail the test.

The same rehearsal runs in GitHub Actions on every push (`.github/workflows/ci.yml`).

## 2. Build the package

```powershell
.\intune\Build-IntunePackage.ps1 -DownloadTool
```

`-DownloadTool` fetches Microsoft's `IntuneWinAppUtil.exe` and checks that its signature is Microsoft's. If you already have the tool, use `-IntuneWinAppUtilPath` instead. The build creates:

| File | What it's for |
|---|---|
| `build\EngramicBaseline-<version>.intunewin` | Win32 app package |
| `build\upload\` | Scripts and rules to upload in the Intune portal |
| `build\INTUNE-SETTINGS.md` | Every value to enter in the portal, filled in for this version |
| `build\EngramicBaseline.zip` | The same payload, for RMM, Group Policy or manual installs |

If you'd rather not build it yourself, push a tag such as `v0.3.0`. `.github/workflows/release.yml` then publishes a GitHub release with all of these files attached.

**Before building, you may want to customise:**

- `config/cloud-services.json`: list your cloud services and record MFA attestations. Without this, the strict rules report every device as non-compliant on `CEMfaAttested`, which is correct: Cyber Essentials requires MFA on every cloud service.
- `config/thresholds.json`: patch window, lockout, password and PIN lengths.
- `config/auto-remediation.json`: fixes the Remediations script may apply automatically (off by default).
- `config/scheduled-audit.json`: checks to skip in the unattended audit.

You can also change settings on individual devices without rebuilding. A file with the same name in `%ProgramData%\EngramicBaseline\config\` replaces the packaged one.

## 3. Create the Win32 app

**Apps > Windows > Add > Windows app (Win32)**, then upload the `.intunewin` file.

| Field | Value |
|---|---|
| Install command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\intune\Install-CEChecker.ps1 -RunNow` |
| Uninstall command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\intune\Uninstall-CEChecker.ps1` |
| Install behaviour | System |
| Return codes | `0` success, `1` failed |
| Requirements | x64, Windows 10 22H2 or later (the floor Intune offers; it admits Windows 11 and Server, and Windows 10 itself reports as out of support) |
| Detection | Custom script: `upload\Detect-CEChecker.ps1`. Run as 32-bit on 64-bit clients: **No** |
| Assignment | **Required** for your device group |

The installer:

- **Program files:** copies the tool to `C:\Program Files\EngramicBaseline`. The folder's permissions only allow administrators and SYSTEM to change it, because the scheduled task runs these scripts as SYSTEM.
- **Data folder:** creates `C:\ProgramData\EngramicBaseline`, readable by administrators only (except `config\`).
- **Background tasks:** registers the event log source and two scheduled tasks. `\EngramicBaseline\Audit` runs as SYSTEM daily at 11:00 with up to 2 hours' random delay, 15 minutes after start-up, when missed, and on battery. `\EngramicBaseline\User probe` runs as each signed-in user (Users-group principal, non-elevated) at logon and daily, for the shadow-AI/WSL User-scope checks. Skip the second with `-NoUserProbeTask`.
- **Start menu:** adds a Start menu shortcut so users can open the desktop app and fix things themselves.
- **Detection value:** writes the detection value `HKLM\SOFTWARE\EngramicBaseline\Version`.

Options: `-DailyAt 13:30`, `-RandomDelayMinutes 60`, `-NoShortcut`, `-NoScheduledTask`, `-InstallPath`.

To upgrade, bump `ModuleVersion` in `src/CEAudit/CEAudit.psd1` and `$required` in `intune/Detect-CEChecker.ps1` (the build refuses to run if they differ). Then rebuild, and use Intune's *supersedence* or replace the package content. The installer upgrades in place.

## 4. Custom compliance

**Devices > Compliance > Scripts > Add > Windows 10 and later**

- Script: `upload\Discover-CECompliance.ps1`
- Run this script using the logged on credentials: **No**
- Enforce script signature check: **No** (or sign the script and choose Yes)
- Run script in 64 bit PowerShell Host: **Yes**

**Devices > Compliance > Create policy > Windows 10 and later > Custom Compliance: Require**, then select the script and upload a rules file:

| Rules file | Device is compliant when |
|---|---|
| `compliance-rules-autofail-only.json` (**start here**) | The tool is installed, an audit ran within 72 hours, there are no automatic-fail items (overdue updates or apps), Windows is supported, and antivirus is on and current |
| `compliance-rules.json` | All of the above, **plus** no failing Cyber Essentials checks, the everyday account is a standard user, and MFA is attested for cloud services |
| `compliance-rules-frameworks.json` | Installed, audited within 72 hours, no automatic-fail or failing controls, **and** at least 80% of the applicable Cyber Essentials v3.3 controls met (`CEv33MetPct`). Shadow-AI posture is enforced separately, via a user-context remediation on `ai.deviations` (SYSTEM compliance can't see per-user AI). |

Suggested rollout:

1. **Report only:** assign the lenient rules, with no Conditional Access and a long grace period.
2. **Fix the fleet:** use the Remediations report (below) and the per-device reports to fix what's failing.
3. **Enforce:** switch to `compliance-rules.json`, then use compliance in Conditional Access.

### What the discovery script reports

| Setting | Type | Meaning |
|---|---|---|
| `CECheckerInstalled` | Boolean | Detection key present |
| `CEToolVersion` | String | Version that produced the last audit |
| `CEAuditAgeHours` | Int64 | Hours since the last successful audit (99999 if none) |
| `CEAuditError` | Boolean | The most recent run failed (see `logs\`) |
| `CEAutoFailCount` | Int64 | v3.3 automatic-fail controls currently failing (-1 if unknown) |
| `CEFailCount` | Int64 | Failing Cyber Essentials controls (-1 if unknown) |
| `CEReviewCount` | Int64 | Cyber Essentials controls needing review or attestation |
| `CEv33MetPct` | Int64 | Cyber Essentials v3.3: % of applicable controls met (-1 if unknown) |
| `CENcscMetPct` | Int64 | NCSC hardening: % of applicable controls met (-1 if unknown) |
| `CEOSSupported` | Boolean | SU-01 not failing |
| `CEPatchingOK` | Boolean | SU-03, SU-05 and SU-06 not failing |
| `CEFirewallOK` | Boolean | FW-01 and FW-02 not failing |
| `CEAntimalwareOK` | Boolean | MP-01, MP-02 and MP-03 not failing |
| `CEStandardUserOK` | Boolean | UA-01 and UA-02 not failing (CE+ TC5) |
| `CEMfaAttested` | Boolean | UA-07 passing |
| `CEPlusTC2`, `CEPlusTC3`, `CEPlusTC5` | String | Cyber Essentials Plus estimate |
| `CEFailing` | String | IDs of failing findings (up to 400 characters) |

Any of these can be used in your own rules file. Unknown values are always reported as failing values.

## 5. Remediations (optional)

**Devices > Scripts and remediations > Remediations > Create**

| Field | Value |
|---|---|
| Detection script | `upload\Detect-CECompliance.ps1` |
| Remediation script | `upload\Remediate-CECompliance.ps1` |
| Run using logged-on credentials | No |
| Run in 64-bit PowerShell | Yes |
| Schedule | Daily |

The **Pre-remediation detection output** column then gives you one line per device across the tenant:

```
FAIL | autofail=2 fail=7 review=4 | age=5h | TC2=Likely fail TC3=Likely pass TC4=Check TC5=Likely fail | v0.3.0 | SU-03:Overdue,SU-05:7zip-7zip,UA-01
```

Out of the box, the remediation script only runs a fresh audit. To have it fix things automatically, set `"enabled": true` in `config/auto-remediation.json` and copy the fixes you want from `suggested` into `remediationIds`. High-risk fixes are always skipped. Every change is written to an undo log in the device's report folder, and `Restore-CEChangeset.ps1` can roll it back.

## Where to look on a device

| What | Where |
|---|---|
| Latest result | `C:\ProgramData\EngramicBaseline\status.json` |
| Full reports | `C:\ProgramData\EngramicBaseline\reports\` (last 14 kept) |
| Run logs | `C:\ProgramData\EngramicBaseline\logs\` |
| Last failure | `C:\ProgramData\EngramicBaseline\last-error.json` |
| Event log | Application log, source `EngramicBaseline`: 1000 clean (no attention, no auto-fail), 1001 attention items present, 1002 auto-fail controls failing. The event text includes the status JSON, so the Azure Monitor Agent / Log Analytics can collect it with a Windows event data collection rule. |
| Run it now | `Start-ScheduledTask -TaskPath '\EngramicBaseline\' -TaskName Audit` |

## Behaviour when running as SYSTEM

- **Per-user settings:** Office macros, screen saver and per-user apps are read from the **signed-in user's** profile. If nobody is signed in, the Office macro check is marked Manual rather than guessed.
- **App updates:** winget is found from the machine-wide App Installer. Apps installed only for one user aren't visible to SYSTEM, so users can still run the desktop app to check those.
- **Account separation (UA-01):** checks whether the signed-in user is a member of the local Administrators group. It doesn't expand membership that comes through an Entra ID group, such as the *Microsoft Entra joined device local administrator* role, so review that role in Entra ID.

## Troubleshooting

| Symptom | Check |
|---|---|
| Win32 app shows *failed* | `C:\ProgramData\EngramicBaseline\logs\install-*.log` and `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AppWorkload.log` |
| Compliance shows *error* / *not applicable* for the custom settings | The discovery script didn't return JSON; see `HealthScripts.log` in the IME logs folder |
| `CEAuditAgeHours` keeps growing | `Get-ScheduledTaskInfo -TaskPath '\EngramicBaseline\' -TaskName Audit`, then `last-error.json` and `logs\audit-*.log` |
| SU-08 only reports BIOS age, never "latest for this model" | Open the device's `findings.json` and look for the `Firmware catalog:` line in the SU-08 evidence. `Error - Firmware catalog unreachable` means the device can't reach `baseline.engramic.ai` over HTTPS as SYSTEM (see [Network access](#network-access)); `Unsupported` means the make isn't Dell, HP or Lenovo |
| Everything says `CEMfaAttested` is false | Expected until `config/cloud-services.json` records MFA for each service. Use the lenient rules until then. |
