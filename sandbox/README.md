# sandbox - disposable Windows environments from a JSON file

Builds a Windows Sandbox from a small environment definition: which folders to map, whether it has network, which tools to install (from `tools.json`, via winget, a vendor script, npm or VS Code extensions), what variables to set, and what to run. The sandbox is destroyed when its window closes; the only thing that reaches the host is the results folder.

This folder has no dependency on the rest of the repository. Engramic Baseline uses it to test fixes for real and to check that its AI-tool detection works against real installers; it could just as well hand a coding agent a clean, audited Windows to work in.

## Use

```powershell
# from anywhere; {root} defaults to the parent of this folder
.\sandbox\New-Sandbox.ps1 -Environment .\tools\sandbox\environments\ai-lab.json -Networking
.\sandbox\New-Sandbox.ps1 -Environment my-env.json -MappedFolder @{ host = 'C:\modules'; sandbox = 'C:\ps-modules' } -Var @{ CE_LAB_TOOLS = 'cursor,ollama' }
.\sandbox\New-Sandbox.ps1 -Environment my-env.json -NoLaunch   # write the .wsb and env.json only
```

Requires Windows 10/11 Pro, Enterprise or Education with the *Windows Sandbox* optional feature enabled.

## Environment file

```json
{
  "name": "ai-lab",
  "description": "Install AI tools and check they are detected",
  "networking": true,
  "mappedFolders": [ { "host": "{root}", "sandbox": "C:\\baseline-tool", "readOnly": true } ],
  "tools": [ "vscode" ],
  "vars": { "CE_LAB_TOOLS": "claude-desktop,cursor" },
  "run": { "script": "C:\\baseline-tool\\tests\\lab\\Invoke-Lab.ps1", "args": [] }
}
```

- `{root}`, `{results}` and `{sandbox}` are replaced with host paths.
- This folder is always mapped read-only at `C:\sandbox`; the results folder read-write at `C:\results`, with the resolved environment copied there as `env.json`.
- Inside the sandbox, `Invoke-SandboxBootstrap.ps1` runs as the sandbox administrator: sets `vars`, bootstraps winget when there are tools to install, installs them, then runs `run.script` in a visible console. It exports `SANDBOX_RESULTS`, a per-run folder under `C:\results`.

## tools.json

The install catalogue: how to get a tool onto a machine unattended, and which executable it runs as. It is an overlay keyed by id, not a list of tools: what a tool *is* lives in the consumer's rules (for Engramic Baseline, `config/ai-tools.json`, with a unit test keeping the two id sets equal), and only helper entries such as `vscode` and `node` carry a name. Types: `winget` (with optional `source`, e.g. `msstore`), `script` (a PowerShell one-liner such as a vendor's install script), `npm` (global package; depends on `node`), `vscode` (extension ids; depends on `vscode`). Tools marked `manual` cannot be installed unattended and are reported as such rather than skipped silently. winget ids drift; a failing id is reported per tool, never fatal.

`SandboxLab.psm1` exposes the same operations to scripts running inside: `Install-Winget`, `Install-SandboxTool`, `Start-SandboxTool`, `Stop-SandboxTool`, `Find-SandboxToolExe`.

## Known host conflicts

- **DNS.** The sandbox gets DNS from the host's Internet Connection Sharing proxy at the Default Switch address (172.x.x.1), which often does not answer even when raw IP works. `Invoke-SandboxBootstrap.ps1` therefore points the sandbox at 1.1.1.1 / 8.8.8.8 straight away rather than waiting to find out. If names still fail, it reports whether raw IP works; if that fails too, look at VPN software, a third-party firewall, or `Restart-Service SharedAccess` on the host.
- **Only one sandbox at a time.** Close it from its window (or `(Get-Process WindowsSandboxRemoteSession).CloseMainWindow()`); killing the process orphans the VM (`vmmemWindowsSandbox`) and the next launch fails to connect until an administrator runs `hcsdiag kill <id>`.
- **The LogonCommand runs as a logon task**, so a bare console never shows; the .wsb starts the bootstrap through `cmd /c start` with a titled window.
- **The first launch after enabling the feature takes several minutes** while the base image is built; later launches take about 30 seconds.

## Safety

- Mapped folders should be read-only unless the sandbox genuinely needs to write there; copy the tree inside if a script needs a writable working copy.
- Networking is off unless the environment or `-Networking` turns it on.
- The sandbox user is an administrator. Anything you run inside can do anything to the sandbox; it cannot reach the host outside the mapped folders.
