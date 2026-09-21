# Feature packs

A pack adds checks, remediations, categories and config to Engramic Baseline without changing the core module. The core stays MIT licensed; packs can live in their own (private) repositories. Licensing for paid packs is designed in issue #3.

## Where packs are loaded from

At import, the module looks for pack folders in:

| Folder | Use | Permissions required |
|---|---|---|
| `packs\<pack>` next to the module (repo root) | Local development. Git-ignored. | None |
| Folders listed in `CE_CHECKER_PACKS` (separated by `;` on Windows) | Development and tests | None |
| `%ProgramData%\EngramicBaseline\packs\<pack>` | Installed copies (Intune) | Owned by, and only writable by, SYSTEM, Administrators or TrustedInstaller |

Audits run elevated or as SYSTEM, so a pack under `%ProgramData%` that a standard user could change or owns is refused: loading it would let that user run code as SYSTEM.

`Get-CEPack` lists every pack found, with `Loaded` or `Skipped` and the reason. `Invoke-CEAudit.ps1 -ListChecks` prints the same, and reports and `status.json` list the packs.

## Layout

```
my-pack\
  pack.json
  Checks\*.ps1          (optional)
  Remediations\*.ps1    (optional)
  config\*.json         (optional)
```

`pack.json`:

```json
{
  "id": "ai-agents",
  "name": "AI agent coverage",
  "version": "0.1.0",
  "minCoreVersion": "0.2.0",
  "categories": [ { "id": "AIAgents", "label": "AI agents" } ]
}
```

- `id`: lower-case letters, digits and hyphens. Only the first pack with an id is loaded.
- `version`, `minCoreVersion`: `major.minor.patch`. A pack that needs a newer core is skipped.
- `categories`: PascalCase ids and a label. Reports, the app and `Invoke-CEAudit.ps1 -Category` pick them up.

## Writing checks and remediations

Pack scripts are dot-sourced into the module, in file name order, so they use the same functions as the built-in checks: `Register-CECheck`, `New-CEResult`, `New-CERemediationRef`, `Register-CERemediation`, `Get-CEConfig`, `Get-CERegistryValue` and so on. Functions a pack defines stay available to its checks. Follow the rules in `CONTRIBUTING.md`: ASCII only, Windows PowerShell 5.1 and pwsh 7, strict mode.

- Check ids use two letters and two digits (`AI-01`) and must not clash with built-in or other packs' ids.
- Checks that go beyond Cyber Essentials should use frameworks like `NCSC`, so they don't change the Cyber Essentials verdict.
- A pack's `config\*.json` files are merged into `Get-CEConfig` under their file name. They can't reuse a built-in config name, and an administrator can still override them from `%ProgramData%\EngramicBaseline\config`.

## Isolation

If a pack script throws, everything it registered (checks, remediations, categories, config) is removed and the pack is marked `Skipped`. A pack that redefines a built-in function is refused and the original function is put back. The rest of the audit is unaffected.

## Documentation

`tools/Export-ControlMapping.ps1` leaves pack checks out of `docs/CONTROL-MAPPING.md` unless you pass `-IncludePacks`, so a locally installed pack never ends up in the repository docs. Document a pack in its own repository.
