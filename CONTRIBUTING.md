# Contributing

**We are not accepting external code contributions at this time.** Engramic
Baseline is early and moving fast, and we haven't yet put the contributor
agreement in place that an open-core project needs (contributions to the core
may also be used in commercial feature packs). We expect to open up to
contributions later.

In the meantime:

- **Found a bug, or want a check or fix?** Please [open an issue](../../issues) describing it. That's the most useful thing you can do right now.
- **Security issue?** See [SECURITY.md](SECURITY.md) - please do not file security reports as public issues.

Thanks for your interest.

## Licence

Engramic Baseline is licensed under the **Apache License, Version 2.0** (see [LICENSE](LICENSE) and [NOTICE](NOTICE)).

## Conventions in this codebase

For reference (and for when contributions do open up), the code follows these rules:

- **ASCII only** in sources.
- Must run on **Windows PowerShell 5.1 and PowerShell 7**. `Set-StrictMode -Version 2.0` is on.
- A check is `Register-CECheck` in `src/CEAudit/Checks`; a fix is `Register-CERemediation` in `src/CEAudit/Remediations`. Remediations must record undo data and validate every parameter.
- Read optional remediation parameters with `Get-CEParamValue`, never `$p.Name` (strict mode throws).
- Tunables go in `config/*.json`.
- After adding checks or remediations, update the counts in `tests/CEAudit.Tests.ps1` and `README.md`, then regenerate `docs/CONTROL-MAPPING.md` with `tools/Export-ControlMapping.ps1`.
- Run the Pester tests on both PowerShell versions and PSScriptAnalyzer (`.github/PSScriptAnalyzerSettings.psd1`) before proposing a change.
