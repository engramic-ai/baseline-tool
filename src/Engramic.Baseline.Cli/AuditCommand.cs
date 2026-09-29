using System.CommandLine;
using System.Globalization;
using Engramic.Baseline.Controls;
using Engramic.Baseline.Engine;
using Engramic.Baseline.Model;
using Engramic.Baseline.Windows;

namespace Engramic.Baseline.Cli;

/// <summary>
/// baseline audit: runs the selected checks on this device and shows the findings, or writes findings.json
/// or status.json to standard output.
/// </summary>
/// <remarks>
/// For development and for comparing the tool with the PowerShell module. It writes no file itself: files
/// are written only into the machine data folder, through SecureStore, by the scheduled audit.
/// </remarks>
internal static class AuditCommand
{
    private const string StatusFormat = "status";
    private const string FindingsFormat = "findings";

    /// <summary>Makes the command.</summary>
    /// <returns>The command.</returns>
    public static Command Create()
    {
        var ids = new Option<string[]>("--id")
        {
            Description = "Run only these checks, such as SU-01. Repeat it or separate identifiers with commas.",
            HelpName = "ID",
            AllowMultipleArgumentsPerToken = true,
        };
        var excludeIds = new Option<string[]>("--exclude-id")
        {
            Description = "Do not run these checks, even if they are not in this version yet.",
            HelpName = "ID",
            AllowMultipleArgumentsPerToken = true,
        };
        var categories = new Option<string[]>("--category")
        {
            Description = "Run only the checks of these themes: " + string.Join(", ", Enum.GetNames<CheckCategory>()) + ".",
            HelpName = "THEME",
            AllowMultipleArgumentsPerToken = true,
        };
        var frameworks = new Option<string[]>("--framework")
        {
            Description = "Run only the checks with a framework tag that starts with these, such as CE or NCSC.",
            HelpName = "TAG",
            AllowMultipleArgumentsPerToken = true,
        };
        var json = new Option<string?>("--json")
        {
            Description = "Write findings.json or status.json to standard output instead of the summary, byte for byte as the file is written: UTF-8 with a byte order mark. Redirect it to a file.",
            HelpName = "status|findings",
        };
        json.AcceptOnlyFromAmong(StatusFormat, FindingsFormat);

        var command = new Command("audit", "Audit this device and show the findings. Read-only: it changes nothing.");
        command.Options.Add(ids);
        command.Options.Add(excludeIds);
        command.Options.Add(categories);
        command.Options.Add(frameworks);
        command.Options.Add(json);
        command.SetAction((parseResult, cancel) => RunAsync(
            new AuditRequest(
                Split(parseResult.GetValue(ids)),
                Split(parseResult.GetValue(excludeIds)),
                Split(parseResult.GetValue(categories)),
                Split(parseResult.GetValue(frameworks)),
                parseResult.GetValue(json)),
            cancel));
        return command;
    }

    private static string[] Split(string[]? values)
    {
        return [.. (values ?? []).SelectMany(v => v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))];
    }

    private static async Task<int> RunAsync(AuditRequest request, CancellationToken cancel)
    {
        var catalog = BuiltInChecks.CreateCatalog();
        if (!TrySelect(request, catalog, out var selection, out var problem))
        {
            await Console.Error.WriteLineAsync(problem).ConfigureAwait(false);
            return 1;
        }

        var time = TimeProvider.System;
        var device = DeviceContextReader.Read(new WindowsRegistry(), Environment.MachineName, CurrentProcess.ReadAccount(), time.GetUtcNow());
        var context = new CheckContext(device, new AuditConfig(ShippedConfig.Files), time);
        var findings = await new AuditRunner(catalog).RunAsync(selection, context, cancel).ConfigureAwait(false);

        switch (request.Json)
        {
            case StatusFormat:
                await WriteStandardOutputAsync(StatusFile.ToBytes(StatusBuilder.Build(findings, catalog, device, ToolVersion.Current)), cancel).ConfigureAwait(false);
                break;
            case FindingsFormat:
                await WriteStandardOutputAsync(FindingsFile.ToBytes(new FindingsDocument { Findings = findings }), cancel).ConfigureAwait(false);
                break;
            default:
                await Console.Out.WriteAsync(Summary(device, findings, StatusBuilder.Build(findings, catalog, device, ToolVersion.Current))).ConfigureAwait(false);
                break;
        }

        return 0;
    }

    private static bool TrySelect(AuditRequest request, CheckCatalog catalog, out CheckSelection selection, out string problem)
    {
        selection = CheckSelection.All;
        problem = string.Empty;
        // A check that is not ported yet may be excluded (as the scheduled audit's excludeCheckIds will), but not run.
        var unknownIds = request.Ids.Where(id => catalog.Find(id) is null).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (unknownIds.Count > 0)
        {
            problem = $"Not a check this version has: {string.Join(", ", unknownIds)}. Checks: {string.Join(", ", catalog.Checks.Select(c => c.Info.Id))}.";
            return false;
        }

        var themes = new List<CheckCategory>();
        foreach (var name in request.Categories)
        {
            if (!name.All(char.IsAsciiLetter) || !Enum.TryParse<CheckCategory>(name, ignoreCase: true, out var theme))
            {
                problem = $"Unknown category: {name}. Valid categories: {string.Join(", ", Enum.GetNames<CheckCategory>())}.";
                return false;
            }

            themes.Add(theme);
        }

        selection = new CheckSelection
        {
            Ids = request.Ids,
            ExcludeIds = request.ExcludeIds,
            Categories = themes,
            Frameworks = request.Frameworks,
        };
        return true;
    }

    private static async Task WriteStandardOutputAsync(byte[] bytes, CancellationToken cancel)
    {
        var stdout = Console.OpenStandardOutput();
        await using (stdout.ConfigureAwait(false))
        {
            await stdout.WriteAsync(bytes, cancel).ConfigureAwait(false);
            await stdout.FlushAsync(cancel).ConfigureAwait(false);
        }
    }

    /// <summary>The summary a person reads, as the PowerShell tool's Invoke-CEAudit.ps1 prints it.</summary>
    private static string Summary(DeviceContext device, IReadOnlyList<Finding> findings, StatusDocument status)
    {
        var text = new System.Text.StringBuilder();
        var culture = CultureInfo.InvariantCulture;
        text.AppendLine("Cyber Essentials v3.3 / CE+ / NCSC device audit");
        text.AppendLine(culture, $"  Device : {device.ComputerName}  ({device.OSFamily} {device.DisplayVersion} {device.EditionId}, build {device.FullBuild})");
        text.AppendLine(culture, $"  User   : {device.RunningAs}  [{(device.IsElevated ? "elevated" : "not elevated")}]");
        if (!device.IsElevated)
        {
            text.AppendLine("  Note   : not elevated, so admin-only checks are marked Skipped. Run it again as administrator for full coverage.");
        }

        text.AppendLine();
        foreach (var f in findings)
        {
            var label = string.IsNullOrEmpty(f.Subject) ? f.Title : $"{f.Title} ({f.Subject})";
            text.AppendLine(culture, $"  {f.CheckId,-8} {f.Status,-7} {label}{(f.AutoFail ? " [AUTO-FAIL]" : string.Empty)}");
        }

        text.AppendLine();
        var rollups = new (string Key, FrameworkRollup? Rollup)[] { ("ce-v3.3", status.Frameworks.CeV33), ("ncsc", status.Frameworks.Ncsc) };
        text.AppendLine(culture, $"Frameworks: {string.Join("  ", rollups.Where(r => r.Rollup is not null).Select(r => string.Create(culture, $"{r.Key}={r.Rollup!.MetPct}%")))}");
        text.AppendLine("CE+ device test estimate:");
        foreach (var outcome in CePlusTestCases.Evaluate(findings))
        {
            text.AppendLine(culture, $"  {outcome.TestCase.Id} {outcome.TestCase.Name,-38} {StateText(outcome.State)}");
        }

        return text.ToString();
    }

    private static string StateText(CePlusState state) => state switch
    {
        CePlusState.NotAssessed => "Not assessed",
        CePlusState.LikelyFail => "Likely fail",
        CePlusState.Check => "Check",
        _ => "Likely pass",
    };

    private sealed record AuditRequest(string[] Ids, string[] ExcludeIds, string[] Categories, string[] Frameworks, string? Json);
}
