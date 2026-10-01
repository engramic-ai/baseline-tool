using System.CommandLine;
using System.Globalization;
using Engramic.Baseline.Controls;
using Engramic.Baseline.Engine;
using Engramic.Baseline.Model;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Cli;

/// <summary>
/// baseline audit: runs the selected checks on this device and shows the findings, or writes findings.json
/// or status.json to standard output.
/// </summary>
/// <remarks>
/// <para>
/// For development and for comparing the tool with the PowerShell module. It changes nothing: it writes no
/// file itself, since files are written only into the machine data folder, through SecureStore, by the
/// scheduled audit, and it writes no event.
/// </para>
/// <para>
/// Elevated, it reads administrators' config overrides from the data folder's config folder through the config
/// trust gate, as the scheduled audit does, so that an administrator sees what Intune will report; but through
/// SecureStore's read-only way in (<see cref="Windows.SecureStore.OpenReadOnly(Windows.SecureStoreOptions)"/>),
/// which refuses an untrusted folder rather than moving it aside. It names each override it used on standard
/// output beside the summary, or on standard error with <c>--json</c>, so that standard output stays the file
/// alone. It warns on standard error, always, of each override refused or unreadable, and once of a data folder or
/// config folder refused. Nothing goes to the event log. A data folder or config folder that does not exist means
/// no overrides. Not elevated, or with <c>--shipped-config</c>, it reads only the config that ships with the tool;
/// the parity harness passes that switch, and runs the module with an empty data folder, so that both read the
/// same config.
/// </para>
/// </remarks>
internal static class AuditCommand
{
    private const string StatusFormat = "status";
    private const string FindingsFormat = "findings";

    /// <summary>Makes the command, for this device and the console.</summary>
    /// <returns>The command.</returns>
    public static Command Create() => Create(AuditSettings.ForThisDevice, Console.Out, Console.Error, Console.OpenStandardOutput);

    /// <summary>Makes the command with the settings and the console a test gives.</summary>
    /// <param name="settings">Gives what the audit runs with, when the command runs.</param>
    /// <param name="output">Where the summary goes, and the overrides used beside it.</param>
    /// <param name="error">Where problems and warnings go.</param>
    /// <param name="openStandardOutput">Opens the stream findings.json or status.json is written to, byte for byte.</param>
    /// <returns>The command.</returns>
    internal static Command Create(Func<AuditSettings> settings, TextWriter output, TextWriter error, Func<Stream> openStandardOutput)
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
        var shippedConfig = new Option<bool>("--shipped-config")
        {
            Description = "Use only the config that ships with the tool, and ignore administrators' config overrides in the data folder, which an elevated audit otherwise reads.",
        };

        var command = new Command(
            "audit",
            "Audit this device and show the findings. Read-only: it changes nothing. Elevated, it reads administrators' config overrides from the data folder, as the scheduled audit does.");
        command.Options.Add(ids);
        command.Options.Add(excludeIds);
        command.Options.Add(categories);
        command.Options.Add(frameworks);
        command.Options.Add(json);
        command.Options.Add(shippedConfig);
        command.SetAction((parseResult, cancel) => RunAsync(
            new AuditRequest(
                Split(parseResult.GetValue(ids)),
                Split(parseResult.GetValue(excludeIds)),
                Split(parseResult.GetValue(categories)),
                Split(parseResult.GetValue(frameworks)),
                parseResult.GetValue(json),
                parseResult.GetValue(shippedConfig)),
            settings(),
            new AuditConsole(output, error, openStandardOutput),
            cancel));
        return command;
    }

    private static string[] Split(string[]? values)
    {
        return [.. (values ?? []).SelectMany(v => v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))];
    }

    private static async Task<int> RunAsync(AuditRequest request, AuditSettings settings, AuditConsole console, CancellationToken cancel)
    {
        var catalog = settings.Catalog;
        if (!TrySelect(request, catalog, out var selection, out var problem))
        {
            await console.Error.WriteLineAsync(problem).ConfigureAwait(false);
            return 1;
        }

        var device = DeviceContextReader.Read(settings.Registry, settings.ComputerName, settings.Account, settings.Time.GetUtcNow());
        var warnings = new List<string>();

        // Elevated, as the gate requires, unless told to use the shipped config alone. Held open while the checks
        // read config, and only read: nothing in the data folder is created, moved or changed.
        using var dataFolder = !request.ShippedConfigOnly && settings.Account.IsElevated ? OpenDataFolder(settings, warnings) : null;
        var gate = dataFolder is null ? null : new ConfigTrustGate(settings.Config, dataFolder, settings.Account);
        var context = new CheckContext(device, new AuditConfig((IConfigFiles?)gate ?? settings.Config), settings.Time);
        var findings = await new AuditRunner(catalog).RunAsync(selection, context, cancel).ConfigureAwait(false);

        // As the scheduled audit says them, without the events. With --json, standard output is the file alone.
        var used = request.Json is null ? console.Output : console.Error;
        foreach (var path in gate?.Overrides ?? [])
        {
            await used.WriteLineAsync("Config override used: " + path).ConfigureAwait(false);
        }

        foreach (var notice in warnings.Concat(gate?.Notices ?? []))
        {
            await console.Error.WriteLineAsync("Warning: " + notice).ConfigureAwait(false);
        }

        switch (request.Json)
        {
            case StatusFormat:
                await WriteStandardOutputAsync(console, StatusFile.ToBytes(StatusBuilder.Build(findings, catalog, device, settings.ToolVersion)), cancel).ConfigureAwait(false);
                break;
            case FindingsFormat:
                await WriteStandardOutputAsync(console, FindingsFile.ToBytes(new FindingsDocument { Findings = findings }), cancel).ConfigureAwait(false);
                break;
            default:
                await console.Output.WriteAsync(Summary(device, findings, StatusBuilder.Build(findings, catalog, device, settings.ToolVersion))).ConfigureAwait(false);
                break;
        }

        return 0;
    }

    /// <summary>
    /// Opens the data folder only to read administrators' overrides from it. One that is missing gives none; one
    /// that is refused is a warning, and the shipped config is used, as the gate uses it for a refused override.
    /// </summary>
    private static IDataFolderReader? OpenDataFolder(AuditSettings settings, List<string> warnings)
    {
        try
        {
            return settings.OpenDataFolder();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            warnings.Add("Ignoring the config overrides in the data folder and using the shipped config: " + e.Message);
            return null;
        }
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

    private static async Task WriteStandardOutputAsync(AuditConsole console, byte[] bytes, CancellationToken cancel)
    {
        var stdout = console.OpenStandardOutput();
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

    private sealed record AuditRequest(string[] Ids, string[] ExcludeIds, string[] Categories, string[] Frameworks, string? Json, bool ShippedConfigOnly);

    /// <summary>Where the command writes: the summary, problems and warnings, and the bytes of a JSON file.</summary>
    private sealed record AuditConsole(TextWriter Output, TextWriter Error, Func<Stream> OpenStandardOutput);
}
