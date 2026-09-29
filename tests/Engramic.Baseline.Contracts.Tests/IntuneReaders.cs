using System.Diagnostics;
using System.Text.Json;
using Engramic.Baseline.Model;

namespace Engramic.Baseline.Contracts.Tests;

/// <summary>What one Intune script reported in one host (tools/contracts/Invoke-IntuneReaders.ps1).</summary>
/// <param name="Script">Discover or Detect.</param>
/// <param name="Bitness">64-bit or 32-bit, the host it was run in.</param>
/// <param name="Is64BitProcess">What the host said it was.</param>
/// <param name="PSVersion">The host's version.</param>
/// <param name="ExitCode">The script's exit code.</param>
/// <param name="Output">What the script printed, a line each.</param>
/// <param name="Errors">What it wrote to the error stream.</param>
/// <param name="Values">Its output as names and values, or null when it is not in the script's usual form.</param>
/// <param name="TaskStartRequested">Whether it tried to start the scheduled audit.</param>
internal sealed record ReaderRun(
    string Script,
    string Bitness,
    bool Is64BitProcess,
    string PSVersion,
    int ExitCode,
    IReadOnlyList<string> Output,
    IReadOnlyList<string> Errors,
    IReadOnlyDictionary<string, string>? Values,
    bool TaskStartRequested)
{
    /// <summary>Gets a value the script reported: text as it is, anything else as JSON writes it.</summary>
    public string Value(string name) => Values is { } values && values.TryGetValue(name, out var value)
        ? value
        : throw new KeyNotFoundException($"{Script} in {Bitness} Windows PowerShell reported no {name}: {string.Join(" / ", Output)}");

    /// <summary>Gets what the script reported, in one line, to compare runs.</summary>
    public string Reported => $"exit {ExitCode}: {string.Join(" / ", Output)}";
}

/// <summary>
/// Runs the unchanged Intune discovery and detection scripts on a status.json, in 64-bit and 32-bit Windows
/// PowerShell 5.1, through tools/contracts/Invoke-IntuneReaders.ps1.
/// </summary>
internal static class IntuneReaders
{
    private static readonly Lazy<string> Root = new(FindRoot);

    /// <summary>Gets why the scripts cannot run here, or null when they can.</summary>
    public static string? Unavailable
    {
        get
        {
            if (!OperatingSystem.IsWindows())
            {
                return "The Intune scripts run in Windows PowerShell 5.1, which only Windows has.";
            }

            return File.Exists(PowerShell) ? null : $"Windows PowerShell 5.1 is not at {PowerShell}.";
        }
    }

    private static string PowerShell => Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");

    /// <summary>Runs both scripts in both hosts on a copy of these bytes, and returns what each reported.</summary>
    public static IReadOnlyList<ReaderRun> Run(byte[] statusJson)
    {
        var work = Directory.CreateTempSubdirectory("engramic-contracts-");
        try
        {
            var status = Path.Combine(work.FullName, "status.json");
            File.WriteAllBytes(status, statusJson);
            var results = Path.Combine(work.FullName, "readers.json");
            var start = new ProcessStartInfo(PowerShell)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            string[] arguments =
            [
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", Path.Combine(Root.Value, "tools", "contracts", "Invoke-IntuneReaders.ps1"),
                "-StatusPath", status, "-ResultPath", results, "-WorkPath", work.FullName,
            ];
            foreach (var argument in arguments)
            {
                start.ArgumentList.Add(argument);
            }

            // Windows PowerShell finds its own modules; a PSModulePath from PowerShell 7 would point it at 7's.
            start.Environment.Remove("PSModulePath");
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Windows PowerShell did not start.");
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(TimeSpan.FromSeconds(25)))
            {
                process.Kill(entireProcessTree: true);
                throw new TimeoutException("Invoke-IntuneReaders.ps1 did not finish within 25 seconds.");
            }

            process.WaitForExit();
            if (process.ExitCode != 0 || !File.Exists(results))
            {
                throw new InvalidOperationException($"Invoke-IntuneReaders.ps1 failed ({process.ExitCode}): {error.Result}\n{output.Result}");
            }

            return Parse(File.ReadAllBytes(results));
        }
        finally
        {
            try
            {
                work.Delete(recursive: true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // A scanner can hold a file for a moment; a folder left in the temp folder does no harm.
            }
        }
    }

    private static List<ReaderRun> Parse(byte[] json)
    {
        using var document = JsonDocument.Parse(json.AsMemory(json.AsSpan().StartsWith(Utf8Bom.Preamble) ? Utf8Bom.Preamble.Length : 0));
        return [.. document.RootElement.EnumerateArray().Select(run => new ReaderRun(
            run.GetProperty("Script").GetString()!,
            run.GetProperty("Bitness").GetString()!,
            run.GetProperty("Is64BitProcess").GetBoolean(),
            run.GetProperty("PSVersion").GetString()!,
            run.GetProperty("ExitCode").GetInt32(),
            Lines(run.GetProperty("Output")),
            Lines(run.GetProperty("Errors")),
            run.GetProperty("Values") is { ValueKind: JsonValueKind.Object } values
                ? values.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString()! : p.Value.GetRawText(), StringComparer.Ordinal)
                : null,
            run.GetProperty("TaskStartRequested").GetBoolean()))];
    }

    /// <summary>A list of lines, which Windows PowerShell writes as a string when there is one and null when there are none.</summary>
    private static List<string> Lines(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Array => [.. element.EnumerateArray().Select(e => e.GetString() ?? string.Empty)],
        JsonValueKind.String => [element.GetString()!],
        _ => [],
    };

    private static string FindRoot()
    {
        for (var folder = new DirectoryInfo(AppContext.BaseDirectory); folder is not null; folder = folder.Parent)
        {
            if (File.Exists(Path.Combine(folder.FullName, "Baseline.slnx")))
            {
                return folder.FullName;
            }
        }

        throw new InvalidOperationException("Baseline.slnx was not found above " + AppContext.BaseDirectory);
    }
}
