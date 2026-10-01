using System.Diagnostics;
using System.Text;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// What Windows' own package manager says is installed, for comparing the Appx sources with: Get-AppxPackage in
/// Windows PowerShell 5.1, run hidden as a separate process, so that WinRT never comes near the product's libraries.
/// </summary>
internal static class AppxOracle
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(120);

    private static string PowerShell => Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");

    /// <summary>
    /// Get-AppxPackage -AllUsers: for each user it names, the full names of the packages whose state for them is
    /// Installed, and of those in any other state (such as Staged) apart.
    /// </summary>
    public static OracleAnswer ForAllUsers()
    {
        // One line for each package and user: the user's SID, the user's install state, then the package's own facts.
        const string Script = """
            $ErrorActionPreference = 'Stop'
            $ProgressPreference = 'SilentlyContinue'
            Get-AppxPackage -AllUsers | ForEach-Object {
                $p = $_
                foreach ($u in @($p.PackageUserInformation)) { '{0}|{1}|{2}|{3}|{4}|{5}' -f $u.UserSecurityId.Sid, $u.InstallState, $p.PackageFullName, $p.Status, $p.SignatureKind, $p.InstallLocation }
            }
            """;
        return Parse("Get-AppxPackage -AllUsers", Script, user: null);
    }

    /// <summary>Get-AppxPackage with no user named: the packages of the account running the tests.</summary>
    public static OracleAnswer ForCurrentUser(Sid user)
    {
        const string Script = """
            $ErrorActionPreference = 'Stop'
            $ProgressPreference = 'SilentlyContinue'
            Get-AppxPackage | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.PackageFullName, $_.Status, $_.SignatureKind, $_.InstallLocation }
            """;
        return Parse("Get-AppxPackage", Script, user);
    }

    private static OracleAnswer Parse(string command, string script, Sid? user)
    {
        var stopwatch = Stopwatch.StartNew();
        var lines = Run(script);
        stopwatch.Stop();
        var installed = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var other = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var facts = new Dictionary<string, string>(AppxPackage.FullNameComparer);
        if (user is not null)
        {
            installed[user.Value] = new HashSet<string>(AppxPackage.FullNameComparer);
        }

        foreach (var line in lines)
        {
            var parts = user is null ? line.Split('|', 6) : [user.Value, "Installed", .. line.Split('|', 4)];
            if (parts.Length != 6)
            {
                throw new InvalidOperationException($"{command} gave a line that is not user|state|package|status|signature|folder: {line}");
            }

            var target = string.Equals(parts[1], "Installed", StringComparison.OrdinalIgnoreCase) ? installed : other;
            if (!target.TryGetValue(parts[0], out var set))
            {
                set = new HashSet<string>(AppxPackage.FullNameComparer);
                target[parts[0]] = set;
            }

            set.Add(parts[2]);
            facts[parts[2]] = $"status {parts[3]}, signature {parts[4]}, folder {parts[5]} ({(parts[5].Length > 0 && Directory.Exists(parts[5]) ? "exists" : "not found")})";
        }

        return new OracleAnswer(command, installed, other, facts, stopwatch.Elapsed);
    }

    private static List<string> Run(string script)
    {
        var start = new ProcessStartInfo(PowerShell)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-OutputFormat", "Text", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes("[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)\n" + script)) })
        {
            start.ArgumentList.Add(argument);
        }

        // Windows PowerShell finds its own modules; a PSModulePath from PowerShell 7 would point it at 7's.
        start.Environment.Remove("PSModulePath");
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Windows PowerShell did not start.");
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(Timeout))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"Get-AppxPackage did not finish within {Timeout.TotalSeconds} seconds.");
        }

        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"Get-AppxPackage failed ({process.ExitCode}): {errors.Result}");
        }

        return [.. output.Result.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0)];
    }
}

/// <summary>What Get-AppxPackage answered.</summary>
/// <param name="Command">The command that was run.</param>
/// <param name="Installed">For each user's SID, the full names of the packages installed for them.</param>
/// <param name="Other">For each user's SID, the full names of the packages in another state for them, such as Staged.</param>
/// <param name="Facts">For each full name, what Get-AppxPackage says of the package: its status, signature kind and folder.</param>
/// <param name="Took">How long the command took, Windows PowerShell's start included.</param>
internal sealed record OracleAnswer(string Command, Dictionary<string, HashSet<string>> Installed, Dictionary<string, HashSet<string>> Other, Dictionary<string, string> Facts, TimeSpan Took);
