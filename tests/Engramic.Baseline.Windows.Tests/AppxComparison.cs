using System.Globalization;
using System.Text;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// Compares what each Appx source read with what Get-AppxPackage said, user by user and package by package, and
/// writes it all down: which source missed which package for whom, and which listed one Get-AppxPackage did not.
/// </summary>
internal sealed class AppxComparison
{
    private readonly StringBuilder _report = new();
    private readonly List<(string Source, string Text)> _differences = [];
    private readonly List<(string Source, string Name)> _unregistered = [];

    private AppxComparison()
    {
    }

    /// <summary>Gets the whole comparison, for the test output.</summary>
    public string Report => _report.ToString();

    /// <summary>
    /// Gets each difference that counts against a source: for a user the source says it read, a package
    /// Get-AppxPackage has installed and the source missed, or one the source listed and Get-AppxPackage does not; a
    /// user the source was denied or failed to read; and a user with packages installed whom the source does not list.
    /// </summary>
    public IReadOnlyList<(string Source, string Text)> Differences => _differences;

    /// <summary>Gets the differences that count against one source.</summary>
    /// <param name="source">The source's name.</param>
    /// <returns>Each difference, in words.</returns>
    public IReadOnlyList<string> DifferencesOf(string source) => [.. _differences.Where(d => d.Source == source).Select(d => d.Text)];

    /// <summary>Compares the sources' answers with the oracle's for each user either names.</summary>
    /// <param name="oracle">What Get-AppxPackage said.</param>
    /// <param name="sources">Each source's name, what it read, and how long it took.</param>
    /// <param name="onlyUser">The one user to compare, when the oracle answered for one user only.</param>
    /// <param name="explain">
    /// Says, for a package a source missed for a user, where each source would have found it, and whether Windows'
    /// package runtime says it is registered for the user.
    /// </param>
    public static AppxComparison Compare(OracleAnswer oracle, IReadOnlyList<(string Name, IReadOnlyList<AppxUserPackages> Users, TimeSpan Took)> sources, Func<string, string, (string Text, bool Registered)> explain, Sid? onlyUser = null)
    {
        var comparison = new AppxComparison();
        var r = comparison._report;
        r.AppendLine(CultureInfo.InvariantCulture, $"Appx sources against {oracle.Command}, as {Environment.UserName} (elevated: {Testing.Windows.Elevation.IsElevated}, SYSTEM: {Testing.Windows.Elevation.IsSystem}) on Windows {Environment.OSVersion.Version}.");
        r.AppendLine(CultureInfo.InvariantCulture, $"  {oracle.Command}: {oracle.Installed.Count} users with installed packages, {oracle.Installed.Values.Sum(s => s.Count)} installed registrations, {oracle.Other.Values.Sum(s => s.Count)} in another state; {oracle.Took.TotalMilliseconds:0} ms with PowerShell's start.");
        foreach (var (name, users, took) in sources)
        {
            r.AppendLine(CultureInfo.InvariantCulture, $"  {name}: {users.Count} users, {users.Count(u => u.Outcome == AppxReadOutcome.Read)} read, {users.Sum(u => u.Packages.Count)} packages; {took.TotalMilliseconds:0} ms.");
        }

        var sids = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        if (onlyUser is not null)
        {
            sids.Add(onlyUser.Value);
        }
        else
        {
            sids.UnionWith(oracle.Installed.Keys);
            sids.UnionWith(oracle.Other.Keys);
            foreach (var (_, users, _) in sources)
            {
                sids.UnionWith(users.Select(u => u.User.Value));
            }
        }

        foreach (var sid in sids)
        {
            var expected = oracle.Installed.TryGetValue(sid, out var set) ? set : new HashSet<string>(AppxPackage.FullNameComparer);
            var known = oracle.Installed.ContainsKey(sid) || oracle.Other.ContainsKey(sid);
            var other = oracle.Other.TryGetValue(sid, out var o) ? o.Count : 0;
            r.AppendLine(CultureInfo.InvariantCulture, $"User {sid}: {oracle.Command} has {expected.Count} installed{(other > 0 ? $" and {other} in another state" : string.Empty)}{(known ? string.Empty : " (it names no package for this user)")}.");
            foreach (var (name, users, _) in sources)
            {
                comparison.CompareUser(name, sid, users.FirstOrDefault(u => string.Equals(u.User.Value, sid, StringComparison.OrdinalIgnoreCase)), expected, known, oracle, explain);
            }
        }

        foreach (var (name, _, _) in sources)
        {
            var count = comparison._differences.Count(d => d.Source == name);
            var unregistered = comparison._unregistered.Count(d => d.Source == name);
            r.AppendLine(CultureInfo.InvariantCulture, $"{name}: {(count == 0 ? "no differences" : $"{count} differences")} from {oracle.Command} for the users it read{(unregistered > 0 ? $", not counting {unregistered} it lists that the package runtime says are not registered" : string.Empty)}.");
        }
        return comparison;
    }

    private void CompareUser(string source, string sid, AppxUserPackages? read, HashSet<string> expected, bool known, OracleAnswer answer, Func<string, string, (string Text, bool Registered)> explain)
    {
        var oracle = answer.Command;
        if (read is null)
        {
            _report.AppendLine(CultureInfo.InvariantCulture, $"  {source}: does not list this user{(expected.Count > 0 ? $", so it missed all {expected.Count}" : string.Empty)}.");
            if (expected.Count > 0)
            {
                _differences.Add((source, $"{source} does not list {sid}, who has {expected.Count} packages installed"));
            }

            return;
        }

        if (read.Outcome != AppxReadOutcome.Read)
        {
            // Not loaded is the source saying it does not know, which is allowed; denied or failed, for an account
            // that should be able to read the user, is not.
            _report.AppendLine(string.Create(CultureInfo.InvariantCulture, $"  {source}: {read.Outcome}, so these {expected.Count} are not known to it. {read.Detail}").TrimEnd());
            if (read.Outcome is AppxReadOutcome.Denied or AppxReadOutcome.Failed)
            {
                _differences.Add((source, $"{source} could not read {sid}: {read.Outcome}. {read.Detail}"));
            }

            return;
        }

        var got = new HashSet<string>(read.Packages.Select(p => p.FullName), AppxPackage.FullNameComparer);
        var missed = expected.Where(n => !got.Contains(n)).Order(StringComparer.OrdinalIgnoreCase).ToList();
        var extra = got.Where(n => !expected.Contains(n)).Order(StringComparer.OrdinalIgnoreCase).ToList();
        var detail = read.Detail.Length > 0 ? " " + read.Detail : string.Empty;
        if (missed.Count == 0 && extra.Count == 0)
        {
            _report.AppendLine(CultureInfo.InvariantCulture, $"  {source}: read {got.Count}, the same.{detail}");
            return;
        }

        _report.AppendLine(CultureInfo.InvariantCulture, $"  {source}: read {got.Count}; missed {missed.Count} that {oracle} has, and listed {extra.Count} that it does not{(known ? string.Empty : " (it names no package for this user, so these cannot be checked)")}.{detail}");
        foreach (var name in missed)
        {
            // A package Get-AppxPackage lists as installed for the user that the package runtime, asked about it alone,
            // says is not registered for them is reported but not counted: two of Windows' own views disagree, and the
            // source agrees with the one that says what the user can run.
            var (why, registered) = explain(sid, name);
            _report.AppendLine(CultureInfo.InvariantCulture, $"    missed: {name}{(registered ? string.Empty : " (not counted: the package runtime says it is not registered for this user)")}");
            _report.AppendLine(CultureInfo.InvariantCulture, $"      {oracle}: {(answer.Facts.TryGetValue(name, out var facts) ? facts : "no facts")}");
            _report.AppendLine(CultureInfo.InvariantCulture, $"      {why}");
            if (registered)
            {
                _differences.Add((source, $"{source} missed {name} for {sid}"));
            }
            else
            {
                _unregistered.Add((source, name));
            }
        }

        foreach (var name in extra)
        {
            _report.AppendLine(CultureInfo.InvariantCulture, $"    not in {oracle}: {name}");
            if (known)
            {
                _differences.Add((source, $"{source} listed {name} for {sid}, which {oracle} does not"));
            }
        }
    }
}
