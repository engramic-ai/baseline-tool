using System.Globalization;
using Engramic.Baseline.Engine;
using Engramic.Baseline.Model;

namespace Engramic.Baseline.Controls.Checks;

/// <summary>
/// SU-01: the operating system is licensed and supported by Microsoft. An auto-fail check: Cyber
/// Essentials fails a device whose operating system no longer gets security updates.
/// </summary>
/// <remarks>
/// <para>
/// Ported from the PowerShell tool (Checks/03-SecurityUpdateManagement.ps1), with its statuses,
/// severities and words. The release is judged against config/os-lifecycle.json on today's local date:
/// </para>
/// <list type="bullet">
/// <item>A Warn (Low, subject Lifecycle data) first, when the data was reviewed more than reviewWarningDays ago.</item>
/// <item>Windows Server: its build in windowsServer against extendedEnd, or Manual when the build is not listed.</item>
/// <item>Windows 10: Fail, whatever the build.</item>
/// <item>Anything that is not Windows 11 (build 0 when unreadable, or older than Windows 10): Fail.</item>
/// <item>Windows 11: its build in windows11 against the enterprise date for Enterprise editions (LTSC and
/// IoT included) and the homePro date for the rest; Manual when the build is not listed or has no date.</item>
/// </list>
/// <para>
/// A date is Fail once passed, Warn (High) up to upcomingEndWarningDays before it, the day itself
/// included, and Pass before that. Config the check needs but cannot read makes an Error finding.
/// </para>
/// <para>
/// A member the branch taken reads but the file does not have is an Error too, as reading it is under
/// the PowerShell tool's strict mode: source when the data is out of date, build in each entry up to the
/// one that matches, version and the date the edition uses in that entry, and endOfSupport for Windows 10.
/// A member written as null is read as null (empty in text), as there.
/// </para>
/// </remarks>
internal sealed class OperatingSystemSupported : Check
{
    /// <summary>What the check is.</summary>
    public static readonly CheckInfo Definition = new(
        Id: "SU-01",
        Title: "Operating system is licensed and supported by Microsoft",
        Category: CheckCategory.SecurityUpdateManagement,
        Severity: Severity.Critical,
        Frameworks: [FrameworkTags.CeV33, FrameworkTags.CePlusTC2],
        Reference: "CE v3.3 Security update management: all software must be licensed and supported, and removed when it becomes unsupported.",
        AutoFail: true);

    private const string SupportedExpected = "Supported Windows version";
    private const string ListedExpected = "Build listed in config/os-lifecycle.json";

    public override CheckInfo Info => Definition;

    public override ValueTask<IReadOnlyList<CheckResult>> RunAsync(CheckContext context, CancellationToken cancel)
    {
        ArgumentNullException.ThrowIfNull(context);
        var lifecycle = context.Config.OsLifecycle;
        var device = context.Device;
        var today = DateOnly.FromDateTime(context.Time.GetLocalNow().DateTime);
        var results = new List<CheckResult>();

        var reviewed = ParseDate(lifecycle.LastReviewed, "lastReviewed");
        if (today.DayNumber - reviewed.DayNumber > lifecycle.ReviewWarningDays)
        {
            results.Add(new CheckResult(FindingStatus.Warn)
            {
                Subject = "Lifecycle data",
                Severity = Severity.Low,
                Expected = Invariant($"Lifecycle data reviewed within {lifecycle.ReviewWarningDays} days"),
                Actual = $"config/os-lifecycle.json last reviewed {lifecycle.LastReviewed}",
                Recommendation = $"Update config/os-lifecycle.json from {Member(lifecycle.HasSource, lifecycle.Source, "source")}.",
            });
        }

        results.Add(Judge(lifecycle, device, today));
        return ValueTask.FromResult<IReadOnlyList<CheckResult>>(results);
    }

    private static CheckResult Judge(OsLifecycle lifecycle, DeviceContext device, DateOnly today)
    {
        if (device.OSFamily == WindowsFamily.Server)
        {
            var server = Require(lifecycle.WindowsServer, "windowsServer")
                .FirstOrDefault(r => ListedBuild(r.Build, r.HasBuild, "windowsServer") == device.Build);
            if (server is null)
            {
                return new CheckResult(FindingStatus.Manual)
                {
                    Expected = ListedExpected,
                    Actual = $"Windows Server build {device.FullBuild} ({device.ProductName}) is not in the lifecycle data",
                    Recommendation = "Check this Windows Server release is still supported (Microsoft lifecycle pages) and add it to config/os-lifecycle.json.",
                };
            }

            return AgainstDate(
                lifecycle,
                today,
                $"Windows Server {Member(server.HasVersion, server.Version, Invariant($"version for Windows Server build {server.Build}"))} {device.EditionId} (build {device.FullBuild})",
                server.ExtendedEnd,
                "Migrate to a supported Windows Server release, or enrol in Extended Security Updates and record the evidence.",
                "Plan the migration to a newer Windows Server release (or ESU) before this date.");
        }

        if (device.OSFamily == WindowsFamily.Windows10)
        {
            return new CheckResult(FindingStatus.Fail)
            {
                Expected = SupportedExpected,
                Actual = $"Windows 10 build {device.FullBuild}: support ended {EndOfWindows10(lifecycle)}",
                Recommendation = "Upgrade to a supported Windows 11 release. A device enrolled in Extended Security Updates can remain in scope only while ESU is active and updates are applied; record the ESU evidence if so.",
            };
        }

        if (device.OSFamily != WindowsFamily.Windows11)
        {
            return new CheckResult(FindingStatus.Fail)
            {
                Expected = SupportedExpected,
                Actual = $"Unrecognised OS build {device.FullBuild}",
                Recommendation = "Move to a supported Windows 11 release.",
            };
        }

        var release = Require(lifecycle.Windows11, "windows11")
            .FirstOrDefault(r => ListedBuild(r.Build, r.HasBuild, "windows11") == device.Build);
        if (release is null)
        {
            return new CheckResult(FindingStatus.Manual)
            {
                Expected = ListedExpected,
                Actual = Invariant($"Windows 11 build {device.Build} ({device.DisplayVersion}) not in lifecycle data"),
                Recommendation = "Check the build is in support on Microsoft release health and add it to config/os-lifecycle.json.",
            };
        }

        var end = device.EditionClass == EditionClass.Enterprise
            ? Member(release.HasEnterprise, release.Enterprise, Invariant($"enterprise for Windows 11 build {release.Build}"))
            : Member(release.HasHomePro, release.HomePro, Invariant($"homePro for Windows 11 build {release.Build}"));
        var version = Member(release.HasVersion, release.Version, Invariant($"version for Windows 11 build {release.Build}"));
        if (string.IsNullOrEmpty(end))
        {
            return new CheckResult(FindingStatus.Manual)
            {
                Expected = "Known end-of-servicing date",
                Actual = $"Windows 11 {version} ({device.EditionId}): end date not recorded",
                Recommendation = "Confirm the end-of-servicing date on Microsoft release health and add it to config/os-lifecycle.json.",
            };
        }

        return AgainstDate(
            lifecycle,
            today,
            $"Windows 11 {version} {device.EditionId} (build {device.FullBuild})",
            end,
            "Install the latest Windows 11 feature update now (Settings > Windows Update).",
            "Plan the upgrade to the next Windows 11 feature update before this date, or the device drops out of scope.");
    }

    /// <summary>Pass, Warn or Fail against an end-of-support date: the PowerShell tool's $judge.</summary>
    private static CheckResult AgainstDate(OsLifecycle lifecycle, DateOnly today, string label, string? endText, string failFix, string warnFix)
    {
        var end = ParseDate(endText, "end-of-support date");
        var daysLeft = end.DayNumber - today.DayNumber;
        var endShown = end.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        if (daysLeft < 0)
        {
            return new CheckResult(FindingStatus.Fail) { Expected = SupportedExpected, Actual = $"{label}: support ended {endShown}", Recommendation = failFix };
        }

        if (daysLeft <= lifecycle.UpcomingEndWarningDays)
        {
            return new CheckResult(FindingStatus.Warn)
            {
                Severity = Severity.High,
                Expected = SupportedExpected,
                Actual = Invariant($"{label}: support ends {endShown} ({daysLeft} days)"),
                Recommendation = warnFix,
            };
        }

        return new CheckResult(FindingStatus.Pass) { Expected = SupportedExpected, Actual = $"{label}: supported until {endShown}" };
    }

    /// <summary>A date written yyyy-MM-dd, read as strictly as the PowerShell tool's ConvertTo-CEDate.</summary>
    private static DateOnly ParseDate(string? text, string what)
    {
        return DateOnly.ParseExact(Require(text, what), "yyyy-MM-dd", CultureInfo.InvariantCulture);
    }

    /// <summary>What Windows 10's end of support reads in the PowerShell tool: $lc.windows10.endOfSupport.</summary>
    private static string? EndOfWindows10(OsLifecycle lifecycle)
    {
        var windows10 = Require(lifecycle.Windows10, "windows10");
        return Member(windows10.HasEndOfSupport, windows10.EndOfSupport, "endOfSupport in windows10");
    }

    private static T Require<T>(T? value, string what)
        where T : class
    {
        return value ?? throw new InvalidDataException($"config/os-lifecycle.json has no {what}.");
    }

    /// <summary>An entry's build, as the PowerShell tool's [int]$_.build reads it for each entry up to the one that matches.</summary>
    private static int ListedBuild(int build, bool present, string section)
    {
        return present ? build : throw new InvalidDataException($"config/os-lifecycle.json has an entry in {section} with no build.");
    }

    /// <summary>A member as strict mode reads it: an error when the file does not have it, whatever it holds when it does.</summary>
    private static T Member<T>(bool present, T value, string what)
    {
        return present ? value : throw new InvalidDataException($"config/os-lifecycle.json has no {what}.");
    }

    private static string Invariant(FormattableString text) => text.ToString(CultureInfo.InvariantCulture);
}
