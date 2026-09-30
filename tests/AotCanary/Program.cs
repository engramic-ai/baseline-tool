using Engramic.Baseline.Engine;
using Engramic.Baseline.Model;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Windows;

// Calls into each AOT-clean library, compiled with Native AOT. Exits 1 if any gives a wrong answer.
var failures = 0;

Expect("Model", Utf8Bom.GetBytes("{}") is [0xEF, 0xBB, 0xBF, (byte)'{', (byte)'}']);
Expect("Model: source-generated JSON", ModelRoundTrip());
Expect("Platform", Sid.TryParse("s-1-5-18", out var sid) && sid == Sid.LocalSystem && RegistryValue.FromDWord(7).Number == 7);
Expect("Engine", CheckIds.IsWellFormed("SU-01") && !CheckIds.IsWellFormed("SU-1") && FindingIds.For("SU-01", "Lifecycle data") == "SU-01:Lifecycle-data");
Expect("Engine: runner and rollups", await EngineRun());
Expect("Windows", ConsoleSession.GetActiveSessionId() is null or > 0);
Expect("Windows: registry and account", WindowsReads());

Console.WriteLine(failures == 0 ? "AOT canary: all libraries ran." : $"AOT canary: {failures} failed.");
return failures == 0 ? 0 : 1;

void Expect(string library, bool passed)
{
    Console.WriteLine($"{library}: {(passed ? "ok" : "FAILED")}");
    if (!passed)
    {
        failures++;
    }
}

static bool ModelRoundTrip()
{
    var lifecycle = ConfigFile.ReadOsLifecycle("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }"""u8);
    var status = new StatusDocument
    {
        ToolVersion = "0.0.0",
        ComputerName = "CANARY",
        AuditTime = DateTimeOffset.UnixEpoch,
        RunAs = "canary",
        Elevated = false,
        Os = "canary",
        Counts = new StatusCounts(),
        AutoFails = ["SU-01"],
        Checks = new Dictionary<string, StatusCheck>(),
        Frameworks = new StatusFrameworks(),
        ReportFolder = string.Empty,
    };
    var read = StatusFile.Parse(StatusFile.ToBytes(status));
    return lifecycle.ReviewWarningDays == 90 && read.ComputerName == "CANARY" && read.AutoFailCount == 1 && read.AuditTime == DateTimeOffset.UnixEpoch;
}

static async Task<bool> EngineRun()
{
    var catalog = new CheckCatalog.Builder().Add(new CanaryCheck()).Build();
    var device = new DeviceContext
    {
        ComputerName = "CANARY",
        OSFamily = "Windows 11",
        InstallationType = "Client",
        ProductName = "canary",
        EditionId = "Professional",
        EditionClass = "Pro",
        DisplayVersion = "25H2",
        Build = 26200,
        Ubr = 1,
        RunningAs = "canary",
        IsElevated = false,
        IsSystem = false,
        AuditTime = DateTimeOffset.UnixEpoch,
    };
    var context = new CheckContext(device, new AuditConfig(new NoConfigFiles()), TimeProvider.System);
    var findings = await new AuditRunner(catalog).RunAsync(CheckSelection.All, context);
    var status = StatusBuilder.Build(findings, catalog, device, "0.0.0");
    return findings is [{ Status: FindingStatus.Pass }]
        && status.Frameworks.CeV33?.MetPct == 100
        && status.Frameworks.CePlus?.TestCases.TC2 == CePlusState.LikelyPass;
}

static bool WindowsReads()
{
    var build = new WindowsRegistry().GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber");
    return build is { Kind: RegistryValueKind.Text } && CurrentProcess.ReadAccount().Name.Length > 0;
}

/// <summary>A check that passes, to run the engine end to end.</summary>
internal sealed class CanaryCheck : Check
{
    public override CheckInfo Info { get; } = new("SU-01", "Canary", CheckCategory.SecurityUpdateManagement, Severity.Critical, [FrameworkTags.CeV33, FrameworkTags.CePlusTC2], "Canary", AutoFail: true);

    public override ValueTask<IReadOnlyList<CheckResult>> RunAsync(CheckContext context, CancellationToken cancel)
    {
        return ValueTask.FromResult<IReadOnlyList<CheckResult>>([new CheckResult(FindingStatus.Pass)]);
    }
}

/// <summary>No config files.</summary>
internal sealed class NoConfigFiles : IConfigFiles
{
    public byte[]? Read(string name) => null;
}
