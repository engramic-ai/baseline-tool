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
Expect("Engine: config trust gate", ConfigTrustGateDecides());
Expect("Windows", ConsoleSession.GetActiveSessionId() is null or > 0);
Expect("Windows: registry and account", WindowsReads());
Expect("Platform: data folder trust", TrustRules());
Expect("Windows: SecureStore", SecureStoreRefusesAMissingFolder());
Expect("Windows: SecureStore set-up", SecureStoreSetUpRefusesAMissingFolder());
Expect("Windows: audit mutex", AuditMutexTurns());

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

static bool ConfigTrustGateDecides()
{
    // An override that meets its schema replaces the shipped file; one that names a member twice does not.
    var shipped = new CanaryConfigFiles("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }""");
    var system = new ProcessAccount(@"NT AUTHORITY\SYSTEM", IsAdministrator: true, IsLocalSystem: true);
    using var valid = new CanaryStore("""{ "lastReviewed": "2026-01-01", "reviewWarningDays": 30, "upcomingEndWarningDays": 60 }""");
    using var twice = new CanaryStore("""{ "lastReviewed": "2026-01-01", "reviewWarningDays": 30, "upcomingEndWarningDays": 60, "lastReviewed": "2020-01-01" }""");
    var loaded = new ConfigTrustGate(shipped, valid, system);
    var refused = new ConfigTrustGate(shipped, twice, system);
    return new AuditConfig(loaded).OsLifecycle.LastReviewed == "2026-01-01" && loaded.Overrides.Count == 1
        && new AuditConfig(refused).OsLifecycle.LastReviewed == "2026-09-16" && refused.Notices.Count == 1;
}

static bool WindowsReads()
{
    var build = new WindowsRegistry().GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber");
    return build is { Kind: RegistryValueKind.Text } && CurrentProcess.ReadAccount().Name.Length > 0;
}

static bool TrustRules()
{
    var locked = new ItemSecurity(Sid.Administrators, [new AccessEntry(AccessEntryType.Allow, Sid.LocalSystem, 0x1F01FF), new AccessEntry(AccessEntryType.Allow, Sid.Administrators, 0x1F01FF)]);
    var writable = locked with { Dacl = [.. locked.Dacl!, new AccessEntry(AccessEntryType.Allow, Sid.Users, 0x2)] };
    var folder = new FileFacts { IsDirectory = true };
    return DataFolderTrust.Machine.FindDataFolderProblem("C:\\ProgramData\\EngramicBaseline", folder, locked, isSealed: true) is null
        && DataFolderTrust.Machine.FindDataFolderProblem("C:\\ProgramData\\EngramicBaseline", folder, writable, isSealed: true) is not null
        && DataFolderLayout.AsideName("EngramicBaseline", "0123456789abcdef0123456789abcdef", "reports") == "EngramicBaseline.untrusted-0123456789abcdef0123456789abcdef-reports";
}

static bool SecureStoreRefusesAMissingFolder()
{
    // The machine's ProgramData from the known-folder API, then a folder that does not exist: nothing is touched.
    var machine = SecureStoreOptions.ForMachine(new WindowsRegistry(), TimeProvider.System);
    var missing = machine with { ProgramDataPath = Path.Combine(Path.GetTempPath().TrimEnd('\\'), "baseline-canary-" + Guid.NewGuid().ToString("n")) };
    try
    {
        SecureStore.Open(missing).Dispose();
        return false;
    }
    catch (SecureStoreException e)
    {
        return machine.ProgramDataPath.EndsWith(":\\ProgramData", StringComparison.OrdinalIgnoreCase) && e.Message.Contains("does not exist", StringComparison.Ordinal);
    }
}

static bool SecureStoreSetUpRefusesAMissingFolder()
{
    // A ProgramData folder that does not exist, and an event log that keeps nothing: nothing is made or written.
    var machine = SecureStoreOptions.ForMachine(new WindowsRegistry(), TimeProvider.System);
    var missing = machine with { ProgramDataPath = Path.Combine(Path.GetTempPath().TrimEnd('\\'), "baseline-canary-" + Guid.NewGuid().ToString("n")), EventLog = new NoEvents() };
    try
    {
        SecureStore.Initialize(missing).Dispose();
        return false;
    }
    catch (SecureStoreException e)
    {
        return e.Message.Contains("does not exist", StringComparison.Ordinal) && !Directory.Exists(missing.ProgramDataPath);
    }
}

static bool AuditMutexTurns()
{
    // A name of the canary's own, never the product's audit mutex.
    var name = "Global\\Engramic.Baseline.Canary." + Guid.NewGuid().ToString("n");
    using var held = AuditMutex.TryAcquire(name, TimeSpan.FromSeconds(5));
    return held is not null;
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

/// <summary>An event log that keeps nothing.</summary>
internal sealed class NoEvents : IEventLog
{
    public bool Write(int eventId, EventLogLevel level, string message) => true;
}

/// <summary>No config files.</summary>
internal sealed class NoConfigFiles : IConfigFiles
{
    public byte[]? Read(string name) => null;
}

/// <summary>The shipped os-lifecycle.json, and no other file.</summary>
internal sealed class CanaryConfigFiles(string lifecycle) : IConfigFiles
{
    public byte[]? Read(string name) => name == ConfigFile.OsLifecycleName ? System.Text.Encoding.UTF8.GetBytes(lifecycle) : null;
}

/// <summary>A data folder in memory whose config folder holds one os-lifecycle.json.</summary>
internal sealed class CanaryStore(string lifecycle) : ISecureStore
{
    public string RootPath => @"C:\ProgramData\EngramicBaseline";

    public IReadOnlyList<string> Notices => [];

    public byte[]? ReadFile(DataFolder folder, string name, int maxLength)
    {
        return folder == DataFolder.Config && name == ConfigFile.OsLifecycleName ? System.Text.Encoding.UTF8.GetBytes(lifecycle) : null;
    }

    public void WriteFile(string name, ReadOnlySpan<byte> content) => throw new NotSupportedException();

    public void WriteFile(DataFolder folder, string name, ReadOnlySpan<byte> content) => throw new NotSupportedException();

    public IScratchFolder CreateScratchFolder() => throw new NotSupportedException();

    public IReadOnlyList<string> DeleteTree(DataFolder folder, string name) => throw new NotSupportedException();

    public void Dispose()
    {
    }
}
