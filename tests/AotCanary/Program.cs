using System.Diagnostics;
using System.Globalization;
using System.Security.Principal;
using Engramic.Baseline.Engine;
using Engramic.Baseline.Model;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Windows;

// Calls into each AOT-clean library, compiled with Native AOT. Exits 1 if any gives a wrong answer. Then prints
// what the run cost (Measure), and, compiled with Native AOT beside a JIT build of itself, compares the two.
var mainStarted = DateTime.Now;
var running = Stopwatch.StartNew();
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
Expect("Platform: service addresses and proxy rules", await ProxyRules());
Expect("Windows: WinHTTP proxy", WinHttpReads());
Expect("Windows: service client", await ServiceClientSends());

// Detection, as the AI tool checks will need it, from AOT-clean code alone.
Detect("Windows: processes, owner and elevation from tokens", ReadProcesses);
Detect("Windows: installed programs, both views and this account's hive", ReadInstalledPrograms);
Detect("Runtime: file version (FileVersionInfo, by path)", ReadFileVersion);

Console.WriteLine(failures == 0 ? "AOT canary: all libraries ran." : $"AOT canary: {failures} failed.");
running.Stop();
Console.WriteLine(Measure(mainStarted, running.Elapsed));
if (failures == 0 && IsNativeAot() && !args.Contains("--no-compare"))
{
    CompareWithJit();
}

return failures == 0 ? 0 : 1;

void Expect(string library, bool passed)
{
    Console.WriteLine($"{library}: {(passed ? "ok" : "FAILED")}");
    if (!passed)
    {
        failures++;
    }
}

// A detection step: ok with a short fact and how long it took, or FAILED with what went wrong, an exception included.
void Detect(string step, Func<(bool Passed, string Fact)> run)
{
    try
    {
        var clock = Stopwatch.StartNew();
        var (passed, fact) = run();
        Console.WriteLine($"{step}: {(passed ? "ok" : "FAILED")} ({fact}; {clock.ElapsedMilliseconds} ms)");
        if (!passed)
        {
            failures++;
        }
    }
    catch (Exception e)
    {
        Console.WriteLine($"{step}: FAILED ({e.GetType().Name}: {e.Message})");
        failures++;
    }
}

static bool ModelRoundTrip()
{
    var lifecycle = ConfigFile.ReadOsLifecycle("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }"""u8);
    var network = ConfigFile.ReadNetwork("""{ "proxyUrl": 8080, "proxyUseDefaultCredentials": "yes", "proxyAutoDetect": false }"""u8);
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
    return lifecycle.ReviewWarningDays == 90 && read.ComputerName == "CANARY" && read.AutoFailCount == 1 && read.AuditTime == DateTimeOffset.UnixEpoch
        && network == new NetworkConfig(ProxyAutoDetect: false);
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
    // An override that meets its schema replaces the shipped file, the proxy settings' included; one that names a
    // member twice does not.
    var shipped = new CanaryConfigFiles(
        """{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }""",
        """{ "proxyUrl": "", "proxyAutoDetect": true }""");
    var system = new ProcessAccount(@"NT AUTHORITY\SYSTEM", IsAdministrator: true, IsLocalSystem: true);
    using var valid = new CanaryStore(
        """{ "lastReviewed": "2026-01-01", "reviewWarningDays": 30, "upcomingEndWarningDays": 60 }""",
        """{ "proxyUrl": "http://proxy.contoso.com:8080", "proxyAutoDetect": false }""");
    using var twice = new CanaryStore(
        """{ "lastReviewed": "2026-01-01", "reviewWarningDays": 30, "upcomingEndWarningDays": 60, "lastReviewed": "2020-01-01" }""",
        """{ "proxyUrl": "http://proxy.contoso.com:8080", "ProxyUrl": "http://other.contoso.com:8080" }""");
    var loaded = new ConfigTrustGate(shipped, valid, system);
    var refused = new ConfigTrustGate(shipped, twice, system);
    var loadedConfig = new AuditConfig(loaded);
    var refusedConfig = new AuditConfig(refused);
    return loadedConfig.OsLifecycle.LastReviewed == "2026-01-01" && loadedConfig.Network is { ProxyUrl: "http://proxy.contoso.com:8080", ProxyAutoDetect: false, Problems: [] }
        && loaded.Overrides.Count == 2
        && refusedConfig.OsLifecycle.LastReviewed == "2026-09-16" && refusedConfig.Network is { ProxyUrl: "", ProxyAutoDetect: true, Problems: [] }
        && refused.Notices.Count == 2;
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

static async Task<bool> ProxyRules()
{
    var chooser = new ProxyChooser(new ProxySettings(), new CanaryProxy(), isSystem: true);
    var route = await chooser.ChooseAsync(new Uri("https://baseline.engramic.ai/v1"), TimeSpan.FromSeconds(5));
    var local = await chooser.ChooseAsync(new Uri("http://localhost:8787/v1"), TimeSpan.FromSeconds(5));
    return ServiceUri.TryResolve("https://baseline.engramic.ai", "v1/firmware/dell/0CF1", out var uri, out _)
        && uri.AbsolutePath == "/v1/firmware/dell/0CF1"
        && !ServiceUri.TryResolve("http://baseline.engramic.ai", "v1", out _, out _)
        && route is { Source: ProxySource.WinHttp, UseDefaultCredentials: false, Proxy.Port: 8080 }
        && local is { Source: ProxySource.Local, IsDirect: true };
}

static bool WinHttpReads()
{
    // Read only: the machine's setting, whatever it is, is never changed.
    var machine = new WinHttpProxy().ReadMachineProxy();
    return machine is null || machine.Proxy.Length > 0;
}

static async Task<bool> ServiceClientSends()
{
    // A site on the loopback address that answers one request: the handler, HttpClient and the route, compiled ahead of time.
    using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
    listener.Start();
    var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
    var serving = Task.Run(async () =>
    {
        using var connection = await listener.AcceptTcpClientAsync();
        var stream = connection.GetStream();
        var head = new byte[4096];
        var read = 0;
        while (!System.Text.Encoding.ASCII.GetString(head, 0, read).Contains("\r\n\r\n", StringComparison.Ordinal) && read < head.Length)
        {
            var n = await stream.ReadAsync(head.AsMemory(read));
            if (n == 0)
            {
                break;
            }

            read += n;
        }

        await stream.WriteAsync("HTTP/1.1 200 OK\r\nETag: \"canary\"\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"u8.ToArray());
    });
    var client = new ServiceClient(new ServiceClientOptions { Proxy = new ProxySettings(), IsSystem = false, SystemProxy = new CanaryProxy() });
    var refused = await client.GetAsync(new ServiceRequest(new Uri("http://baseline.engramic.ai/v1")));
    var response = await client.GetAsync(new ServiceRequest(new UriBuilder("http", "127.0.0.1", port, "v1").Uri) { Timeout = TimeSpan.FromSeconds(10) });
    await serving.WaitAsync(TimeSpan.FromSeconds(10));
    return refused is { StatusCode: 0, Route: null }
        && response is { StatusCode: 200, ETag: "\"canary\"", Route.Source: ProxySource.Local }
        && response.Body.Span.SequenceEqual("ok"u8);
}

static (bool, string) ReadProcesses()
{
    // Every process, with its owner and elevation from its token: this one must be found as itself.
    var processes = new WindowsProcessList().Read();
    using var identity = WindowsIdentity.GetCurrent();
    var self = processes.SingleOrDefault(p => p.Id == (uint)Environment.ProcessId);
    var passed = self is { IsElevated: not null, CommandLine: not null }
        && self.Owner?.Value == identity.User?.Value
        && string.Equals(self.ImagePath, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase);
    return (passed, $"{processes.Count} processes; {processes.Count(p => p.Owner is not null)} owners, {processes.Count(p => p.IsElevated == true)} elevated, "
        + $"{processes.Count(p => p.ImagePath is not null)} paths and {processes.Count(p => p.CommandLine is not null)} command lines read");
}

static (bool, string) ReadInstalledPrograms()
{
    // As the PowerShell tool's Get-CEInstalledSoftware lists them: the uninstall keys of both registry views of
    // HKLM and of one user's hive, counting entries with a display name that are not system components. That hive
    // is HKCU, this account's own under HKEY_USERS; as SYSTEM the module reads the console user's hive instead,
    // which the canary does not look up. No other loaded hive is read, as the module reads none.
    const string Uninstall = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    var registry = new WindowsRegistry();
    int Count(RegistryHive hive, RegistryView view, string key)
    {
        return (registry.GetSubKeyNames(hive, view, key) ?? []).Count(name =>
            registry.GetValue(hive, view, key + "\\" + name, "DisplayName") is { Text.Length: > 0 }
            && registry.GetValue(hive, view, key + "\\" + name, "SystemComponent") is not { Number: 1 });
    }

    var native = Count(RegistryHive.LocalMachine, RegistryView.Registry64, Uninstall);
    var wow = Count(RegistryHive.LocalMachine, RegistryView.Registry32, Uninstall);
    using var identity = WindowsIdentity.GetCurrent();
    var own = identity.User?.Value ?? string.Empty;
    var loaded = registry.GetSubKeyNames(RegistryHive.Users, RegistryView.Registry64, string.Empty) ?? [];
    var perUser = own.Length > 0 ? Count(RegistryHive.Users, RegistryView.Registry64, own + "\\" + Uninstall) : 0;

    var passed = registry.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry64, Uninstall) is not null
        && own.Length > 0 && loaded.Contains(own, StringComparer.OrdinalIgnoreCase);
    return (passed, $"{native} 64-bit and {wow} 32-bit for the machine, {perUser} in this account's hive");
}

static (bool, string) ReadFileVersion()
{
    // The libraries have no version reader: product code may not read a file by path, and the PowerShell tool reads
    // no file versions. This shows the runtime's own reader works compiled ahead of time. Windows reports the fixed
    // version of its own files as 6.2 to a process whose manifest does not declare Windows 10, as neither exe here does.
    var info = FileVersionInfo.GetVersionInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"));
    return (info.FileBuildPart > 0 && info.CompanyName == "Microsoft Corporation" && !string.IsNullOrEmpty(info.FileVersion),
        $"cmd.exe fixed {info.FileMajorPart}.{info.FileMinorPart}.{info.FileBuildPart}.{info.FilePrivatePart}, text {info.FileVersion}");
}

static bool IsNativeAot()
{
    // Not RuntimeFeature.IsDynamicCodeSupported: PublishAot sets it false in a JIT build's runtimeconfig.json too.
    using var process = Process.GetCurrentProcess();
    return !process.Modules.Cast<ProcessModule>().Any(m => string.Equals(m.ModuleName, "coreclr.dll", StringComparison.OrdinalIgnoreCase));
}

static string Measure(DateTime mainStarted, TimeSpan run)
{
    // From the process's creation to Main, which is the runtime's start-up, then Main to here; the peak working set;
    // and the size of the files this build ships beside its exe.
    using var process = Process.GetCurrentProcess();
    var startUp = mainStarted - process.StartTime;
    var folder = AppContext.BaseDirectory;
    var shipped = Directory.EnumerateFiles(folder).Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)).ToList();
    var mode = IsNativeAot() ? "Native AOT" : "JIT";
    return string.Create(CultureInfo.InvariantCulture,
        $"Measure: mode={mode}; start-up ms={startUp.TotalMilliseconds:F1}; run ms={run.TotalMilliseconds:F0}; peak working set MB={process.PeakWorkingSet64 / 1048576.0:F1}; "
        + $"exe MB={new FileInfo(Environment.ProcessPath!).Length / 1048576.0:F2}; files={shipped.Count}; files MB={shipped.Sum(f => new FileInfo(f).Length) / 1048576.0:F2}");
}

static void CompareWithJit()
{
    // CI builds the solution before it publishes this canary, so a JIT build of it sits in the build output. Both
    // run five times on the same machine, each with --no-compare, and the medians are printed.
    var jit = Path.GetFullPath(Path.Combine("artifacts", "bin", "AotCanary", "release", "AotCanary.exe"));
    if (!File.Exists(jit))
    {
        Console.WriteLine($"Compare: skipped, no JIT build at {jit}");
        return;
    }

    foreach (var (name, exe) in new[] { ("Native AOT", Environment.ProcessPath!), ("JIT", jit) })
    {
        var runs = Enumerable.Range(0, 5).Select(_ => RunOnce(exe)).ToList();
        if (runs.Any(r => r is null))
        {
            Console.WriteLine($"Compare: {name} run failed");
            continue;
        }

        double Median(Func<(double Wall, Dictionary<string, double> Values), double> pick)
        {
            var sorted = runs.Select(r => pick(r!.Value)).Order().ToList();
            return sorted[sorted.Count / 2];
        }

        Console.WriteLine(string.Create(CultureInfo.InvariantCulture,
            $"Compare: {name}, median of 5: wall ms={Median(r => r.Wall):F0}; start-up ms={Median(r => r.Values["start-up ms"]):F1}; run ms={Median(r => r.Values["run ms"]):F0}; "
            + $"peak working set MB={Median(r => r.Values["peak working set MB"]):F1}; files MB={runs[0]!.Value.Values["files MB"]:F2}"));
    }

    static (double Wall, Dictionary<string, double> Values)? RunOnce(string exe)
    {
        var start = new ProcessStartInfo(exe, "--no-compare") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
        var clock = Stopwatch.StartNew();
        using var child = Process.Start(start)!;
        var output = child.StandardOutput.ReadToEnd();
        child.WaitForExit();
        clock.Stop();
        var line = output.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.StartsWith("Measure: ", StringComparison.Ordinal));
        if (child.ExitCode != 0 || line is null)
        {
            Console.WriteLine(output);
            return null;
        }

        var values = new Dictionary<string, double>();
        foreach (var part in line["Measure: ".Length..].Split("; "))
        {
            var pair = part.Split('=');
            if (pair.Length == 2 && double.TryParse(pair[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var value))
            {
                values[pair[0]] = value;
            }
        }

        return (clock.Elapsed.TotalMilliseconds, values);
    }
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

/// <summary>What the canary says Windows says about proxies: a machine WinHTTP proxy, and no PAC file.</summary>
internal sealed class CanaryProxy : ISystemProxy
{
    public MachineProxy? ReadMachineProxy() => new("proxy.contoso.com:8080", "<local>");

    public Task<AutoProxyAnswer> FindAutoProxyAsync(Uri target, Uri? scriptUrl, TimeSpan timeout) => Task.FromResult(AutoProxyAnswer.NotFound("None."));
}

/// <summary>The shipped os-lifecycle.json and network.json, and no other file.</summary>
internal sealed class CanaryConfigFiles(string lifecycle, string network) : IConfigFiles
{
    public byte[]? Read(string name) => CanaryFiles.Read(name, lifecycle, network);
}

/// <summary>A data folder in memory whose config folder holds an os-lifecycle.json and a network.json.</summary>
internal sealed class CanaryStore(string lifecycle, string network) : ISecureStore
{
    public string RootPath => @"C:\ProgramData\EngramicBaseline";

    public IReadOnlyList<string> Notices => [];

    public byte[]? ReadFile(DataFolder folder, string name, int maxLength)
    {
        return folder == DataFolder.Config ? CanaryFiles.Read(name, lifecycle, network) : null;
    }

    public void WriteFile(string name, ReadOnlySpan<byte> content) => throw new NotSupportedException();

    public void WriteFile(DataFolder folder, string name, ReadOnlySpan<byte> content) => throw new NotSupportedException();

    public IScratchFolder CreateScratchFolder() => throw new NotSupportedException();

    public IReadOnlyList<string> DeleteTree(DataFolder folder, string name) => throw new NotSupportedException();

    public void Dispose()
    {
    }
}

/// <summary>The canary's config files, by name.</summary>
internal static class CanaryFiles
{
    public static byte[]? Read(string name, string lifecycle, string network) => name switch
    {
        ConfigFile.OsLifecycleName => System.Text.Encoding.UTF8.GetBytes(lifecycle),
        ConfigFile.NetworkName => System.Text.Encoding.UTF8.GetBytes(network),
        _ => null,
    };
}
