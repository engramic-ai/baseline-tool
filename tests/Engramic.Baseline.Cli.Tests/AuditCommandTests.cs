using System.Text;
using Engramic.Baseline.Controls;
using Engramic.Baseline.Engine;
using Engramic.Baseline.Model;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;
using Engramic.Baseline.Testing.Windows;
using Engramic.Baseline.Windows;
using Microsoft.Extensions.Time.Testing;

namespace Engramic.Baseline.Cli.Tests;

/// <summary>
/// baseline audit, run through its command line with a data folder in memory, or, elevated, a locked one of the
/// tests' own read through SecureStore's read-only way in: it reads administrators' config overrides only when
/// elevated and not given --shipped-config, says what it used and what it refused on the console as the scheduled
/// audit does, and changes nothing: no file and no event.
/// </summary>
public sealed class AuditCommandTests
{
    private static readonly ProcessAccount Administrator = new(@"CONTOSO\admin", IsAdministrator: true, IsLocalSystem: false);
    private static readonly ProcessAccount StandardUser = new(@"CONTOSO\alex", IsAdministrator: false, IsLocalSystem: false);
    private static readonly DateTimeOffset AuditTime = new(2026, 9, 29, 14, 3, 49, TimeSpan.Zero);

    /// <summary>
    /// An administrator's os-lifecycle.json in which Windows 11 24H2, the device's release, is out of support, so
    /// SU-01 fails with it; with the shipped file it warns, as support ends in 14 days.
    /// </summary>
    private const string EndedLifecycle = """
        {
          "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60,
          "windows11": [ { "build": 26100, "version": "24H2", "homePro": "2025-10-14", "enterprise": "2026-10-13" } ]
        }
        """;

    private const string OverridePath = @"C:\ProgramData\EngramicBaseline\config\os-lifecycle.json";

    private readonly StringWriter _output = new();
    private readonly StringWriter _error = new();
    private readonly MemoryStream _standardOutput = new();
    private readonly FakeSecureStore _store = new();
    private readonly List<string> _planted = [];
    private int _opens;

    [Fact]
    public async Task Reads_an_administrator_s_override_when_elevated_and_names_it_beside_the_summary()
    {
        PlantOverride(EndedLifecycle);

        var code = await RunAsync(Settings(Administrator), "--id", "SU-01");

        Assert.Equal(0, code);
        Assert.Equal(string.Empty, _error.ToString());
        Assert.Equal("Config override used: " + OverridePath, Lines(_output)[0]);
        Assert.Contains(Lines(_output), l => l.StartsWith("  SU-01    Fail ", StringComparison.Ordinal));
        Assert.Equal(1, _opens);
        Assert.True(_store.IsDisposed);
        AssertNothingWritten();
    }

    [Fact]
    public async Task Keeps_standard_output_to_the_file_alone_with_json_and_names_the_override_on_standard_error()
    {
        PlantOverride(EndedLifecycle);

        var code = await RunAsync(Settings(Administrator), "--id", "SU-01", "--json", "status");

        Assert.Equal(0, code);
        var bytes = _standardOutput.ToArray();
        Assert.Equal([0xEF, 0xBB, 0xBF], bytes[..3]);
        Assert.Equal(StatusFile.ToBytes(StatusFile.Parse(bytes)), bytes);
        Assert.Equal(FindingStatus.Fail, StatusFile.Parse(bytes).Checks["SU-01"].Status);
        Assert.Equal(["Config override used: " + OverridePath], Lines(_error));
        Assert.Equal(string.Empty, _output.ToString());
        Assert.Equal([(DataFolder.Config, ConfigFile.OsLifecycleName, ConfigTrustGate.MaxOverrideLength)], _store.Reads);
        AssertNothingWritten();
    }

    [Fact]
    public async Task Reads_no_override_when_not_elevated()
    {
        PlantOverride(EndedLifecycle);

        var code = await RunAsync(Settings(StandardUser), "--id", "SU-01", "--json", "status");

        Assert.Equal(0, code);
        Assert.Equal(FindingStatus.Warn, SU01());
        Assert.Equal(string.Empty, _error.ToString());
        Assert.Equal(0, _opens);
    }

    [Fact]
    public async Task Reads_no_override_when_told_to_use_the_shipped_config()
    {
        PlantOverride(EndedLifecycle);

        var code = await RunAsync(Settings(Administrator), "--id", "SU-01", "--json", "status", "--shipped-config");

        Assert.Equal(0, code);
        Assert.Equal(FindingStatus.Warn, SU01());
        Assert.Equal(string.Empty, _error.ToString());
        Assert.Equal(0, _opens);
    }

    [Fact]
    public async Task Reads_overrides_as_SYSTEM()
    {
        PlantOverride(EndedLifecycle);
        var system = new ProcessAccount(@"NT AUTHORITY\SYSTEM", IsAdministrator: true, IsLocalSystem: true);

        await RunAsync(Settings(system), "--id", "SU-01", "--json", "status");

        Assert.Equal(FindingStatus.Fail, SU01());
        Assert.Equal(1, _opens);
    }

    [Fact]
    public async Task Warns_of_an_override_the_data_folder_refuses_on_standard_error_and_judges_by_the_shipped_file()
    {
        const string Reason = OverridePath + " is owned by S-1-5-21-1004336348-1177238915-682003330-1001, not SYSTEM, Administrators or TrustedInstaller.";
        _store.FailRead(DataFolder.Config, ConfigFile.OsLifecycleName, new SecureStoreException(Reason));

        var code = await RunAsync(Settings(Administrator), "--id", "SU-01");

        Assert.Equal(0, code);
        Assert.Equal(["Warning: Ignoring the config override os-lifecycle.json and using the shipped copy: " + Reason], Lines(_error));
        Assert.Contains(Lines(_output), l => l.StartsWith("  SU-01    Warn ", StringComparison.Ordinal));
        Assert.DoesNotContain("Config override used", _output.ToString(), StringComparison.Ordinal);
        AssertNothingWritten();
    }

    [Fact]
    public async Task Warns_of_a_config_folder_the_data_folder_refuses_as_the_folder_and_judges_by_the_shipped_file()
    {
        // What the read-only store gives for a config folder that fails the trust rules: refused, left in place, and
        // nothing in it opened, so the warning names no override, which may not be there.
        const string Reason = @"C:\ProgramData\EngramicBaseline\config can be changed by S-1-5-32-545, not only administrators.";
        _store.FailRead(DataFolder.Config, ConfigFile.OsLifecycleName, new SecureStoreException(Reason) { IsFolderRefused = true });

        var code = await RunAsync(Settings(Administrator), "--id", "SU-01", "--json", "status");

        Assert.Equal(0, code);
        Assert.Equal(FindingStatus.Warn, SU01());
        Assert.Equal(["Warning: Ignoring the config overrides in the config folder and using the shipped config: " + Reason], Lines(_error));
    }

    [Fact]
    public async Task Reports_the_checks_that_need_an_override_it_could_not_read_as_errors_rather_than_use_the_shipped_file()
    {
        const string Reason = "Could not read " + OverridePath + ": The process cannot access the file because another process has locked a portion of the file (Win32 error 33).";
        _store.FailRead(DataFolder.Config, ConfigFile.OsLifecycleName, new SecureStoreException(Reason, isUnavailable: true, null));

        var code = await RunAsync(Settings(Administrator), "--id", "SU-01", "--json", "status");

        Assert.Equal(0, code);
        Assert.Equal(FindingStatus.Error, SU01());
        Assert.Equal(
            ["Warning: Could not read the config override os-lifecycle.json, so the checks that read it report an error and the shipped copy is not used in its place: " + Reason],
            Lines(_error));
    }

    [Fact]
    public async Task Warns_of_a_data_folder_it_refuses_and_judges_by_the_shipped_config()
    {
        const string Reason = @"C:\ProgramData\EngramicBaseline was not created locked by an install of this tool (its DataRootSealed marker is missing), so a standard user may once have been able to change it, and a handle they opened then would keep that access.";
        var settings = Settings(Administrator) with
        {
            OpenDataFolder = () =>
            {
                _opens++;
                throw new SecureStoreException(Reason);
            },
        };

        var code = await RunAsync(settings, "--id", "SU-01", "--json", "status");

        Assert.Equal(0, code);
        Assert.Equal(FindingStatus.Warn, SU01());
        Assert.Equal(["Warning: Ignoring the config overrides in the data folder and using the shipped config: " + Reason], Lines(_error));
        Assert.Equal(1, _opens);
    }

    [Fact]
    public async Task Takes_a_missing_data_folder_as_no_overrides_and_says_nothing_of_it()
    {
        var settings = Settings(Administrator) with
        {
            OpenDataFolder = () =>
            {
                _opens++;
                return null;
            },
        };

        var code = await RunAsync(settings, "--id", "SU-01", "--json", "status");

        Assert.Equal(0, code);
        Assert.Equal(FindingStatus.Warn, SU01());
        Assert.Equal(string.Empty, _error.ToString());
        Assert.Equal(1, _opens);
    }

    [Fact]
    public async Task Refuses_a_check_it_does_not_have_before_opening_the_data_folder()
    {
        var code = await RunAsync(Settings(Administrator), "--id", "ZZ-99");

        Assert.Equal(1, code);
        Assert.StartsWith("Not a check this version has: ZZ-99.", _error.ToString(), StringComparison.Ordinal);
        Assert.Equal(0, _opens);
    }

    [Fact]
    public void Documents_the_switch_that_ignores_overrides_in_its_help()
    {
        var command = AuditCommand.Create();

        var option = Assert.Single(command.Options, o => o.Name == "--shipped-config");
        Assert.Equal(
            "Use only the config that ships with the tool, and ignore administrators' config overrides in the data folder, which an elevated audit otherwise reads.",
            option.Description);
        Assert.Contains("Elevated, it reads administrators' config overrides from the data folder", command.Description, StringComparison.Ordinal);
        Assert.DoesNotContain(command.Options, o => o.Name.StartsWith("--data", StringComparison.Ordinal) || o.Name.StartsWith("--output", StringComparison.Ordinal));
    }

    [Fact]
    public void Takes_its_settings_from_this_device_and_opens_the_data_folder_only_through_the_read_only_way_in()
    {
        var settings = AuditSettings.ForThisDevice();

        Assert.Equal(Environment.MachineName, settings.ComputerName);
        Assert.Equal(CurrentProcess.ReadAccount(), settings.Account);
        Assert.Same(TimeProvider.System, settings.Time);
        Assert.IsType<WindowsRegistry>(settings.Registry);
        Assert.Equal(ToolVersion.Current, settings.ToolVersion);
        Assert.Contains(settings.Catalog.Checks, c => c.Info.Id == "SU-01");

        // Not called, since it would open this machine's data folder: what it is declared to give is enough. Only
        // SecureStore.OpenReadOnly gives a ReadOnlySecureStore, which can only read, so SecureStore.Open, which would
        // move an untrusted config folder aside with event 1003, cannot be put in its place unseen.
        Assert.Equal(typeof(ReadOnlySecureStore), settings.OpenDataFolder.Method.ReturnType);
    }

    [Fact]
    public async Task Reads_an_administrator_s_override_from_a_locked_config_folder_through_the_read_only_store_and_changes_nothing()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);
        using var tree = new TempTree();
        var programData = tree.Folder("ProgramData", Descriptors.ProgramDataLike);
        tree.Folder(@"ProgramData\EngramicBaseline", Descriptors.InstallerLocked);
        tree.Folder(@"ProgramData\EngramicBaseline\config", Descriptors.InstallerLockedUsersRead);
        var used = tree.File(@"ProgramData\EngramicBaseline\config\os-lifecycle.json", EndedLifecycle, "O:BA");
        var events = new FakeEventLog();
        var before = TreeSnapshot.Of(programData);

        var code = await RunAsync(RealStore(programData, events), "--id", "SU-01", "--json", "status");

        Assert.Equal(0, code);
        Assert.Equal(["Config override used: " + used], Lines(_error));
        Assert.Equal(FindingStatus.Fail, SU01());
        Assert.Equal(before, TreeSnapshot.Of(programData));
        Assert.Empty(events.Entries);
    }

    [Fact]
    public async Task Warns_of_an_untrusted_config_folder_and_leaves_it_in_place_with_no_event()
    {
        // The scheduled audit would move this folder aside, with event 1003; the audit promises to change nothing.
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);
        using var tree = new TempTree();
        var programData = tree.Folder("ProgramData", Descriptors.ProgramDataLike);
        tree.Folder(@"ProgramData\EngramicBaseline", Descriptors.InstallerLocked);
        var config = tree.Folder(@"ProgramData\EngramicBaseline\config", Descriptors.InstallerLockedUsersRead + "(A;OICI;0x1301bf;;;BU)");
        tree.File(@"ProgramData\EngramicBaseline\config\os-lifecycle.json", EndedLifecycle, "O:BA");
        var events = new FakeEventLog();
        var before = TreeSnapshot.Of(programData);

        var code = await RunAsync(RealStore(programData, events), "--id", "SU-01", "--json", "status");

        Assert.Equal(0, code);
        Assert.Equal(["Warning: Ignoring the config overrides in the config folder and using the shipped config: " + config + " can be changed by S-1-5-32-545, not only administrators."], Lines(_error));
        Assert.Equal(FindingStatus.Warn, SU01());
        Assert.Equal(before, TreeSnapshot.Of(programData));
        Assert.Empty(events.Entries);
    }

    [Fact]
    public async Task Warns_of_a_data_folder_that_was_never_sealed_and_changes_nothing()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);
        using var tree = new TempTree();
        var programData = tree.Folder("ProgramData", Descriptors.ProgramDataLike);
        tree.Folder(@"ProgramData\EngramicBaseline", Descriptors.InstallerLocked);
        tree.Folder(@"ProgramData\EngramicBaseline\config", Descriptors.InstallerLockedUsersRead);
        tree.File(@"ProgramData\EngramicBaseline\config\os-lifecycle.json", EndedLifecycle, "O:BA");
        var events = new FakeEventLog();
        var before = TreeSnapshot.Of(programData);

        var code = await RunAsync(RealStore(programData, events, new FakeRegistry()), "--id", "SU-01", "--json", "status");

        Assert.Equal(0, code);
        var warning = Assert.Single(Lines(_error));
        Assert.StartsWith("Warning: Ignoring the config overrides in the data folder and using the shipped config: ", warning, StringComparison.Ordinal);
        Assert.Contains("its DataRootSealed marker is missing", warning, StringComparison.Ordinal);
        Assert.Equal(FindingStatus.Warn, SU01());
        Assert.Equal(before, TreeSnapshot.Of(programData));
        Assert.Empty(events.Entries);
    }

    private static string[] Lines(StringWriter writer)
    {
        var text = writer.ToString().ReplaceLineEndings("\n").TrimEnd();
        return text.Length == 0 ? [] : text.Split('\n');
    }

    /// <summary>A Windows 11 24H2 Pro device, as its registry says.</summary>
    private static FakeRegistry Windows11()
    {
        return new FakeRegistry()
            .Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "CurrentBuildNumber", RegistryValue.FromText("26100"))
            .Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "UBR", RegistryValue.FromDWord(6584))
            .Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "DisplayVersion", RegistryValue.FromText("24H2"))
            .Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "EditionID", RegistryValue.FromText("Professional"))
            .Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "ProductName", RegistryValue.FromText("Windows 10 Pro"))
            .Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "InstallationType", RegistryValue.FromText("Client"));
    }

    private async Task<int> RunAsync(AuditSettings settings, params string[] args)
    {
        var command = AuditCommand.Create(() => settings, _output, _error, () => _standardOutput);
        return await command.Parse(args).InvokeAsync(cancellationToken: TestContext.Current.CancellationToken);
    }

    private void PlantOverride(string text)
    {
        _store.WriteFile(DataFolder.Config, ConfigFile.OsLifecycleName, Encoding.UTF8.GetBytes(text));
        _planted.Add(ConfigFile.OsLifecycleName);
    }

    /// <summary>Nothing was written to the data folder in memory beyond the override planted, and nothing was moved aside.</summary>
    private void AssertNothingWritten()
    {
        Assert.Empty(_store.Files);
        Assert.Equal(_planted, _store.FilesIn(DataFolder.Config).Keys);
        Assert.Empty(_store.ScratchFolders);
        Assert.Empty(_store.Notices);
    }

    private FindingStatus SU01() => StatusFile.Parse(_standardOutput.ToArray()).Checks["SU-01"].Status;

    private AuditSettings Settings(ProcessAccount account) => new()
    {
        Account = account,
        Registry = Windows11(),
        Time = new FakeTimeProvider(AuditTime),
        ComputerName = "DEVICE01",
        OpenDataFolder = () =>
        {
            _opens++;
            return _store;
        },
        ToolVersion = "1.0.0-test",
    };

    /// <summary>
    /// The settings with SecureStore's read-only way in to a ProgramData folder of the test's own, with the product's
    /// rules, as this process, which must be elevated.
    /// </summary>
    private AuditSettings RealStore(string programData, FakeEventLog events, FakeRegistry? seal = null) => Settings(CurrentProcess.ReadAccount()) with
    {
        OpenDataFolder = () => SecureStore.OpenReadOnly(new SecureStoreOptions
        {
            ProgramDataPath = programData,
            Registry = seal ?? new FakeRegistry().Set(RegistryHive.LocalMachine, SecureStoreOptions.MachineSealKeyPath, SecureStoreOptions.MachineSealValueName, RegistryValue.FromText("0.3.2")),
            EventLog = events,
        }),
    };
}
