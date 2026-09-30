using System.Security.Principal;
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
/// The scheduled audit, with an account said to be SYSTEM, a data folder in memory and a mutex of the tests'
/// own: its refusals, its exit codes, the config it reads, and the status.json it writes.
/// </summary>
public sealed class ScheduledAuditTests
{
    private static readonly ProcessAccount LocalSystem = new(@"NT AUTHORITY\SYSTEM", IsAdministrator: true, IsLocalSystem: true);
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
    private readonly FakeSecureStore _store = new();
    private readonly FakeEventLog _events = new();
    private readonly string _mutexName = TestMutexes.NewName();
    private int _opens;

    [Fact]
    public void Writes_status_json_through_SecureStore_as_the_module_writes_it()
    {
        var code = ScheduledAudit.Run(Settings(), _output, _error);

        Assert.Equal(ScheduledAudit.Succeeded, code);
        Assert.Equal(string.Empty, _error.ToString());
        var bytes = _store.Files[StatusFile.FileName];
        Assert.Equal(StatusFile.ToBytes(StatusFile.Parse(bytes)), bytes);
        Assert.Equal([0xEF, 0xBB, 0xBF], bytes[..3]);
        var status = StatusFile.Parse(bytes);
        Assert.Equal("DEVICE01", status.ComputerName);
        Assert.Equal(@"NT AUTHORITY\SYSTEM", status.RunAs);
        Assert.True(status.Elevated);
        Assert.Equal(AuditTime, status.AuditTime);
        Assert.Equal("1.0.0-test", status.ToolVersion);
        Assert.Equal(["SU-01"], status.Checks.Keys);
        Assert.Equal(string.Empty, status.ReportFolder);
        Assert.True(_store.IsDisposed);
        Assert.Equal(1, _opens);
    }

    [Fact]
    public void Judges_by_the_shipped_config_when_there_is_no_override()
    {
        ScheduledAudit.Run(Settings(), _output, _error);

        Assert.Equal(FindingStatus.Warn, SU01());
        Assert.Equal([(DataFolder.Config, ConfigFile.OsLifecycleName, ConfigTrustGate.MaxOverrideLength)], _store.Reads);
        Assert.DoesNotContain("Config override", _output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Reads_an_administrator_s_override_through_the_trust_gate_and_names_it()
    {
        _store.WriteFile(DataFolder.Config, ConfigFile.OsLifecycleName, Encoding.UTF8.GetBytes(EndedLifecycle));

        var code = ScheduledAudit.Run(Settings(), _output, _error);

        Assert.Equal(ScheduledAudit.Succeeded, code);
        Assert.Equal(string.Empty, _error.ToString());
        Assert.Equal(FindingStatus.Fail, SU01());
        Assert.Contains("Config override used: " + OverridePath, Lines(_output));
    }

    [Fact]
    public void Warns_of_an_override_the_data_folder_refuses_and_judges_by_the_shipped_file()
    {
        const string Reason = OverridePath + " is owned by S-1-5-21-1004336348-1177238915-682003330-1001, not SYSTEM, Administrators or TrustedInstaller.";
        _store.FailRead(DataFolder.Config, ConfigFile.OsLifecycleName, new SecureStoreException(Reason));

        var code = ScheduledAudit.Run(Settings(), _output, _error);

        Assert.Equal(ScheduledAudit.Succeeded, code);
        Assert.Equal("Warning: Ignoring the config override os-lifecycle.json and using the shipped copy: " + Reason, _error.ToString().TrimEnd());
        Assert.Equal(FindingStatus.Warn, SU01());
        Assert.DoesNotContain("Config override", _output.ToString(), StringComparison.Ordinal);

        // Where an administrator sees it, not only in the task's output.
        Assert.Equal([(1003, EventLogLevel.Warning, "Engramic Baseline - data folder: Ignoring the config override os-lifecycle.json and using the shipped copy: " + Reason)], _events.Entries);
    }

    [Fact]
    public void Reports_the_checks_that_need_an_override_it_could_not_read_as_errors_rather_than_use_the_shipped_file()
    {
        // As a standard user can bring about by holding the file open without sharing, which the config folder lets them.
        const string Reason = "Could not read " + OverridePath + ": Could not open " + OverridePath + " to read it: The process cannot access the file because it is being used by another process (Win32 error 32).";
        _store.FailRead(DataFolder.Config, ConfigFile.OsLifecycleName, new SecureStoreException(Reason, isUnavailable: true, null));

        var code = ScheduledAudit.Run(Settings(), _output, _error);

        Assert.Equal(ScheduledAudit.Succeeded, code);
        var su01 = StatusFile.Parse(_store.Files[StatusFile.FileName]).Checks["SU-01"];
        Assert.Equal(FindingStatus.Error, su01.Status);
        const string Notice = "Could not read the config override os-lifecycle.json, so the checks that read it report an error and the shipped copy is not used in its place: " + Reason;
        Assert.Equal("Warning: " + Notice, _error.ToString().TrimEnd());
        Assert.Equal([(1003, EventLogLevel.Warning, "Engramic Baseline - data folder: " + Notice)], _events.Entries);
    }

    [Fact]
    public void Says_so_when_a_warning_cannot_be_written_to_the_event_log()
    {
        _store.FailRead(DataFolder.Config, ConfigFile.OsLifecycleName, new SecureStoreException(OverridePath + " has 2 names (hard links), not one, so it may also be a file somewhere else."));
        _events.Refuses = true;

        var code = ScheduledAudit.Run(Settings(), _output, _error);

        Assert.Equal(ScheduledAudit.Succeeded, code);
        Assert.Equal(
            [
                $"Warning: Ignoring the config override os-lifecycle.json and using the shipped copy: {OverridePath} has 2 names (hard links), not one, so it may also be a file somewhere else.",
                "Warning: The warning above could not be written to the Application event log as event 1003.",
            ],
            Lines(_error));
    }

    [Fact]
    public void Warns_of_an_override_that_does_not_meet_its_schema_and_judges_by_the_shipped_file()
    {
        _store.WriteFile(DataFolder.Config, ConfigFile.OsLifecycleName, Encoding.UTF8.GetBytes(EndedLifecycle + EndedLifecycle));

        var code = ScheduledAudit.Run(Settings(), _output, _error);

        Assert.Equal(ScheduledAudit.Succeeded, code);
        Assert.StartsWith($"Warning: Ignoring the config override os-lifecycle.json and using the shipped copy: {OverridePath} is not valid JSON: ", _error.ToString(), StringComparison.Ordinal);
        Assert.Equal(FindingStatus.Warn, SU01());
    }

    [Fact]
    public void Says_what_it_did_as_the_module_s_scheduled_audit_does()
    {
        ScheduledAudit.Run(Settings(), _output, _error);

        var lines = _output.ToString().ReplaceLineEndings("\n").TrimEnd().Split('\n');
        Assert.Equal(@"Audit started on DEVICE01 as NT AUTHORITY\SYSTEM (tool 1.0.0-test)", lines[0]);
        Assert.StartsWith("Checks: 1  Auto-fail failing: ", lines[1], StringComparison.Ordinal);
        Assert.StartsWith("Frameworks: ce-v3.3=", lines[2], StringComparison.Ordinal);
        Assert.Equal(@"Status: C:\ProgramData\EngramicBaseline\status.json", lines[3]);
    }

    [Theory]
    [InlineData(@"CONTOSO\admin", true)]
    [InlineData(@"CONTOSO\alex", false)]
    public void Refuses_to_run_as_anyone_but_SYSTEM(string name, bool administrator)
    {
        var settings = Settings() with { Account = new ProcessAccount(name, administrator, IsLocalSystem: false) };

        var code = ScheduledAudit.Run(settings, _output, _error);

        Assert.Equal(ScheduledAudit.Failed, code);
        Assert.Equal(
            $"baseline scheduled-audit runs only as SYSTEM, as the scheduled audit task runs it; this process runs as {name}. To audit this device now, run baseline audit.",
            _error.ToString().TrimEnd());
        Assert.Equal(0, _opens);
        Assert.Empty(_store.Files);
    }

    [Fact]
    public void Runs_the_machine_checks_only()
    {
        var selection = ScheduledAudit.Selection();

        Assert.True(selection.Matches(Info("SU-01", CheckScope.Machine)));
        Assert.False(selection.Matches(Info("AI-01", CheckScope.User)));
    }

    [Fact]
    public void Gives_up_with_exit_code_2_while_another_audit_holds_the_mutex()
    {
        using var release = new ManualResetEventSlim();
        using var taken = new ManualResetEventSlim();
        var holder = new Thread(() =>
        {
            using var mutex = TestMutexes.OpenableByTheTests(_mutexName);
            mutex.WaitOne();
            taken.Set();
            release.Wait();
            mutex.ReleaseMutex();
        });
        holder.Start();
        taken.Wait(TestContext.Current.CancellationToken);

        try
        {
            var code = ScheduledAudit.Run(Settings(), _output, _error);

            Assert.Equal(ScheduledAudit.AlreadyRunning, code);
            Assert.Equal("Another audit is still running; giving up.", _error.ToString().TrimEnd());
            Assert.Equal(0, _opens);
        }
        finally
        {
            release.Set();
            holder.Join();
        }
    }

    [Fact]
    public void Counts_a_mutex_this_account_may_not_open_as_a_failed_run()
    {
        // As a standard user could make it first, to stop audits: only SYSTEM is in its access list.
        Assert.SkipWhen(Elevation.IsSystem, "SYSTEM is in the access list.");
        using var planted = TestMutexes.Create(_mutexName, "D:P(A;;0x1f0001;;;SY)");

        var code = TestMutexes.OnOtherThread(() => ScheduledAudit.Run(Settings(), _output, _error));

        Assert.Equal(ScheduledAudit.Failed, code);
        Assert.StartsWith($"Audit failed: the audit mutex {_mutexName} could not be taken, so another program may be holding its name to stop audits.", _error.ToString(), StringComparison.Ordinal);
        Assert.Equal(0, _opens);
    }

    [Fact]
    public void Counts_a_mutex_name_something_else_has_as_a_failed_run()
    {
        using var planted = new EventWaitHandle(false, EventResetMode.ManualReset, _mutexName);

        var code = ScheduledAudit.Run(Settings(), _output, _error);

        Assert.Equal(ScheduledAudit.Failed, code);
        Assert.StartsWith($"Audit failed: the audit mutex {_mutexName} could not be taken", _error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Fails_and_writes_nothing_when_SecureStore_refuses_the_data_folder()
    {
        const string Reason = @"C:\ProgramData\EngramicBaseline is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.";
        var settings = Settings() with { OpenStore = () => throw new SecureStoreException(Reason) };

        var code = ScheduledAudit.Run(settings, _output, _error);

        Assert.Equal(ScheduledAudit.Failed, code);
        Assert.Equal("Audit failed: " + Reason, _error.ToString().TrimEnd());
        Assert.DoesNotContain("Audit started", _output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Fails_rather_than_stopping_when_opening_the_data_folder_throws_anything_else()
    {
        var settings = Settings() with { OpenStore = () => throw new IOException("The device is not ready.") };

        var code = ScheduledAudit.Run(settings, _output, _error);

        Assert.Equal(ScheduledAudit.Failed, code);
        Assert.Equal("Audit failed: The device is not ready.", _error.ToString().TrimEnd());
    }

    [Fact]
    public void Fails_when_status_json_cannot_be_written()
    {
        _store.WriteError = new SecureStoreException(@"C:\ProgramData\EngramicBaseline\status.json is read-only, so it cannot be replaced.");

        var code = ScheduledAudit.Run(Settings(), _output, _error);

        Assert.Equal(ScheduledAudit.Failed, code);
        Assert.Equal(@"Audit failed: C:\ProgramData\EngramicBaseline\status.json is read-only, so it cannot be replaced.", _error.ToString().TrimEnd());
        Assert.DoesNotContain("Status:", _output.ToString(), StringComparison.Ordinal);
        Assert.True(_store.IsDisposed);
    }

    [Fact]
    public void Holds_the_mutex_while_it_writes_and_releases_it_after()
    {
        using var mutex = TestMutexes.OpenableByTheTests(_mutexName);
        bool? freeWhileWriting = null;
        _store.OnWrite = _ => freeWhileWriting = TestMutexes.IsFree(mutex);

        var code = ScheduledAudit.Run(Settings(), _output, _error);

        Assert.Equal(ScheduledAudit.Succeeded, code);
        Assert.False(freeWhileWriting);
        Assert.True(TestMutexes.IsFree(mutex));
    }

    [Fact]
    public void Takes_its_settings_from_this_device()
    {
        var settings = ScheduledAuditSettings.ForThisDevice();

        Assert.Equal(@"Global\EngramicBaselineAudit", settings.MutexName);
        Assert.Equal(TimeSpan.FromMinutes(30), settings.MutexWait);
        Assert.Equal(Environment.MachineName, settings.ComputerName);
        Assert.Equal(WindowsIdentity.GetCurrent().Name, settings.Account.Name);
        Assert.Same(TimeProvider.System, settings.Time);
        Assert.Equal(ToolVersion.Current, settings.ToolVersion);
        Assert.Equal(WindowsEventLog.ProductSource, Assert.IsType<WindowsEventLog>(settings.EventLog).Source);
        Assert.Contains(settings.Catalog.Checks, c => c.Info.Id == "SU-01");
    }

    [Fact]
    public void The_command_is_scheduled_audit()
    {
        var command = ScheduledAuditCommand.Create();

        Assert.Equal("scheduled-audit", command.Name);
        Assert.DoesNotContain(command.Options, o => o.Name.StartsWith("--data", StringComparison.Ordinal));
    }

    [Fact]
    public void Writes_status_json_into_a_locked_data_folder_through_the_real_SecureStore()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);
        using var tree = new TempTree();
        var programData = tree.Folder("ProgramData", Descriptors.ProgramDataLike);
        var dataFolder = tree.Folder(@"ProgramData\EngramicBaseline", Descriptors.InstallerLocked);
        var seal = new FakeRegistry().Set(RegistryHive.LocalMachine, SecureStoreOptions.MachineSealKeyPath, SecureStoreOptions.MachineSealValueName, RegistryValue.FromText("0.3.2"));
        var settings = Settings() with { OpenStore = () => SecureStore.Open(new SecureStoreOptions { ProgramDataPath = programData, Registry = seal, EventLog = new FakeEventLog() }) };

        var code = ScheduledAudit.Run(settings, _output, _error);

        Assert.Equal(ScheduledAudit.Succeeded, code);
        var statusPath = Path.Combine(dataFolder, StatusFile.FileName);
        var status = StatusFile.Parse(File.ReadAllBytes(statusPath));
        Assert.Equal(AuditTime, status.AuditTime);
        Assert.Equal("S-1-5-32-544", new FileInfo(statusPath).GetAccessControl().GetOwner(typeof(SecurityIdentifier))!.Value);
        Assert.Equal([StatusFile.FileName], Directory.GetFileSystemEntries(dataFolder).Select(Path.GetFileName));
    }

    [Fact]
    public void Reads_an_administrator_s_override_from_the_locked_config_folder_through_the_real_SecureStore()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);
        using var tree = new TempTree();
        var programData = tree.Folder("ProgramData", Descriptors.ProgramDataLike);
        var dataFolder = tree.Folder(@"ProgramData\EngramicBaseline", Descriptors.InstallerLocked);
        tree.Folder(@"ProgramData\EngramicBaseline\config", Descriptors.InstallerLockedUsersRead);
        var used = tree.File(@"ProgramData\EngramicBaseline\config\os-lifecycle.json", EndedLifecycle, "O:BA");
        var seal = new FakeRegistry().Set(RegistryHive.LocalMachine, SecureStoreOptions.MachineSealKeyPath, SecureStoreOptions.MachineSealValueName, RegistryValue.FromText("0.3.2"));
        var settings = Settings() with { OpenStore = () => SecureStore.Open(new SecureStoreOptions { ProgramDataPath = programData, Registry = seal, EventLog = new FakeEventLog() }) };

        var code = ScheduledAudit.Run(settings, _output, _error);

        Assert.Equal(ScheduledAudit.Succeeded, code);
        Assert.Equal(string.Empty, _error.ToString());
        Assert.Contains("Config override used: " + used, Lines(_output));
        Assert.Equal(FindingStatus.Fail, StatusFile.Parse(File.ReadAllBytes(Path.Combine(dataFolder, StatusFile.FileName))).Checks["SU-01"].Status);
    }

    private static string[] Lines(StringWriter writer) => writer.ToString().ReplaceLineEndings("\n").TrimEnd().Split('\n');

    private FindingStatus SU01() => StatusFile.Parse(_store.Files[StatusFile.FileName]).Checks["SU-01"].Status;

    private static CheckInfo Info(string id, CheckScope scope)
    {
        return new CheckInfo(id, "Title of " + id, CheckCategory.SecurityUpdateManagement, Severity.High, [FrameworkTags.CeV33], "Reference of " + id, scope);
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

    private ScheduledAuditSettings Settings() => new()
    {
        Account = LocalSystem,
        Registry = Windows11(),
        Time = new FakeTimeProvider(AuditTime),
        ComputerName = "DEVICE01",
        EventLog = _events,
        OpenStore = () =>
        {
            _opens++;
            return _store;
        },
        ToolVersion = "1.0.0-test",
        MutexName = _mutexName,
        MutexWait = TimeSpan.FromMilliseconds(200),
    };
}
