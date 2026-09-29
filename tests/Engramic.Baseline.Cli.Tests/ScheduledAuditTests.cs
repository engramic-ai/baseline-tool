using System.Security.Principal;
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
/// own: its refusals, its exit codes, and the status.json it writes.
/// </summary>
public sealed class ScheduledAuditTests
{
    private static readonly ProcessAccount LocalSystem = new(@"NT AUTHORITY\SYSTEM", IsAdministrator: true, IsLocalSystem: true);
    private static readonly DateTimeOffset AuditTime = new(2026, 9, 29, 14, 3, 49, TimeSpan.Zero);

    private readonly StringWriter _output = new();
    private readonly StringWriter _error = new();
    private readonly FakeSecureStore _store = new();
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
        var settings = Settings() with { OpenStore = () => SecureStore.Open(new SecureStoreOptions { ProgramDataPath = programData, Registry = seal }) };

        var code = ScheduledAudit.Run(settings, _output, _error);

        Assert.Equal(ScheduledAudit.Succeeded, code);
        var statusPath = Path.Combine(dataFolder, StatusFile.FileName);
        var status = StatusFile.Parse(File.ReadAllBytes(statusPath));
        Assert.Equal(AuditTime, status.AuditTime);
        Assert.Equal("S-1-5-32-544", new FileInfo(statusPath).GetAccessControl().GetOwner(typeof(SecurityIdentifier))!.Value);
        Assert.Equal([StatusFile.FileName], Directory.GetFileSystemEntries(dataFolder).Select(Path.GetFileName));
    }

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
