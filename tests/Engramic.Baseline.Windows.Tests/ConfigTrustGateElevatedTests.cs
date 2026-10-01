using Engramic.Baseline.Controls;
using Engramic.Baseline.Engine;
using Engramic.Baseline.Model;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;
using Engramic.Baseline.Testing.Windows;
using Microsoft.Extensions.Time.Testing;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// The config trust gate with the product's rules, as the scheduled audit runs it: SecureStore opens a data folder
/// made as the installer makes it (owned by Administrators, locked from birth, config readable by Users), and the
/// gate reads an administrator's override from it as this process, which must be elevated. Overrides that a
/// standard user owns or can change, or that are linked or hard-linked, are refused and the shipped file used;
/// one owned by Administrators loads. The same holds through SecureStore's read-only way in, as an elevated
/// baseline.exe audit reads, except that an untrusted config folder is refused and left in place rather than moved
/// aside. Only an elevated administrator or SYSTEM can make those folders, so these skip without elevation; the
/// Security job in CI runs them as the elevated administrator and as SYSTEM.
/// </summary>
[Trait("Suite", "Security")]
public sealed class ConfigTrustGateElevatedTests : IDisposable
{
    private const string Name = ConfigFile.OsLifecycleName;

    /// <summary>A valid os-lifecycle.json that differs from the shipped one.</summary>
    private const string OverrideText = """{ "lastReviewed": "2026-01-01", "reviewWarningDays": 30, "upcomingEndWarningDays": 60 }""";

    /// <summary>The access list of the config folder as the installer makes it.</summary>
    private const string ConfigAccess = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

    /// <summary>A file owned by Administrators that only SYSTEM and Administrators may change, elsewhere than the config folder.</summary>
    private const string LockedFile = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";

    private readonly TempTree _tree = new();
    private readonly FakeEventLog _events = new();
    private string _programData = string.Empty;

    private string Config => Path.Combine(_programData, SecureStore.DataFolderName, "config");

    private string Override => Path.Combine(Config, Name);

    private static string ShippedLastReviewed => ConfigFile.ReadOsLifecycle(ShippedConfig.Files.Read(Name)).LastReviewed;

    public void Dispose() => _tree.Dispose();

    [Fact]
    public void An_override_owned_by_Administrators_that_only_administrators_can_change_loads()
    {
        Arrange();
        _tree.File(Relative(Override), OverrideText, "O:BA");

        var (gate, lifecycle) = ReadAsThisProcess();

        Assert.Equal("S-1-5-32-544", Acls.Owner(Override));
        Assert.Equal("2026-01-01", lifecycle.LastReviewed);
        Assert.Equal([Override], gate.Overrides);
        Assert.Empty(gate.Notices);
    }

    [Fact]
    public void An_override_a_standard_user_owns_is_refused_and_the_shipped_file_used()
    {
        Assert.SkipUnless(Attacker.IsAvailable, Attacker.Unavailable);
        Arrange();

        // The attacker may add a file to the config folder for a moment, as a mistaken grant could let them, and the
        // folder is locked again after: the file keeps the owner who made it.
        Acls.Reset(Config, ConfigAccess + $"(A;;0x100003;;;{Attacker.Sid})");
        Attacker.Run(() => File.WriteAllText(Override, OverrideText));
        Acls.Reset(Config, ConfigAccess);

        var (gate, lifecycle) = ReadAsThisProcess();

        Assert.Equal(Attacker.Sid.Value, Acls.Owner(Override));
        AssertRefused(gate, lifecycle, $"is owned by {Attacker.Sid}, not SYSTEM, Administrators or TrustedInstaller.");
    }

    [Fact]
    public void An_override_owned_by_the_administrator_s_own_account_is_refused()
    {
        // As an administrator copying it in by hand on a Windows client makes it. SYSTEM's own account is trusted.
        Assert.SkipUnless(Elevation.IsElevated && !Elevation.IsSystem, Elevation.NeedsElevation);
        Arrange();
        _tree.File(Relative(Override), OverrideText, $"O:{Elevation.CurrentUser}");

        var (gate, lifecycle) = ReadAsThisProcess();

        AssertRefused(gate, lifecycle, $"is owned by {Elevation.CurrentUser}, not SYSTEM, Administrators or TrustedInstaller.");
    }

    [Fact]
    public void An_override_standard_users_can_change_is_refused_and_the_shipped_file_used()
    {
        Arrange();
        _tree.File(Relative(Override), OverrideText, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;BU)");

        var (gate, lifecycle) = ReadAsThisProcess();

        AssertRefused(gate, lifecycle, "can be changed by S-1-5-32-545, not only administrators.");
    }

    [Fact]
    public void A_symbolic_link_in_the_override_s_place_is_refused_and_not_followed()
    {
        Arrange();
        var outside = _tree.File("outside.json", OverrideText, LockedFile);
        Assert.SkipUnless(Links.TryCreateFileSymbolicLink(Override, outside), "This account may not make a symbolic link.");

        var (gate, lifecycle) = ReadAsThisProcess();

        AssertRefused(gate, lifecycle, "is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.");
    }

    [Fact]
    public void A_junction_in_the_override_s_place_is_refused_and_not_followed()
    {
        Arrange();
        Links.CreateJunction(Override, _tree.Folder("Elsewhere"));

        var (gate, lifecycle) = ReadAsThisProcess();

        AssertRefused(gate, lifecycle, "is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.");
    }

    [Fact]
    public void A_hard_link_to_a_locked_file_elsewhere_is_refused_and_the_shipped_file_used()
    {
        Arrange();
        var outside = _tree.File("outside.json", OverrideText, LockedFile);
        Links.CreateHardLink(Override, outside);

        var (gate, lifecycle) = ReadAsThisProcess();

        AssertRefused(gate, lifecycle, "has 2 names (hard links), not one, so it may also be a file somewhere else.");
    }

    [Fact]
    public void A_config_folder_standard_users_can_change_is_moved_aside_and_the_shipped_file_used()
    {
        Arrange();
        Acls.Reset(Config, ConfigAccess + "(A;OICI;0x1301bf;;;BU)");
        _tree.File(Relative(Override), OverrideText, "O:BA");

        var (gate, lifecycle) = ReadAsThisProcess();

        Assert.Equal(ShippedLastReviewed, lifecycle.LastReviewed);
        Assert.Empty(gate.Overrides);
        Assert.Single(_events.Entries);
        Assert.False(Directory.Exists(Config));
        Assert.Single(Directory.GetDirectories(_programData, SecureStore.DataFolderName + DataFolderLayout.UntrustedMarker + "*"));
    }

    [Theory]
    [MemberData(nameof(Holders.ReadOnlyHolderWays), MemberType = typeof(Holders))]
    public void An_administrator_s_override_a_standard_user_holds_up_is_not_replaced_by_the_shipped_file(string way)
    {
        // The config folder lets Users read what is in it, so the attacker can lock the override or hold an oplock
        // on it to stop the read; what they must not get is the shipped copy judged in its place without a trace.
        Assert.SkipUnless(Attacker.IsAvailable, Attacker.Unavailable);
        Arrange();
        _tree.File(Relative(Override), OverrideText, "O:BA");
        var clock = new FakeTimeProvider();

        using var store = SecureStore.Open(new SecureStoreOptions { ProgramDataPath = _programData, Registry = DataFolderFixture.Sealed(), EventLog = _events, Time = clock });
        var gate = new ConfigTrustGate(ShippedConfig.Files, store, CurrentProcess.ReadAccount());
        using (var holder = Attacker.Run(() => Holders.Hold(way, Override, Config)))
        {
            var e = Assert.Throws<IOException>(() => Waits.AdvanceUntilDone(clock, () => _ = new AuditConfig(gate).OsLifecycle));

            Assert.StartsWith($"The config override {Override} could not be read, so the shipped copy is not used in its place: ", e.Message, StringComparison.Ordinal);
            if (holder is Oplock oplock)
            {
                Assert.True(oplock.BreakRequested);
            }
        }

        Assert.StartsWith($"Could not read the config override {Name}, so the checks that read it report an error", Assert.Single(gate.Notices), StringComparison.Ordinal);
        Assert.Empty(gate.Overrides);
        Assert.Empty(_events.Entries);
    }

    [Theory]
    [MemberData(nameof(Holders.WaysIgnoredFromReadOnlyHolder), MemberType = typeof(Holders))]
    public void An_administrator_s_override_loads_while_a_standard_user_holds_it_or_its_folder_open_without_sharing(string way)
    {
        // Windows ignores a refusal to share reading from a holder who may not write to what they hold, and Users may
        // only read the config folder and what is in it.
        Assert.SkipUnless(Attacker.IsAvailable, Attacker.Unavailable);
        Arrange();
        _tree.File(Relative(Override), OverrideText, "O:BA");
        var clock = new FakeTimeProvider();

        using var store = SecureStore.Open(new SecureStoreOptions { ProgramDataPath = _programData, Registry = DataFolderFixture.Sealed(), EventLog = _events, Time = clock });
        var gate = new ConfigTrustGate(ShippedConfig.Files, store, CurrentProcess.ReadAccount());
        OsLifecycle? lifecycle = null;
        IOException? refused = null;
        using (Attacker.Run(() => Holders.Hold(way, Override, Config)))
        {
            try
            {
                Waits.AdvanceUntilDone(clock, () => lifecycle = new AuditConfig(gate).OsLifecycle);
            }
            catch (IOException e)
            {
                refused = e;
            }
        }

        Assert.True(
            refused is null,
            $"The read-only-holder rule did not hold on Windows {Environment.OSVersion.Version}: a standard user who may only read {Override} held {way}, and the override could not be read: {refused?.Message}");
        Assert.Equal("2026-01-01", lifecycle?.LastReviewed);
        Assert.Equal([Override], gate.Overrides);
        Assert.Empty(gate.Notices);
    }

    [Fact]
    public void Through_the_read_only_store_an_administrator_s_override_loads_and_nothing_changes()
    {
        Arrange();
        _tree.File(Relative(Override), OverrideText, "O:BA");
        var before = TreeSnapshot.Of(_programData);

        var (gate, lifecycle) = ReadOnlyAsThisProcess();

        Assert.Equal("2026-01-01", lifecycle.LastReviewed);
        Assert.Equal([Override], gate.Overrides);
        Assert.Empty(gate.Notices);
        Assert.Equal(before, TreeSnapshot.Of(_programData));
        Assert.Empty(_events.Entries);
    }

    [Fact]
    public void Through_the_read_only_store_an_override_standard_users_can_change_is_refused_and_the_shipped_file_used()
    {
        Arrange();
        _tree.File(Relative(Override), OverrideText, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;BU)");

        var (gate, lifecycle) = ReadOnlyAsThisProcess();

        AssertRefused(gate, lifecycle, "can be changed by S-1-5-32-545, not only administrators.");
    }

    [Fact]
    public void Through_the_read_only_store_a_config_folder_standard_users_can_change_is_refused_and_left_in_place()
    {
        Arrange();
        Acls.Reset(Config, ConfigAccess + "(A;OICI;0x1301bf;;;BU)");
        _tree.File(Relative(Override), OverrideText, "O:BA");
        var before = TreeSnapshot.Of(_programData);

        var (gate, lifecycle) = ReadOnlyAsThisProcess();

        Assert.Equal(ShippedLastReviewed, lifecycle.LastReviewed);
        Assert.Equal([$"Ignoring the config override {Name} and using the shipped copy: {Config} can be changed by S-1-5-32-545, not only administrators."], gate.Notices);
        Assert.Empty(gate.Overrides);
        Assert.Equal(before, TreeSnapshot.Of(_programData));
        Assert.Empty(_events.Entries);
    }

    [Fact]
    public void Through_the_read_only_store_a_config_folder_a_standard_user_made_is_refused_and_left_in_place()
    {
        Assert.SkipUnless(Attacker.IsAvailable, Attacker.Unavailable);
        _programData = _tree.Folder("ProgramData", Descriptors.ProgramDataLike);
        var dataFolder = _tree.Folder(@"ProgramData\EngramicBaseline", Descriptors.InstallerLocked);

        // The attacker may add a folder to the data folder for a moment, as a mistaken grant could let them, and the
        // data folder is locked again after: the folder keeps the owner who made it.
        Acls.Reset(dataFolder, Descriptors.InstallerLocked[4..] + $"(A;;0x100005;;;{Attacker.Sid})");
        Attacker.Run(() => Directory.CreateDirectory(Config));
        Acls.Reset(dataFolder, Descriptors.InstallerLocked[4..]);
        var before = TreeSnapshot.Of(_programData);

        var (gate, lifecycle) = ReadOnlyAsThisProcess();

        Assert.Equal(Attacker.Sid.Value, Acls.Owner(Config));
        Assert.Equal(ShippedLastReviewed, lifecycle.LastReviewed);
        Assert.Equal([$"Ignoring the config override {Name} and using the shipped copy: {Config} is owned by {Attacker.Sid}, not SYSTEM, Administrators or TrustedInstaller."], gate.Notices);
        Assert.Equal(before, TreeSnapshot.Of(_programData));
        Assert.Empty(_events.Entries);
    }

    [Theory]
    [MemberData(nameof(Holders.ReadOnlyHolderWays), MemberType = typeof(Holders))]
    public void Through_the_read_only_store_an_override_a_standard_user_holds_up_is_not_replaced_by_the_shipped_file(string way)
    {
        Assert.SkipUnless(Attacker.IsAvailable, Attacker.Unavailable);
        Arrange();
        _tree.File(Relative(Override), OverrideText, "O:BA");
        var clock = new FakeTimeProvider();

        using var store = SecureStore.OpenReadOnly(Options() with { Time = clock });
        var gate = new ConfigTrustGate(ShippedConfig.Files, store, CurrentProcess.ReadAccount());
        using (Attacker.Run(() => Holders.Hold(way, Override, Config)))
        {
            var e = Assert.Throws<IOException>(() => Waits.AdvanceUntilDone(clock, () => _ = new AuditConfig(gate).OsLifecycle));

            Assert.StartsWith($"The config override {Override} could not be read, so the shipped copy is not used in its place: ", e.Message, StringComparison.Ordinal);
        }

        Assert.StartsWith($"Could not read the config override {Name}, so the checks that read it report an error", Assert.Single(gate.Notices), StringComparison.Ordinal);
        Assert.Empty(gate.Overrides);
        Assert.Empty(_events.Entries);
    }

    [Fact]
    public void Through_the_read_only_store_a_data_folder_that_does_not_exist_gives_no_overrides_and_none_is_made()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);
        _programData = _tree.Folder("ProgramData", Descriptors.ProgramDataLike);

        var store = SecureStore.OpenReadOnly(Options());

        Assert.Null(store);
        Assert.Empty(Directory.GetFileSystemEntries(_programData));
        Assert.Empty(_events.Entries);
    }

    /// <summary>Makes ProgramData, and the data folder and its config folder as the installer makes them.</summary>
    private void Arrange()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);
        _programData = _tree.Folder("ProgramData", Descriptors.ProgramDataLike);
        _tree.Folder(@"ProgramData\EngramicBaseline", Descriptors.InstallerLocked);
        _tree.Folder(@"ProgramData\EngramicBaseline\config", Descriptors.InstallerLockedUsersRead);
    }

    /// <summary>
    /// Opens the data folder with the product's rules and reads os-lifecycle.json through the gate as this process
    /// reads it, as the scheduled audit does, and the config the checks would then see.
    /// </summary>
    private (ConfigTrustGate Gate, OsLifecycle Lifecycle) ReadAsThisProcess()
    {
        using var store = SecureStore.Open(new SecureStoreOptions { ProgramDataPath = _programData, Registry = DataFolderFixture.Sealed(), EventLog = _events });
        var gate = new ConfigTrustGate(ShippedConfig.Files, store, CurrentProcess.ReadAccount());
        return (gate, new AuditConfig(gate).OsLifecycle);
    }

    /// <summary>
    /// Opens the data folder only to read from it, with the product's rules, and reads os-lifecycle.json through the
    /// gate as this process reads it, as an elevated baseline.exe audit does.
    /// </summary>
    private (ConfigTrustGate Gate, OsLifecycle Lifecycle) ReadOnlyAsThisProcess()
    {
        using var store = SecureStore.OpenReadOnly(Options());
        Assert.NotNull(store);
        var gate = new ConfigTrustGate(ShippedConfig.Files, store, CurrentProcess.ReadAccount());
        return (gate, new AuditConfig(gate).OsLifecycle);
    }

    private SecureStoreOptions Options() => new() { ProgramDataPath = _programData, Registry = DataFolderFixture.Sealed(), EventLog = _events };

    private void AssertRefused(ConfigTrustGate gate, OsLifecycle lifecycle, string reason)
    {
        Assert.Equal(ShippedLastReviewed, lifecycle.LastReviewed);
        Assert.Equal([$"Ignoring the config override {Name} and using the shipped copy: {Override} {reason}"], gate.Notices);
        Assert.Empty(gate.Overrides);
    }

    private string Relative(string path) => Path.GetRelativePath(_tree.Root, path);
}
