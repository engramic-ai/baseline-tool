using System.Text;
using Engramic.Baseline.Controls;
using Engramic.Baseline.Engine;
using Engramic.Baseline.Model;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing.Windows;
using Microsoft.Extensions.Time.Testing;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// The config trust gate in front of the shipped config, reading administrators' overrides through the real
/// SecureStore, in a data folder of the tests' own: each rule an override can break, planted as it could be on a
/// device, keeps the shipped file in use, and the refusal is logged. With the tests' rules, which trust the
/// account running them, so none needs elevation; <see cref="ConfigTrustGateElevatedTests"/> holds the product's
/// rules, as an administrator and as SYSTEM.
/// </summary>
[Trait("Suite", "Security")]
public sealed class ConfigTrustGateTests : IDisposable
{
    private const string Name = ConfigFile.OsLifecycleName;

    /// <summary>A valid os-lifecycle.json that differs from the shipped one.</summary>
    private const string OverrideText = """{ "lastReviewed": "2026-01-01", "reviewWarningDays": 30, "upcomingEndWarningDays": 60 }""";

    /// <summary>A file's access list as the tests' folders give it: SYSTEM, Administrators and the account running the tests.</summary>
    private static readonly string FileAccess = $"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{Elevation.CurrentUser})";

    /// <summary>An account that reads overrides; the store's rules decide which ones it trusts.</summary>
    private static readonly ProcessAccount Elevated = new("CONTOSO\\admin", IsAdministrator: true, IsLocalSystem: false);

    private readonly DataFolderFixture _fixture = new();

    public ConfigTrustGateTests()
    {
        // The config folder as the tests' account makes it, which their rules trust.
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline\config");
    }

    private string Config => Path.Combine(_fixture.DataFolder, "config");

    private string Override => Path.Combine(Config, Name);

    public void Dispose() => _fixture.Dispose();

    [Fact]
    public void An_override_the_rules_trust_replaces_the_shipped_file_whole()
    {
        File.WriteAllText(Override, OverrideText);
        using var store = _fixture.Open();
        var gate = new ConfigTrustGate(ShippedConfig.Files, store, Elevated);

        var lifecycle = new AuditConfig(gate).OsLifecycle;

        Assert.Equal("2026-01-01", lifecycle.LastReviewed);
        Assert.Null(lifecycle.Windows11);
        Assert.Equal([Override], gate.Overrides);
        Assert.Empty(gate.Notices);
    }

    [Theory]
    [InlineData("standard users may write it", "can be changed by S-1-5-32-545, not only administrators.")]
    [InlineData("standard users may delete it", "can be changed by S-1-5-32-545, not only administrators.")]
    [InlineData("standard users may change its permissions", "can be changed by S-1-5-32-545, not only administrators.")]
    [InlineData("standard users may take ownership of it", "can be changed by S-1-5-32-545, not only administrators.")]
    [InlineData("it denies SYSTEM a right", "denies S-1-5-18 some rights, so the tool may be unable to replace it.")]
    [InlineData("it denies Administrators a right", "denies S-1-5-32-544 some rights, so the tool may be unable to replace it.")]
    [InlineData("it has a second name, a hard link", "has 2 names (hard links), not one, so it may also be a file somewhere else.")]
    [InlineData("a junction is at its name", "is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.")]
    [InlineData("it is a reparse point of another kind", "is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.")]
    [InlineData("it is stored online only", "is stored online only, so opening it would fetch it from elsewhere.")]
    [InlineData("a folder is at its name", "is a folder, not a file.")]
    [InlineData("it is longer than the cap", "is 1048577 bytes long, more than the 1048576 bytes the tool reads from it.")]
    [InlineData("it is not UTF-8", "is not UTF-8 (line 1), so it may have been saved as ANSI; save it as UTF-8, for example with Set-Content -Encoding utf8.")]
    [InlineData("it names a member twice", "names lastReviewed more than once in one object (line 1), so which value counts is not clear.")]
    [InlineData("it is not what the file's reader accepts", "is not a valid os-lifecycle.json: ")]
    public void An_override_that_breaks_a_rule_is_ignored_for_the_shipped_file_and_logged(string rule, string reason)
    {
        Plant(rule);
        using var store = _fixture.Open();
        var gate = new ConfigTrustGate(ShippedConfig.Files, store, Elevated);

        Assert.Equal(ShippedConfig.Files.Read(Name), gate.Read(Name));
        var notice = Assert.Single(gate.Notices);
        Assert.StartsWith($"Ignoring the config override {Name} and using the shipped copy: {Override} {reason}", notice, StringComparison.Ordinal);
        Assert.Empty(gate.Overrides);
        Assert.Equal(ConfigFile.ReadOsLifecycle(ShippedConfig.Files.Read(Name)).LastReviewed, new AuditConfig(gate).OsLifecycle.LastReviewed);
    }

    [Fact]
    public void An_override_exactly_as_long_as_the_cap_is_read()
    {
        File.WriteAllBytes(Override, Padded(ConfigTrustGate.MaxOverrideLength));
        using var store = _fixture.Open();
        var gate = new ConfigTrustGate(ShippedConfig.Files, store, Elevated);

        Assert.Equal(ConfigTrustGate.MaxOverrideLength, gate.Read(Name)!.Length);
        Assert.Equal([Override], gate.Overrides);
    }

    [Fact]
    public void A_config_folder_standard_users_can_change_is_moved_aside_and_the_shipped_file_used()
    {
        Acls.Reset(Config, TempTree.TreeAccess + "(A;OICI;FA;;;BU)");
        File.WriteAllText(Override, OverrideText);
        using var store = _fixture.Open();
        var gate = new ConfigTrustGate(ShippedConfig.Files, store, Elevated);

        Assert.Equal(ShippedConfig.Files.Read(Name), gate.Read(Name));

        // Nothing in the folder was read: SecureStore moved it aside whole, with its notice and event 1003.
        Assert.EndsWith("-config", Assert.Single(_fixture.Quarantines), StringComparison.Ordinal);
        Assert.Contains("can be changed by S-1-5-32-545", Assert.Single(store.Notices), StringComparison.Ordinal);
        Assert.Single(_fixture.Events.Entries);
        Assert.Empty(gate.Overrides);
    }

    [Theory]
    [MemberData(nameof(Holders.Ways), MemberType = typeof(Holders))]
    public void An_override_someone_holds_up_is_not_replaced_by_the_shipped_file_and_the_checks_that_read_it_fail(string way)
    {
        // As this account here, which may write to the fixture's folders, so Windows honours each refusal to share;
        // ConfigTrustGateElevatedTests holds as a standard user, whom the product's config folder lets only read the
        // file, which leaves the lock and the oplock.
        File.WriteAllText(Override, OverrideText);
        var clock = new FakeTimeProvider();
        _fixture.Time = clock;
        using var store = _fixture.Open();
        var gate = new ConfigTrustGate(ShippedConfig.Files, store, Elevated);

        using (var holder = Holders.Hold(way, Override, Config))
        {
            var e = Assert.Throws<IOException>(() => Waits.AdvanceUntilDone(clock, () => _ = new AuditConfig(gate).OsLifecycle));

            Assert.StartsWith($"The config override {Override} could not be read, so the shipped copy is not used in its place: Could not read ", e.Message, StringComparison.Ordinal);
            if (holder is Oplock oplock)
            {
                Assert.True(oplock.BreakRequested);
            }
        }

        // Decided once for the run: letting go later does not bring in either copy.
        Assert.Throws<IOException>(() => gate.Read(Name));
        Assert.StartsWith($"Could not read the config override {Name}, so the checks that read it report an error and the shipped copy is not used in its place: ", Assert.Single(gate.Notices), StringComparison.Ordinal);
        Assert.Empty(gate.Overrides);
        Assert.Empty(_fixture.Quarantines);
    }

    [Fact]
    public void A_run_that_is_not_elevated_reads_nothing_from_the_data_folder_and_changes_nothing_there()
    {
        Acls.Reset(Config, TempTree.TreeAccess + "(A;OICI;FA;;;BU)");
        File.WriteAllText(Override, OverrideText);
        using var store = _fixture.Open();
        var gate = new ConfigTrustGate(ShippedConfig.Files, store, new ProcessAccount(@"CONTOSO\alex", IsAdministrator: false, IsLocalSystem: false));

        Assert.Equal(ShippedConfig.Files.Read(Name), gate.Read(Name));
        Assert.Empty(_fixture.Quarantines);
        Assert.Empty(store.Notices);
        Assert.Empty(gate.Notices);
    }

    /// <summary>Puts at the override's name what breaks the rule.</summary>
    private void Plant(string rule)
    {
        switch (rule)
        {
            case "standard users may write it":
                PlantWithAccess(FileAccess + "(A;;0x2;;;BU)");
                break;
            case "standard users may delete it":
                PlantWithAccess(FileAccess + "(A;;SD;;;BU)");
                break;
            case "standard users may change its permissions":
                PlantWithAccess(FileAccess + "(A;;WD;;;BU)");
                break;
            case "standard users may take ownership of it":
                PlantWithAccess(FileAccess + "(A;;WO;;;BU)");
                break;
            case "it denies SYSTEM a right":
                PlantWithAccess("D:P(D;;WD;;;SY)" + FileAccess[4..]);
                break;
            case "it denies Administrators a right":
                PlantWithAccess("D:P(D;;WO;;;BA)" + FileAccess[4..]);
                break;
            case "it has a second name, a hard link":
                Links.CreateHardLink(Override, _fixture.Tree.File("outside.json", OverrideText));
                break;
            case "a junction is at its name":
                Links.CreateJunction(Override, _fixture.Tree.Folder("Elsewhere"));
                break;
            case "it is a reparse point of another kind":
                File.WriteAllText(Override, OverrideText);
                Links.MakeThirdPartyReparsePoint(Override);
                break;
            case "it is stored online only":
                File.WriteAllText(Override, OverrideText);
                File.SetAttributes(Override, FileAttributes.Offline);
                break;
            case "a folder is at its name":
                Directory.CreateDirectory(Override);
                break;
            case "it is longer than the cap":
                File.WriteAllBytes(Override, Padded(ConfigTrustGate.MaxOverrideLength + 1));
                break;
            case "it is not UTF-8":
                File.WriteAllBytes(Override, [0x7B, 0xFF, 0x7D]);
                break;
            case "it names a member twice":
                File.WriteAllText(Override, """{ "lastReviewed": "2026-01-01", "reviewWarningDays": 30, "upcomingEndWarningDays": 60, "lastReviewed": "2020-01-01" }""");
                break;
            case "it is not what the file's reader accepts":
                File.WriteAllText(Override, """{ "lastReviewed": "2026-01-01" }""");
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(rule), rule, "Not a rule these tests plant.");
        }
    }

    private void PlantWithAccess(string dacl)
    {
        File.WriteAllText(Override, OverrideText);
        Acls.Reset(Override, dacl);
    }

    /// <summary>A valid override of exactly the given length, its notes padded with spaces.</summary>
    private static byte[] Padded(int length)
    {
        var start = """{ "lastReviewed": "2026-01-01", "reviewWarningDays": 30, "upcomingEndWarningDays": 60, "notes": " """;
        const string End = "\" }";
        return Encoding.UTF8.GetBytes(start + new string(' ', length - start.Length - End.Length) + End);
    }
}
