using System.Text;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;

namespace Engramic.Baseline.Engine.Tests;

/// <summary>
/// The config trust gate, with a data folder in memory: an administrator's override replaces a shipped file
/// whole only when the run is elevated or SYSTEM, the data folder gives it (SecureStore's rules, which the
/// Windows tests hold it to) and it meets its schema; otherwise the shipped file is used and the refusal logged.
/// </summary>
public sealed class ConfigTrustGateTests
{
    private const string Name = "os-lifecycle.json";
    private const string OverridePath = @"C:\ProgramData\EngramicBaseline\config\os-lifecycle.json";
    private const string Refused = "Ignoring the config override os-lifecycle.json and using the shipped copy: ";

    private const string Shipped = """
        {
          "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60,
          "windows11": [ { "build": 26100, "version": "24H2", "homePro": "2026-10-13", "enterprise": "2027-10-12" } ]
        }
        """;

    private const string Override = """{ "lastReviewed": "2026-01-01", "reviewWarningDays": 30, "upcomingEndWarningDays": 60 }""";

    private static readonly ProcessAccount LocalSystem = new(@"NT AUTHORITY\SYSTEM", IsAdministrator: true, IsLocalSystem: true);
    private static readonly ProcessAccount Administrator = new(@"CONTOSO\admin", IsAdministrator: true, IsLocalSystem: false);
    private static readonly ProcessAccount StandardUser = new(@"CONTOSO\alex", IsAdministrator: false, IsLocalSystem: false);

    /// <summary>A standard user's account.</summary>
    private static readonly Sid User = Sid.Parse("S-1-5-21-1004336348-1177238915-682003330-1001");

    private readonly FakeSecureStore _store = new();

    /// <summary>
    /// Items that break each of SecureStore's rules for a file it reads, by the rule: what a handle open on the
    /// item says, and its owner and access list.
    /// </summary>
    public static TheoryData<string> Rules => [.. Items.Keys];

    private static Dictionary<string, (FileFacts Facts, ItemSecurity Security)> Items { get; } = new()
    {
        ["owned by a standard user"] = (PlainFile(), Locked() with { Owner = User }),
        ["owned by no account the tool can read"] = (PlainFile(), Locked() with { Owner = null }),
        ["standard users may write it"] = (PlainFile(), Locked(Allow(Sid.Users, 0x0000_0002))),
        ["standard users may add to it"] = (PlainFile(), Locked(Allow(Sid.Users, 0x0000_0004))),
        ["standard users may write its extended attributes"] = (PlainFile(), Locked(Allow(Sid.Users, 0x0000_0010))),
        ["standard users may write its attributes"] = (PlainFile(), Locked(Allow(Sid.Users, 0x0000_0100))),
        ["standard users may delete it"] = (PlainFile(), Locked(Allow(Sid.Users, 0x0001_0000))),
        ["standard users may change its permissions"] = (PlainFile(), Locked(Allow(Sid.Users, 0x0004_0000))),
        ["standard users may take ownership of it"] = (PlainFile(), Locked(Allow(Sid.Users, 0x0008_0000))),
        ["a user may write it through a generic right"] = (PlainFile(), Locked(Allow(User, 0x4000_0000))),
        ["a user has every right through a generic right"] = (PlainFile(), Locked(Allow(User, 0x1000_0000))),
        ["everyone may change it"] = (PlainFile(), Locked(Allow(Sid.Parse("S-1-1-0"), 0x001F_01FF))),
        ["it has no access list"] = (PlainFile(), Locked() with { Dacl = null }),
        ["it denies SYSTEM a right"] = (PlainFile(), Locked(new AccessEntry(AccessEntryType.Deny, Sid.LocalSystem, 0x0004_0000))),
        ["it denies Administrators a right"] = (PlainFile(), Locked(new AccessEntry(AccessEntryType.Deny, Sid.Administrators, 0x0001_0000))),
        ["it has an entry of a kind the tool does not recognise"] = (PlainFile(), Locked(new AccessEntry(AccessEntryType.Other, User, 0x0000_0002))),
        ["it has a second name"] = (PlainFile() with { LinkCount = 2 }, Locked()),
        ["it is a junction, symbolic link or other reparse point"] = (PlainFile() with { IsReparsePoint = true }, Locked()),
        ["it is stored online only"] = (PlainFile() with { IsOnlineOnly = true }, Locked()),
        ["it is a folder"] = (new FileFacts { IsDirectory = true }, Locked()),
        ["it is longer than the gate reads"] = (PlainFile() with { Length = ConfigTrustGate.MaxOverrideLength + 1 }, Locked()),
    };

    [Theory]
    [MemberData(nameof(Accounts))]
    public void An_override_that_passes_every_rule_replaces_the_shipped_file_whole(string account)
    {
        _store.WriteFile(DataFolder.Config, Name, Bytes(Override));
        var gate = Gate(Account(account));

        var config = new AuditConfig(gate);

        Assert.Equal("2026-01-01", config.OsLifecycle.LastReviewed);
        Assert.Equal(30, config.OsLifecycle.ReviewWarningDays);
        Assert.Null(config.OsLifecycle.Windows11);
        Assert.Equal([OverridePath], gate.Overrides);
        Assert.Empty(gate.Notices);
    }

    [Fact]
    public void Reads_an_override_from_the_config_folder_no_longer_than_the_cap()
    {
        Gate(LocalSystem).Read(Name);

        Assert.Equal([(DataFolder.Config, Name, ConfigTrustGate.MaxOverrideLength)], _store.Reads);
        Assert.Equal(1024 * 1024, ConfigTrustGate.MaxOverrideLength);
    }

    [Fact]
    public void Gives_the_shipped_file_when_there_is_no_override()
    {
        var gate = Gate(LocalSystem);

        Assert.Equal(Bytes(Shipped), gate.Read(Name));
        Assert.Empty(gate.Overrides);
        Assert.Empty(gate.Notices);
    }

    [Fact]
    public void A_run_that_is_not_elevated_reads_no_override_even_from_an_open_data_folder()
    {
        _store.WriteFile(DataFolder.Config, Name, Bytes(Override));
        var gate = Gate(StandardUser);

        Assert.Equal(Bytes(Shipped), gate.Read(Name));
        Assert.Empty(_store.Reads);
        Assert.Empty(gate.Overrides);
    }

    [Fact]
    public void A_run_without_the_data_folder_gives_the_shipped_files()
    {
        var gate = new ConfigTrustGate(Shipments(), store: null, LocalSystem);

        Assert.Equal(Bytes(Shipped), gate.Read(Name));
        Assert.Empty(gate.Notices);
    }

    [Theory]
    [MemberData(nameof(Rules))]
    public void An_override_that_breaks_one_of_SecureStore_s_rules_is_ignored_for_the_shipped_file_and_logged(string rule)
    {
        var (facts, security) = Items[rule];
        var reason = DataFolderTrust.Machine.FindReadProblem(OverridePath, facts, security, ConfigTrustGate.MaxOverrideLength);
        Assert.NotNull(reason);
        _store.FailRead(DataFolder.Config, Name, new SecureStoreException(reason));
        var gate = Gate(LocalSystem);

        Assert.Equal(Bytes(Shipped), gate.Read(Name));
        Assert.Equal([Refused + reason], gate.Notices);
        Assert.Empty(gate.Overrides);
    }

    [Fact]
    public void An_override_owned_by_SYSTEM_Administrators_or_TrustedInstaller_and_changeable_by_no_one_else_passes_those_rules()
    {
        // What SecureStore gives the gate, for the other half of the test above.
        foreach (var owner in new[] { Sid.LocalSystem, Sid.Administrators, Sid.TrustedInstaller })
        {
            Assert.Null(DataFolderTrust.Machine.FindReadProblem(OverridePath, PlainFile() with { Length = ConfigTrustGate.MaxOverrideLength }, Locked(Allow(Sid.Users, 0x0012_00A9)) with { Owner = owner }, ConfigTrustGate.MaxOverrideLength));
        }
    }

    [Fact]
    public void An_override_longer_than_the_cap_is_ignored_and_one_exactly_as_long_is_read()
    {
        var exact = Padded(ConfigTrustGate.MaxOverrideLength);
        _store.WriteFile(DataFolder.Config, Name, exact);
        Assert.Equal(exact, Gate(LocalSystem).Read(Name));

        _store.WriteFile(DataFolder.Config, Name, Padded(ConfigTrustGate.MaxOverrideLength + 1));
        var gate = Gate(LocalSystem);

        Assert.Equal(Bytes(Shipped), gate.Read(Name));
        Assert.Equal([$"{Refused}{OverridePath} is {ConfigTrustGate.MaxOverrideLength + 1} bytes long, more than the {ConfigTrustGate.MaxOverrideLength} bytes the tool reads from it."], gate.Notices);
    }

    [Theory]
    [MemberData(nameof(Unreadable))]
    public void An_override_that_cannot_be_read_is_not_replaced_by_the_shipped_file_and_the_checks_that_read_it_fail(string failure)
    {
        // Standard users can bring some of these about by locking part of the file or holding an oplock on it, and
        // a process that may write to the file or its folder by holding either open without sharing: falling back
        // to the shipped copy would let them undo the override unseen.
        var error = Failures[failure];
        _store.FailRead(DataFolder.Config, Name, error);
        var gate = Gate(LocalSystem);

        var e = Assert.Throws<IOException>(() => new AuditConfig(gate).OsLifecycle);

        Assert.Equal($"The config override {OverridePath} could not be read, so the shipped copy is not used in its place: {error.Message}", e.Message);
        Assert.Equal([$"Could not read the config override {Name}, so the checks that read it report an error and the shipped copy is not used in its place: {error.Message}"], gate.Notices);
        Assert.Empty(gate.Overrides);
    }

    [Fact]
    public void An_override_that_cannot_be_read_fails_every_read_of_it_in_the_run_and_is_logged_once()
    {
        _store.FailRead(DataFolder.Config, Name, Failures["held open by another process"]);
        var gate = Gate(LocalSystem);

        Assert.Throws<IOException>(() => gate.Read(Name));

        // Whatever the data folder would give now, the run keeps to what it decided.
        _store.FailRead(DataFolder.Config, Name, new InvalidOperationException("Not read again."));
        _store.WriteFile(DataFolder.Config, Name, Bytes(Override));
        Assert.Throws<IOException>(() => gate.Read(Name));
        Assert.Single(_store.Reads);
        Assert.Single(gate.Notices);
    }

    [Fact]
    public void An_override_whose_member_is_named_by_an_escaped_lone_surrogate_is_refused_not_thrown()
    {
        _store.WriteFile(DataFolder.Config, Name, Bytes("""{ "\ud800": 1, "lastReviewed": "2026-01-01", "reviewWarningDays": 30, "upcomingEndWarningDays": 60 }"""));
        var gate = Gate(LocalSystem);

        Assert.Equal(Bytes(Shipped), gate.Read(Name));
        Assert.StartsWith($"{Refused}{OverridePath} is not valid JSON: ", Assert.Single(gate.Notices), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{ "lastReviewed": "2026-01-01" }""", "is not a valid os-lifecycle.json: ")]
    [InlineData("""[ { "lastReviewed": "2026-01-01", "reviewWarningDays": 30, "upcomingEndWarningDays": 60 } ]""", "is not a JSON object.")]
    [InlineData("""{ "lastReviewed": "2026-01-01", "reviewWarningDays": 30, "upcomingEndWarningDays": 60, "LastReviewed": "2020-01-01" }""", "names LastReviewed more than once in one object (line 1), so which value counts is not clear.")]
    [InlineData("""{ "lastReviewed": "2026-01-01", "reviewWarningDays": 30, "upcomingEndWarningDays": 60, }""", "is not valid JSON: ")]
    public void An_override_that_does_not_meet_its_schema_is_ignored_for_the_shipped_file_and_logged(string copy, string problem)
    {
        _store.WriteFile(DataFolder.Config, Name, Bytes(copy));
        var gate = Gate(LocalSystem);

        Assert.Equal(Bytes(Shipped), gate.Read(Name));
        Assert.StartsWith($"{Refused}{OverridePath} {problem}", Assert.Single(gate.Notices), StringComparison.Ordinal);
        Assert.Empty(gate.Overrides);
    }

    [Fact]
    public void An_override_that_is_not_UTF8_is_ignored_for_the_shipped_file_and_logged()
    {
        _store.WriteFile(DataFolder.Config, Name, [0x7B, 0xFF, 0x7D]);
        var gate = Gate(LocalSystem);

        Assert.Equal(Bytes(Shipped), gate.Read(Name));
        Assert.Equal([$"{Refused}{OverridePath} is not UTF-8 (line 1), so it may have been saved as ANSI; save it as UTF-8, for example with Set-Content -Encoding utf8."], gate.Notices);
    }

    [Fact]
    public void An_override_saved_as_UTF16_is_ignored_for_the_shipped_file_and_the_notice_says_how_to_save_it()
    {
        // As Windows PowerShell 5.1's Out-File writes it, which the module read and this tool does not.
        _store.WriteFile(DataFolder.Config, Name, [.. Encoding.Unicode.GetPreamble(), .. Encoding.Unicode.GetBytes(Shipped)]);
        var gate = Gate(LocalSystem);

        Assert.Equal(Bytes(Shipped), gate.Read(Name));
        Assert.Equal([$"{Refused}{OverridePath} is saved as UTF-16, as Windows PowerShell 5.1's > and Out-File save text, not as UTF-8; save it as UTF-8, for example with Set-Content -Encoding utf8."], gate.Notices);
        Assert.Empty(gate.Overrides);
    }

    [Fact]
    public void Only_a_file_that_ships_can_be_overridden()
    {
        _store.WriteFile(DataFolder.Config, "extra.json", Bytes("{}"));
        var gate = Gate(LocalSystem);

        Assert.Null(gate.Read("extra.json"));
        Assert.Empty(_store.Reads);
        Assert.Empty(gate.Notices);
    }

    [Fact]
    public void A_shipped_file_with_no_schema_is_never_overridden_and_the_gate_says_so()
    {
        _store.WriteFile(DataFolder.Config, "unmodelled.json", Bytes("""{ "planted": true }"""));
        var gate = new ConfigTrustGate(new ConfigFiles(new() { ["unmodelled.json"] = "{}" }), _store, LocalSystem);

        Assert.Equal(Bytes("{}"), gate.Read("unmodelled.json"));
        Assert.Empty(_store.Reads);
        Assert.Equal(["Overrides of unmodelled.json are not read, and the shipped copy is used: this version has no schema to check one against."], gate.Notices);
    }

    [Fact]
    public void Decides_each_file_once_and_gives_the_same_bytes_for_the_rest_of_the_run()
    {
        _store.WriteFile(DataFolder.Config, Name, Bytes(Override));
        var gate = Gate(LocalSystem);
        var first = gate.Read(Name);

        _store.WriteFile(DataFolder.Config, Name, Bytes("""{ "lastReviewed": "2020-01-01", "reviewWarningDays": 1, "upcomingEndWarningDays": 1 }"""));

        Assert.Equal(first, gate.Read(Name));
        Assert.Single(_store.Reads);
        Assert.Equal([OverridePath], gate.Overrides);
    }

    [Fact]
    public void Logs_a_refusal_once_however_often_the_file_is_read()
    {
        _store.FailRead(DataFolder.Config, Name, new SecureStoreException(OverridePath + " has 2 names (hard links), not one, so it may also be a file somewhere else."));
        var gate = Gate(LocalSystem);

        gate.Read(Name);
        gate.Read(Name);

        Assert.Single(gate.Notices);
        Assert.Single(_store.Reads);
    }

    [Fact]
    public void Gives_each_reader_a_copy_of_its_own()
    {
        _store.WriteFile(DataFolder.Config, Name, Bytes(Override));
        var gate = Gate(LocalSystem);

        var first = gate.Read(Name)!;
        first[0] = (byte)'[';

        Assert.Equal(Bytes(Override), gate.Read(Name));
    }

    [Fact]
    public void Refuses_no_shipped_files_or_account()
    {
        Assert.Throws<ArgumentNullException>(() => new ConfigTrustGate(null!, _store, LocalSystem));
        Assert.Throws<ArgumentNullException>(() => new ConfigTrustGate(Shipments(), _store, null!));
    }

    public static TheoryData<string> Accounts => ["SYSTEM", "an elevated administrator"];

    public static TheoryData<string> Unreadable => [.. Failures.Keys];

    /// <summary>What the data folder throws for an override it could not open or read, by what happened.</summary>
    private static Dictionary<string, Exception> Failures { get; } = new()
    {
        ["held open by another process"] = new SecureStoreException(OverridePath + " could not be read: The process cannot access the file because it is being used by another process (Win32 error 32).", isUnavailable: true, null),
        ["locked in part"] = new SecureStoreException(OverridePath + " could not be read: The process cannot access the file because another process has locked a portion of the file (Win32 error 33).", isUnavailable: true, null),
        ["its folder could not be opened"] = new SecureStoreException("Could not read os-lifecycle.json: Could not make a locked folder at C:\\ProgramData\\EngramicBaseline\\config.", isUnavailable: true, null),
        ["a device error"] = new IOException("The device is not ready."),
        ["access denied, which the data folder should have judged"] = new UnauthorizedAccessException("Access is denied."),
    };

    private static ProcessAccount Account(string name) => name == "SYSTEM" ? LocalSystem : Administrator;

    private ConfigTrustGate Gate(ProcessAccount account) => new(Shipments(), _store, account);

    private static ConfigFiles Shipments() => new(new() { [Name] = Shipped });

    private static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    /// <summary>A valid override of exactly the given length, its notes padded with spaces.</summary>
    private static byte[] Padded(int length)
    {
        var start = """{ "lastReviewed": "2026-01-01", "reviewWarningDays": 30, "upcomingEndWarningDays": 60, "notes": " """;
        const string End = "\" }";
        return Bytes(start + new string(' ', length - start.Length - End.Length) + End);
    }

    private static FileFacts PlainFile() => new() { Length = 100 };

    /// <summary>A file locked as SecureStore makes one: owned by Administrators, SYSTEM and Administrators in full control, and any entries given.</summary>
    private static ItemSecurity Locked(params AccessEntry[] more)
    {
        return new ItemSecurity(Sid.Administrators, [Allow(Sid.LocalSystem, 0x001F_01FF), Allow(Sid.Administrators, 0x001F_01FF), .. more]);
    }

    private static AccessEntry Allow(Sid trustee, uint mask) => new(AccessEntryType.Allow, trustee, mask);
}
