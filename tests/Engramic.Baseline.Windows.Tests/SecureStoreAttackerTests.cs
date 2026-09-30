using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;
using Engramic.Baseline.Testing.Windows;
using Microsoft.Extensions.Time.Testing;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// The attack suite with a real standard user as the attacker (<see cref="Attacker"/>), working in a folder
/// like ProgramData, where standard users may create folders, before and while SecureStore runs with the
/// product's rules as an elevated administrator or SYSTEM. The attacker's items are theirs: they own them,
/// can change them, and keep what a handle they opened allowed. Only the Security job in CI makes the
/// attacker, so these skip anywhere else.
/// </summary>
[Trait("Suite", "Security")]
public sealed class SecureStoreAttackerTests : IDisposable
{
    private const uint AddFile = 0x0000_0002;
    private const uint ReadControl = 0x0002_0000;
    private const uint WriteDac = 0x0004_0000;
    private const uint Synchronize = 0x0010_0000;

    private readonly TempTree _tree = new();
    private readonly FakeEventLog _events = new();
    private readonly List<string> _attackersItems = [];
    private string _programData = string.Empty;

    private string DataRoot => Path.Combine(_programData, SecureStore.DataFolderName);

    public void Dispose()
    {
        // What the attacker made may deny this account, so the attacker removes it before the tree goes: what it
        // made on purpose, what was moved aside, and a data folder of its own that a failed test left in place.
        if (Attacker.IsAvailable && _programData.Length > 0)
        {
            foreach (var item in _attackersItems.Concat(Quarantines()).Append(DataRoot).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    Attacker.Remove(item);
                }
                catch (Exception e) when (e is UnauthorizedAccessException or IOException)
                {
                    // Not the attacker's, such as the data folder the store made: the tree's own removal takes it.
                }
            }
        }

        _tree.Dispose();
    }

    [Fact]
    public void A_data_folder_the_attacker_made_first_is_moved_aside_and_the_handle_they_kept_reaches_only_the_quarantine()
    {
        Arrange();

        // The attacker makes the folder, keeps a handle that may change its permissions, and locks it to look
        // like the install's, as a user who wants a later install to adopt it would.
        using var kept = Attacker.Run(() =>
        {
            Directory.CreateDirectory(DataRoot);
            var handle = Native.OpenWithShare(DataRoot, WriteDac | ReadControl | Synchronize, NtFiles.ShareAll);
            Acls.Reset(DataRoot, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
            return handle;
        });

        using var store = Initialize();

        var quarantine = Assert.Single(Quarantines());
        Assert.Contains($"is owned by {Attacker.Sid}, not SYSTEM, Administrators or TrustedInstaller", Assert.Single(store.Notices), StringComparison.Ordinal);

        // The handle still changes permissions, whatever the lock said: of the quarantine, not the data folder.
        Assert.Equal(0, Attacker.Run(() => Native.SetDacl(kept, $"D:P(A;OICI;FA;;;{Attacker.Sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")));
        Assert.Contains(Acls.Entries(quarantine), e => e.Contains(Attacker.Sid.Value, StringComparison.Ordinal));
        Assert.DoesNotContain(Acls.Entries(DataRoot), e => e.Contains(Attacker.Sid.Value, StringComparison.Ordinal));
        Assert.Equal("S-1-5-32-544", Acls.Owner(DataRoot));
        Assert.Throws<UnauthorizedAccessException>(() => Attacker.Run(() => File.WriteAllText(Path.Combine(DataRoot, "status.json"), "planted")));
    }

    [Fact]
    public void A_junction_the_attacker_planted_at_the_data_folder_is_deleted_as_a_link_and_nothing_is_written_where_it_leads()
    {
        Arrange();
        var bait = Path.Combine(_programData, "bait");
        _attackersItems.Add(bait);
        Attacker.Run(() =>
        {
            Directory.CreateDirectory(bait);
            Links.CreateJunction(DataRoot, bait);
        });

        using var store = Initialize();
        store.WriteFile("status.json", "{}"u8);

        Assert.Empty(DataFolderFixture.Names(bait));
        Assert.StartsWith($"{DataRoot} was a link", Assert.Single(store.Notices), StringComparison.Ordinal);
        Assert.Equal("S-1-5-32-544", Acls.Owner(DataRoot));
    }

    [Fact]
    public void A_folder_the_attacker_made_to_deny_SYSTEM_and_Administrators_everything_is_still_moved_aside()
    {
        Arrange();
        Attacker.Run(() =>
        {
            Directory.CreateDirectory(DataRoot);
            Acls.Reset(DataRoot, $"D:P(D;;FA;;;SY)(D;;FA;;;BA)(A;OICI;FA;;;{Attacker.Sid})");
        });

        using var store = Initialize();

        Assert.Single(Quarantines());
        Assert.Contains("cannot be read by this account (access is denied)", Assert.Single(store.Notices), StringComparison.Ordinal);
        Assert.Equal("S-1-5-32-544", Acls.Owner(DataRoot));
    }

    [Fact]
    public void An_attacker_holding_a_file_open_in_their_folder_stops_the_set_up_but_gains_nothing()
    {
        Arrange();
        var clock = new FakeTimeProvider();
        var held = Path.Combine(DataRoot, "held.txt");
        var holder = Attacker.Run(() =>
        {
            Directory.CreateDirectory(DataRoot);
            File.WriteAllText(held, "held");
            return new FileStream(held, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        });

        using (holder)
        {
            var e = Assert.Throws<SecureStoreException>(() => Waits.AdvanceUntilDone(clock, () => SecureStore.Initialize(Options() with { Time = clock }).Dispose()));

            Assert.Contains("so nothing was made in its place", e.Message, StringComparison.Ordinal);
            Assert.Equal(Attacker.Sid.Value, Acls.Owner(DataRoot));
            Assert.Empty(Quarantines());
            Assert.Empty(_events.Entries);
        }

        using var store = Initialize();
        Assert.Single(Quarantines());
        Assert.Equal("S-1-5-32-544", Acls.Owner(DataRoot));
    }

    [Fact]
    public void A_folder_the_attacker_makes_between_the_check_and_the_create_is_moved_aside()
    {
        Arrange();
        var raced = false;
        var hooks = new SecureStoreHooks
        {
            BeforeCreate = path =>
            {
                if (!raced && path == DataRoot)
                {
                    raced = true;
                    Attacker.Run(() => Directory.CreateDirectory(path));
                }
            },
        };

        using var store = SecureStore.Initialize(Options(), SecureStoreRules.Machine, hooks);

        Assert.True(raced);
        Assert.Single(Quarantines());
        Assert.Equal("S-1-5-32-544", Acls.Owner(DataRoot));
    }

    [Fact]
    public void The_attacker_can_change_nothing_in_the_data_folder_the_store_made()
    {
        Arrange();
        using var store = Initialize();
        store.WriteFile("status.json", "{}"u8);
        store.WriteFile(DataFolder.Config, "network.json", "{}"u8);

        foreach (var folder in DataFolderLayout.KeptFolderNames.Select(n => Path.Combine(DataRoot, n)).Prepend(DataRoot))
        {
            Assert.Throws<UnauthorizedAccessException>(() => Attacker.Run(() => File.WriteAllText(Path.Combine(folder, "planted.json"), "planted")));
            Assert.Throws<UnauthorizedAccessException>(() => Attacker.Run(() => Directory.CreateDirectory(Path.Combine(folder, "planted"))));
            Assert.NotEqual(0, Attacker.Run(() => NtFiles.MoveByPath(folder, folder + "-moved")));
        }

        Assert.Throws<UnauthorizedAccessException>(() => Attacker.Run(() => File.ReadAllText(Path.Combine(DataRoot, "status.json"))));
        Assert.Equal("{}", Attacker.Run(() => File.ReadAllText(Path.Combine(DataRoot, "config", "network.json"))));
        Assert.Throws<UnauthorizedAccessException>(() => Attacker.Run(() => File.WriteAllText(Path.Combine(DataRoot, "config", "network.json"), "planted")));
    }

    [Fact]
    public void The_attacker_cannot_reach_a_scratch_folder_or_plant_a_hard_link_in_the_data_folder()
    {
        Arrange();
        using var store = Initialize();
        using var scratch = store.CreateScratchFolder();
        scratch.WriteFile("secpol.inf", "[Unicode]"u8);
        var theirs = Path.Combine(_programData, "theirs.json");
        _attackersItems.Add(theirs);
        Attacker.Run(() => File.WriteAllText(theirs, "theirs"));

        Assert.Throws<UnauthorizedAccessException>(() => Attacker.Run(() => File.ReadAllText(scratch.PathOf("secpol.inf"))));
        Assert.Throws<UnauthorizedAccessException>(() => Attacker.Run(() => File.WriteAllText(scratch.PathOf("configure.inf"), "planted")));
        Assert.ThrowsAny<Exception>(() => Attacker.Run(() => Links.CreateHardLink(Path.Combine(DataRoot, "config", "network.json"), theirs)));
        Assert.Null(store.ReadFile(DataFolder.Config, "network.json", 1024));
    }

    [Fact]
    public void A_reparse_point_the_attacker_made_in_place_of_the_data_folder_is_deleted_as_itself()
    {
        Arrange();
        Attacker.Run(() =>
        {
            File.WriteAllText(DataRoot, "tagged");
            Links.MakeThirdPartyReparsePoint(DataRoot);
        });

        using var store = Initialize();

        Assert.StartsWith($"{DataRoot} was a link", Assert.Single(store.Notices), StringComparison.Ordinal);
        Assert.True(Directory.Exists(DataRoot));
    }

    [Fact]
    public void A_folder_the_attacker_marked_as_stored_online_only_is_moved_aside()
    {
        Arrange();
        Attacker.Run(() =>
        {
            Directory.CreateDirectory(DataRoot);
            File.SetAttributes(DataRoot, FileAttributes.Directory | FileAttributes.Offline);
        });

        using var store = Initialize();

        Assert.Single(Quarantines());
        Assert.Equal("S-1-5-32-544", Acls.Owner(DataRoot));
    }

    private void Arrange()
    {
        Assert.SkipUnless(Attacker.IsAvailable, Attacker.Unavailable);
        _programData = _tree.Folder("ProgramData", Descriptors.RealProgramData);
    }

    private SecureStore Initialize() => SecureStore.Initialize(Options());

    private SecureStoreOptions Options() => new() { ProgramDataPath = _programData, Registry = DataFolderFixture.Sealed(), EventLog = _events };

    private string[] Quarantines()
    {
        return Directory.Exists(_programData)
            ? [.. DataFolderFixture.Names(_programData).Where(DataFolderLayout.IsAsideName).Select(n => Path.Combine(_programData, n))]
            : [];
    }
}
