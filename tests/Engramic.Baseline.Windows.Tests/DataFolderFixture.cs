using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;
using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// A ProgramData folder of a test's own, under the temp folder, with a data folder in it, its seal in a
/// registry in memory and an event log in memory: never the real ProgramData folder, registry key or log.
/// </summary>
/// <remarks>
/// A test that is not elevated cannot make a folder owned by Administrators, so the folders here are owned
/// by the account running the tests, which <see cref="Trust"/> adds to the trusted accounts, and what the
/// store creates takes that account as its owner and grants it full control beside SYSTEM and
/// Administrators (<see cref="Rules"/>). The elevated tests use the product's rules instead.
/// </remarks>
internal sealed class DataFolderFixture : IDisposable
{
    public DataFolderFixture(bool withDataFolder = true, string? dataFolderAccess = null)
    {
        ProgramData = Tree.Folder("ProgramData");
        DataFolder = Path.Combine(ProgramData, SecureStore.DataFolderName);
        if (withDataFolder)
        {
            Tree.Folder(Path.Combine("ProgramData", SecureStore.DataFolderName), dataFolderAccess);
        }
    }

    /// <summary>Gets the trust rules of these tests: the product's, and the account running the tests.</summary>
    public static DataFolderTrust Trust { get; } = new([Sid.LocalSystem, Sid.Administrators, Sid.TrustedInstaller, Elevation.CurrentUser]);

    /// <summary>
    /// Gets the store's rules for these tests: <see cref="Trust"/>, the process's own default owner, and full
    /// control for SYSTEM, Administrators and the account running the tests.
    /// </summary>
    public static SecureStoreRules Rules { get; } = new(Trust, Owner: null, Elevation.FullControl);

    public TempTree Tree { get; } = new();

    public string ProgramData { get; }

    public string DataFolder { get; }

    public string StatusJson => Path.Combine(DataFolder, "status.json");

    public FakeRegistry Registry { get; set; } = Sealed();

    public FakeEventLog Events { get; } = new();

    public TimeProvider Time { get; set; } = TimeProvider.System;

    public SecureStoreOptions Options => new() { ProgramDataPath = ProgramData, Registry = Registry, EventLog = Events, Time = Time };

    /// <summary>Gets the names in the data folder, in order.</summary>
    public string[] Entries => Names(DataFolder);

    /// <summary>Gets the names in the fixture's ProgramData folder, in order: the data folder and anything moved aside.</summary>
    public string[] ProgramDataEntries => Names(ProgramData);

    /// <summary>Gets the paths of the items moved aside into the fixture's ProgramData folder, in order.</summary>
    public string[] Quarantines => [.. ProgramDataEntries.Where(DataFolderLayout.IsAsideName).Select(n => Path.Combine(ProgramData, n))];

    /// <summary>A registry holding the installer's seal, as the install writes it.</summary>
    public static FakeRegistry Sealed(RegistryValue? seal = null)
    {
        return new FakeRegistry().Set(RegistryHive.LocalMachine, SecureStoreOptions.MachineSealKeyPath, SecureStoreOptions.MachineSealValueName, seal ?? RegistryValue.FromText("0.3.2"));
    }

    /// <summary>Gets the names in a folder, in order.</summary>
    public static string[] Names(string folder) => [.. Directory.GetFileSystemEntries(folder).Select(e => Path.GetFileName(e)).Order(StringComparer.Ordinal)];

    public SecureStore Open(SecureStoreHooks? hooks = null, DataFolderTrust? trust = null)
    {
        return SecureStore.Open(Options, trust is null ? Rules : Rules with { Trust = trust }, hooks);
    }

    public SecureStore Initialize(SecureStoreHooks? hooks = null)
    {
        return SecureStore.Initialize(Options, Rules, hooks);
    }

    public ReadOnlySecureStore? OpenReadOnly(SecureStoreHooks? hooks = null)
    {
        return SecureStore.OpenReadOnly(Options, Rules, hooks);
    }

    /// <summary>Gets everything in the fixture's ProgramData folder, name for name and byte for byte (<see cref="TreeSnapshot"/>).</summary>
    public string[] Snapshot => TreeSnapshot.Of(ProgramData);

    public void Dispose() => Tree.Dispose();
}
