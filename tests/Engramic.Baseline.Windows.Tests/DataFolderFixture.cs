using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;
using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// A ProgramData folder of a test's own, under the temp folder, with a data folder in it and its seal in a
/// registry in memory: never the real ProgramData folder or registry key.
/// </summary>
/// <remarks>
/// A test that is not elevated cannot make a folder owned by Administrators, so the folders here are owned
/// by the account running the tests, which <see cref="Trust"/> adds to the trusted accounts, and new files
/// take that account as their owner. The elevated tests use the product's rules instead.
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

    public TempTree Tree { get; } = new();

    public string ProgramData { get; }

    public string DataFolder { get; }

    public string StatusJson => Path.Combine(DataFolder, "status.json");

    public FakeRegistry Registry { get; set; } = Sealed();

    public TimeProvider Time { get; set; } = TimeProvider.System;

    public SecureStoreOptions Options => new() { ProgramDataPath = ProgramData, Registry = Registry, Time = Time };

    /// <summary>Gets the names in the data folder, in order.</summary>
    public string[] Entries => [.. Directory.GetFileSystemEntries(DataFolder).Select(e => Path.GetFileName(e)).Order(StringComparer.Ordinal)];

    /// <summary>A registry holding the installer's seal, as the install writes it.</summary>
    public static FakeRegistry Sealed(RegistryValue? seal = null)
    {
        return new FakeRegistry().Set(RegistryHive.LocalMachine, SecureStoreOptions.MachineSealKeyPath, SecureStoreOptions.MachineSealValueName, seal ?? RegistryValue.FromText("0.3.2"));
    }

    public SecureStore Open(SecureStoreHooks? hooks = null, DataFolderTrust? trust = null)
    {
        return SecureStore.Open(Options, trust ?? Trust, newFileOwner: null, hooks);
    }

    public void Dispose() => Tree.Dispose();
}
