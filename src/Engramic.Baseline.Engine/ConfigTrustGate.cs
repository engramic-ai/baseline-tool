using Engramic.Baseline.Model;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Engine;

/// <summary>
/// The config trust gate: the config files a run reads, each the copy shipped inside the tool unless an
/// administrator's override of it passes every rule, as the PowerShell tool's Get-CEConfig judges one with
/// Get-CEDataPathProblem.
/// </summary>
/// <remarks>
/// <para>
/// An override is a whole file of the same name in the data folder's config folder, and it replaces the
/// shipped file whole. It is used only when all of these hold:
/// </para>
/// <list type="bullet">
/// <item>The run is elevated or SYSTEM. A run that is not reads no override: the data folder is for SYSTEM
/// and administrators.</item>
/// <item>The file ships with the tool and has a schema (<see cref="ConfigFile.Names"/>): only a file the tool
/// reads can be overridden.</item>
/// <item>SecureStore reads it through the handle of the config folder it holds, and checks it through the
/// file's own handle (<see cref="ISecureStore.ReadFile"/>): not a junction, symbolic link or other reparse
/// point, not stored online only, an ordinary file with one name, owned by SYSTEM, Administrators or
/// TrustedInstaller, with no right to change it for anyone else and no deny entry against them, and no longer
/// than <see cref="MaxOverrideLength"/>.</item>
/// <item>It meets its file's schema (<see cref="ConfigFile.FindProblem"/>).</item>
/// </list>
/// <para>
/// Otherwise the shipped file is used, and the refusal is one of <see cref="Notices"/>, naming the override
/// and why, for the run to log. Nothing is repaired or changed to get round a refusal. Each file is decided
/// the first time it is read, and every later read in the run gives the same bytes.
/// </para>
/// <para>
/// Safe to use from more than one thread: the data folder is read one file at a time, as SecureStore needs.
/// </para>
/// </remarks>
public sealed class ConfigTrustGate : IConfigFiles
{
    /// <summary>The most bytes an override may hold: 1 MiB, many times the largest shipped file.</summary>
    public const int MaxOverrideLength = 1024 * 1024;

    private readonly IConfigFiles _shipped;
    private readonly ISecureStore? _store;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, byte[]?> _decided = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _notices = [];
    private readonly List<string> _overrides = [];

    /// <summary>Makes the gate of a run.</summary>
    /// <param name="shipped">The config files that ship with the tool.</param>
    /// <param name="store">
    /// The data folder, opened and checked, whose config folder holds the overrides; null for a run that has none.
    /// It must stay open while the run reads config.
    /// </param>
    /// <param name="account">The account the run is: overrides are read only when it is elevated or SYSTEM.</param>
    public ConfigTrustGate(IConfigFiles shipped, ISecureStore? store, ProcessAccount account)
    {
        ArgumentNullException.ThrowIfNull(shipped);
        ArgumentNullException.ThrowIfNull(account);
        _shipped = shipped;
        _store = account.IsElevated ? store : null;
    }

    /// <summary>
    /// Gets why each override that is not used was refused, in the order the files were read: each names the
    /// file, says the shipped copy is used instead, and gives the reason.
    /// </summary>
    public IReadOnlyList<string> Notices
    {
        get
        {
            lock (_gate)
            {
                return [.. _notices];
            }
        }
    }

    /// <summary>Gets the full path of each override in use, in the order the files were read.</summary>
    public IReadOnlyList<string> Overrides
    {
        get
        {
            lock (_gate)
            {
                return [.. _overrides];
            }
        }
    }

    /// <inheritdoc/>
    /// <remarks>An administrator's override when one passes every rule, and otherwise the shipped file.</remarks>
    public byte[]? Read(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        lock (_gate)
        {
            if (!_decided.TryGetValue(name, out var content))
            {
                content = Decide(name);
                _decided.Add(name, content);
            }

            return content is null ? null : [.. content];
        }
    }

    private byte[]? Decide(string name)
    {
        var shipped = _shipped.Read(name);
        if (shipped is null || _store is null)
        {
            return shipped;
        }

        if (!ConfigFile.Names.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            // Every shipped file has a schema (ShippedConfigTests): this is for one that joined without it.
            _notices.Add($"Overrides of {name} are not read, and the shipped copy is used: this version has no schema to check one against.");
            return shipped;
        }

        var path = $@"{_store.RootPath}\{DataFolderLayout.NameOf(DataFolder.Config)}\{name}";

        byte[]? candidate;
        try
        {
            candidate = _store.ReadFile(DataFolder.Config, name, MaxOverrideLength);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return Refuse(name, e.Message, shipped);
        }

        if (candidate is null)
        {
            return shipped;
        }

        if (ConfigFile.FindProblem(name, path, candidate) is { } problem)
        {
            return Refuse(name, problem, shipped);
        }

        _overrides.Add(path);
        return candidate;
    }

    private byte[] Refuse(string name, string reason, byte[] shipped)
    {
        _notices.Add($"Ignoring the config override {name} and using the shipped copy: {reason}");
        return shipped;
    }
}
