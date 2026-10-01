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
/// file's own handle (<see cref="IDataFolderReader.ReadFile"/>): not a junction, symbolic link or other reparse
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
/// An override that could not be opened or read at all is not refused: nothing about it was judged, and what
/// it holds is not known. A standard user, who may only read the config folder and what is in it, can bring
/// that about for as long as they like by locking part of the file or holding an oplock on it. A process that
/// may write to the file or the folder can also do it by holding either open without sharing; Windows ignores
/// that refusal from a holder who may only read. So falling back to the shipped copy would let them undo an
/// administrator's override without a trace. Instead every read of that file in the run throws, so each check
/// that needs it reports an Error finding, and the notice says why.
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
    private readonly IDataFolderReader? _store;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, Decision> _decided = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _notices = [];
    private readonly List<string> _overrides = [];

    /// <summary>Makes the gate of a run.</summary>
    /// <param name="shipped">The config files that ship with the tool.</param>
    /// <param name="store">
    /// The data folder, opened and checked, whose config folder holds the overrides: SecureStore for the scheduled
    /// audit, or a read-only one for a run that changes nothing; null for a run that has none. It must stay open
    /// while the run reads config.
    /// </param>
    /// <param name="account">The account the run is: overrides are read only when it is elevated or SYSTEM.</param>
    public ConfigTrustGate(IConfigFiles shipped, IDataFolderReader? store, ProcessAccount account)
    {
        ArgumentNullException.ThrowIfNull(shipped);
        ArgumentNullException.ThrowIfNull(account);
        _shipped = shipped;
        _store = account.IsElevated ? store : null;
    }

    /// <summary>
    /// Gets why each override that is not used was refused, or could not be read, in the order the files were
    /// read: each names the file, says what is used instead, and gives the reason.
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
    /// <exception cref="IOException">
    /// There is an override of the file, but it could not be opened or read (<see cref="SecureStoreException.IsUnavailable"/>),
    /// so neither it nor the shipped copy is given. Every read of the file in the run throws the same.
    /// </exception>
    public byte[]? Read(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        lock (_gate)
        {
            if (!_decided.TryGetValue(name, out var decision))
            {
                decision = Decide(name);
                _decided.Add(name, decision);
            }

            if (decision.Unreadable is { } reason)
            {
                throw new IOException(reason);
            }

            return decision.Content is null ? null : [.. decision.Content];
        }
    }

    private Decision Decide(string name)
    {
        var shipped = _shipped.Read(name);
        if (shipped is null || _store is null)
        {
            return new Decision(shipped);
        }

        if (!ConfigFile.Names.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            // Every shipped file has a schema (ShippedConfigTests): this is for one that joined without it.
            _notices.Add($"Overrides of {name} are not read, and the shipped copy is used: this version has no schema to check one against.");
            return new Decision(shipped);
        }

        var path = $@"{_store.RootPath}\{DataFolderLayout.NameOf(DataFolder.Config)}\{name}";

        byte[]? candidate;
        try
        {
            candidate = _store.ReadFile(DataFolder.Config, name, MaxOverrideLength);
        }
        catch (SecureStoreException e) when (!e.IsUnavailable)
        {
            return Refuse(name, e.Message, shipped);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Not judged, only not read: anything else would let whoever held it up choose the shipped copy.
            _notices.Add($"Could not read the config override {name}, so the checks that read it report an error and the shipped copy is not used in its place: {e.Message}");
            return new Decision(null, $"The config override {path} could not be read, so the shipped copy is not used in its place: {e.Message}");
        }

        if (candidate is null)
        {
            return new Decision(shipped);
        }

        string? problem;
        try
        {
            problem = ConfigFile.FindProblem(name, path, candidate);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // FindProblem gives every problem it knows as a sentence; this is for one it did not foresee.
            problem = $"{path} could not be checked against its schema: {e.Message}";
        }

        if (problem is not null)
        {
            return Refuse(name, problem, shipped);
        }

        _overrides.Add(path);
        return new Decision(candidate);
    }

    private Decision Refuse(string name, string reason, byte[] shipped)
    {
        _notices.Add($"Ignoring the config override {name} and using the shipped copy: {reason}");
        return new Decision(shipped);
    }

    /// <summary>What the run reads for one file: its bytes, or why it cannot be read at all.</summary>
    private sealed record Decision(byte[]? Content, string? Unreadable = null);
}
