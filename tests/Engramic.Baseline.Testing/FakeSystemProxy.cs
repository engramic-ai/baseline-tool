using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Testing;

/// <summary>
/// The operating system's proxy settings in memory: a machine WinHTTP proxy, or none, and what a PAC file
/// answers. It records what it was asked, so a test can show which settings a choice consulted.
/// </summary>
public sealed class FakeSystemProxy : ISystemProxy
{
    private readonly List<(Uri Target, Uri? Script, TimeSpan Timeout)> _lookups = [];

    /// <summary>Gets or sets the machine's WinHTTP proxy; null for none.</summary>
    public MachineProxy? Machine { get; set; }

    /// <summary>Gets or sets what reading the machine's proxy throws; null to read it.</summary>
    public IOException? MachineError { get; set; }

    /// <summary>
    /// Gets or sets how a PAC file answers, given the address asked about and the file's address (null for
    /// WPAD). By default WPAD finds nothing and a named file cannot be downloaded.
    /// </summary>
    public Func<Uri, Uri?, Task<AutoProxyAnswer>> Answer { get; set; } = static (_, script) => Task.FromResult(
        script is null ? AutoProxyAnswer.NotFound("No PAC file was found.") : AutoProxyAnswer.Failed("The PAC file could not be downloaded."));

    /// <summary>Gets how many times the machine's proxy was read.</summary>
    public int MachineReads { get; private set; }

    /// <summary>Gets every PAC lookup, in order: the address asked about, the file's address and the time allowed.</summary>
    public IReadOnlyList<(Uri Target, Uri? Script, TimeSpan Timeout)> Lookups => _lookups;

    /// <summary>Makes a PAC file answer the same for every address.</summary>
    /// <param name="answer">The answer.</param>
    /// <returns>This fake.</returns>
    public FakeSystemProxy AnswerAlways(AutoProxyAnswer answer)
    {
        Answer = (_, _) => Task.FromResult(answer);
        return this;
    }

    /// <summary>Makes a PAC lookup never finish, as one blocked on the network would.</summary>
    /// <returns>This fake.</returns>
    public FakeSystemProxy NeverAnswer()
    {
        Answer = (_, _) => new TaskCompletionSource<AutoProxyAnswer>(TaskCreationOptions.RunContinuationsAsynchronously).Task;
        return this;
    }

    /// <inheritdoc/>
    public MachineProxy? ReadMachineProxy()
    {
        MachineReads++;
        return MachineError is null ? Machine : throw MachineError;
    }

    /// <inheritdoc/>
    public Task<AutoProxyAnswer> FindAutoProxyAsync(Uri target, Uri? scriptUrl, TimeSpan timeout)
    {
        _lookups.Add((target, scriptUrl, timeout));
        return Answer(target, scriptUrl);
    }
}
