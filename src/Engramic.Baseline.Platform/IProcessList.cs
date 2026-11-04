namespace Engramic.Baseline.Platform;

/// <summary>
/// The process list primitive: the processes running on this device, with their owner and elevation read
/// from their access tokens, never from WMI.
/// </summary>
/// <remarks>Engramic.Baseline.Windows implements it. Nothing is started, and nothing is changed.</remarks>
public interface IProcessList
{
    /// <summary>Reads the processes running now, apart from the idle process.</summary>
    /// <returns>One entry for each process, in the order of the process table.</returns>
    /// <exception cref="IOException">The process table could not be read.</exception>
    IReadOnlyList<RunningProcess> Read();
}
