namespace Engramic.Baseline.Platform;

/// <summary>
/// What the operating system says about proxies: the machine's WinHTTP proxy, and the proxy a PAC file names
/// for an address. The service client asks it, through <see cref="ProxyChooser"/>, and never uses the
/// platform's default proxy.
/// </summary>
/// <remarks>
/// Engramic.Baseline.Windows implements it with WinHTTP (WinHttpProxy); Engramic.Baseline.Testing has a fake.
/// </remarks>
public interface ISystemProxy
{
    /// <summary>Reads the machine's WinHTTP proxy, which only an administrator can set (netsh winhttp set proxy).</summary>
    /// <returns>The setting, or null when none is set, which means direct access.</returns>
    /// <exception cref="IOException">It could not be read.</exception>
    MachineProxy? ReadMachineProxy();

    /// <summary>
    /// Asks a PAC file which proxy to use for an address: the file at <paramref name="scriptUrl"/>, or the one
    /// WPAD finds on the local network when it is null.
    /// </summary>
    /// <remarks>
    /// Returns at once: the lookup runs on another thread and cannot be cancelled, so the caller decides how
    /// long to wait for it. It never fails with an exception; a lookup that goes wrong answers why.
    /// </remarks>
    /// <param name="target">The address, as the PAC file is to see it.</param>
    /// <param name="scriptUrl">The PAC file's address, or null to find one with WPAD.</param>
    /// <param name="timeout">How long each download and each step of the lookup may take.</param>
    /// <returns>What the PAC file said, or why there was no answer.</returns>
    Task<AutoProxyAnswer> FindAutoProxyAsync(Uri target, Uri? scriptUrl, TimeSpan timeout);
}
