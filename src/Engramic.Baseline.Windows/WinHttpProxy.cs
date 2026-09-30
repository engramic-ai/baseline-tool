using System.Globalization;
using System.Runtime.InteropServices;
using Engramic.Baseline.Platform;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Networking.WinHttp;

namespace Engramic.Baseline.Windows;

/// <summary>
/// What WinHTTP says about proxies: the machine's WinHTTP proxy, and the proxy a PAC file names for an address.
/// </summary>
/// <remarks>
/// <para>
/// The machine's proxy is WinHttpGetDefaultProxyConfiguration's answer: the setting netsh winhttp set proxy
/// writes, which only an administrator can change. This process's environment and its account's Internet
/// settings play no part in it.
/// </para>
/// <para>
/// A PAC file is asked through WinHttpGetProxyForUrl, out of process only: the WinHTTP Web Proxy Auto-Discovery
/// service downloads and runs the script, so a script from the network never runs in this process, which may be
/// SYSTEM's. When that service cannot be used, the lookup fails rather than run the script here. With no PAC file
/// named, WPAD looks for one through DHCP and DNS. The server of a PAC file is never sent the Windows sign-in.
/// The lookup blocks, so it runs on a thread of its own, and its caller decides how long to wait.
/// </para>
/// </remarks>
public sealed class WinHttpProxy : ISystemProxy
{
    private const int ErrorTimeout = 12002;
    private const int ErrorInvalidUrl = 12005;
    private const int ErrorUnrecognisedScheme = 12006;
    private const int ErrorLoginFailure = 12015;
    private const int ErrorBadScript = 12166;
    private const int ErrorScriptDownload = 12167;
    private const int ErrorServiceError = 12178;
    private const int ErrorAutoDetectionFailed = 12180;

    /// <inheritdoc/>
    public unsafe MachineProxy? ReadMachineProxy()
    {
        var info = default(WINHTTP_PROXY_INFO);
        if (!PInvoke.WinHttpGetDefaultProxyConfiguration(&info))
        {
            throw new IOException(Failure("Windows did not say what the machine's WinHTTP proxy is", Marshal.GetLastPInvokeError()));
        }

        try
        {
            return info.dwAccessType == WINHTTP_ACCESS_TYPE.WINHTTP_ACCESS_TYPE_NAMED_PROXY && Text(info.lpszProxy) is { Length: > 0 } proxy
                ? new MachineProxy(proxy, Text(info.lpszProxyBypass) ?? string.Empty)
                : null;
        }
        finally
        {
            Free(info.lpszProxy);
            Free(info.lpszProxyBypass);
        }
    }

    /// <inheritdoc/>
    public Task<AutoProxyAnswer> FindAutoProxyAsync(Uri target, Uri? scriptUrl, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);
        var milliseconds = (int)Math.Min(Math.Ceiling(timeout.TotalMilliseconds), int.MaxValue);
        var url = target.AbsoluteUri;
        var script = scriptUrl?.AbsoluteUri;
        return Task.Factory.StartNew(
            () => Find(url, script, milliseconds),
            CancellationToken.None,
            TaskCreationOptions.LongRunning | TaskCreationOptions.DenyChildAttach,
            TaskScheduler.Default);
    }

    /// <summary>What a failed PAC lookup's WinHTTP error means, as the answer to give.</summary>
    internal static AutoProxyAnswer Answer(int error, bool named)
    {
        var code = string.Create(CultureInfo.InvariantCulture, $"(WinHTTP error {error})");
        return error switch
        {
            ErrorAutoDetectionFailed when !named => AutoProxyAnswer.NotFound($"Neither DHCP nor DNS named one {code}."),
            ErrorScriptDownload => AutoProxyAnswer.Failed($"It could not be downloaded {code}."),
            ErrorBadScript => AutoProxyAnswer.Failed($"Its script failed or gave no answer {code}."),
            ErrorServiceError => AutoProxyAnswer.Failed($"The WinHTTP Web Proxy Auto-Discovery service, which runs it outside this process, could not be used {code}."),
            ErrorLoginFailure => AutoProxyAnswer.Failed($"Its server asked for a sign-in, which it is never sent {code}."),
            ErrorTimeout => AutoProxyAnswer.Failed($"The lookup timed out {code}."),
            ErrorInvalidUrl or ErrorUnrecognisedScheme => AutoProxyAnswer.Failed($"WinHTTP did not accept the address {code}."),
            _ => AutoProxyAnswer.Failed($"The lookup failed {code}."),
        };
    }

    private static unsafe AutoProxyAnswer Find(string target, string? script, int milliseconds)
    {
        // A session of its own, with no proxy: it only asks, and never connects anywhere itself.
        var session = PInvoke.WinHttpOpen(ServiceClientOptions.DefaultUserAgent, WINHTTP_ACCESS_TYPE.WINHTTP_ACCESS_TYPE_NO_PROXY, null, null, 0);
        if (session is null)
        {
            return AutoProxyAnswer.Failed(Failure("WinHTTP could not be started", Marshal.GetLastPInvokeError()) + ".");
        }

        try
        {
            _ = PInvoke.WinHttpSetTimeouts(session, milliseconds, milliseconds, milliseconds, milliseconds);
            var info = default(WINHTTP_PROXY_INFO);
            bool found;
            int error;
            fixed (char* url = target)
            fixed (char* scriptUrl = script)
            {
                var options = new WINHTTP_AUTOPROXY_OPTIONS
                {
                    dwFlags = (script is null ? PInvoke.WINHTTP_AUTOPROXY_AUTO_DETECT : PInvoke.WINHTTP_AUTOPROXY_CONFIG_URL)
                        | PInvoke.WINHTTP_AUTOPROXY_RUN_OUTPROCESS_ONLY,
                    dwAutoDetectFlags = script is null ? PInvoke.WINHTTP_AUTO_DETECT_TYPE_DHCP | PInvoke.WINHTTP_AUTO_DETECT_TYPE_DNS_A : 0,
                    lpszAutoConfigUrl = scriptUrl,
                    fAutoLogonIfChallenged = false,
                };
                found = PInvoke.WinHttpGetProxyForUrl(session, url, &options, &info);
                error = Marshal.GetLastPInvokeError();
            }

            try
            {
                if (!found)
                {
                    return Answer(error, named: script is not null);
                }

                return info.dwAccessType == WINHTTP_ACCESS_TYPE.WINHTTP_ACCESS_TYPE_NAMED_PROXY && Text(info.lpszProxy) is { Length: > 0 } proxy
                    ? AutoProxyAnswer.UseProxy(proxy)
                    : AutoProxyAnswer.GoDirect();
            }
            finally
            {
                Free(info.lpszProxy);
                Free(info.lpszProxyBypass);
            }
        }
        finally
        {
            _ = PInvoke.WinHttpCloseHandle(session);
        }
    }

    private static unsafe string? Text(PWSTR text) => text.Value is null ? null : new string(text.Value);

    private static unsafe void Free(PWSTR text)
    {
        if (text.Value is not null)
        {
            _ = PInvoke.GlobalFree(new HGLOBAL(text.Value));
        }
    }

    private static string Failure(string what, int error)
    {
        return string.Create(CultureInfo.InvariantCulture, $"{what} (error {error}: {Marshal.GetPInvokeErrorMessage(error)})");
    }
}
