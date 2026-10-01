using System.Diagnostics.CodeAnalysis;

namespace Engramic.Baseline.Platform;

/// <summary>
/// The addresses the service client may send a request to: https only, except plain http to this device,
/// for a development server. The rules of the PowerShell tool's Resolve-CEServiceUri.
/// </summary>
public static class ServiceUri
{
    /// <summary>The names of this device that plain http may reach, as the PowerShell tool lists them.</summary>
    private static readonly string[] ThisDevice = ["localhost", "127.0.0.1", "::1", "[::1]"];

    /// <summary>
    /// Joins a configured base address and a path, and checks the result may be used: https, or http to this
    /// device.
    /// </summary>
    /// <param name="baseUrl">The base address from config, such as https://baseline.engramic.ai; may be empty.</param>
    /// <param name="path">The path under it, such as v1/firmware/dell/0CF1.</param>
    /// <param name="uri">The address, when it may be used.</param>
    /// <param name="error">Why it may not be used, as the PowerShell tool words it; empty when it may.</param>
    /// <returns>True when the address may be used.</returns>
    public static bool TryResolve(string? baseUrl, string path, [NotNullWhen(true)] out Uri? uri, out string error)
    {
        ArgumentNullException.ThrowIfNull(path);
        uri = null;
        var trimmed = (baseUrl ?? string.Empty).Trim();
        if (trimmed.Length == 0)
        {
            error = "No base URL is configured";
            return false;
        }

        if (!Uri.TryCreate(trimmed.TrimEnd('/') + "/" + path.TrimStart('/'), UriKind.Absolute, out var joined))
        {
            error = "The base URL is not valid: " + trimmed;
            return false;
        }

        if (!IsAllowed(joined))
        {
            error = "The base URL must be https (http only for localhost): " + trimmed;
            return false;
        }

        uri = joined;
        error = string.Empty;
        return true;
    }

    /// <summary>Tells whether the service client may send a request to an address: https, or http to this device.</summary>
    /// <param name="uri">The address.</param>
    /// <returns>True when it may.</returns>
    public static bool IsAllowed(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        return uri.IsAbsoluteUri
            && (uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && IsThisDevice(uri)));
    }

    /// <summary>Tells whether an address names this device as the PowerShell tool recognises it: localhost, 127.0.0.1 or ::1.</summary>
    /// <param name="uri">The address.</param>
    /// <returns>True when it does.</returns>
    public static bool IsThisDevice(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        return uri.IsAbsoluteUri && ThisDevice.Contains(uri.Host, StringComparer.OrdinalIgnoreCase);
    }
}
