namespace Engramic.Baseline.Platform;

/// <summary>
/// What came back from one request of the service client: a response, or why there was none. Returned rather
/// than thrown, as the PowerShell tool's Invoke-CEHttpRequest does.
/// </summary>
public sealed record ServiceResponse
{
    /// <summary>Gets the HTTP status code, or 0 when there was no response that could be used.</summary>
    public int StatusCode { get; init; }

    /// <summary>Gets the response body, as sent: bytes, not decoded. Empty when there was none.</summary>
    public ReadOnlyMemory<byte> Body { get; init; }

    /// <summary>Gets the response's ETag, or empty when it had none.</summary>
    public string ETag { get; init; } = string.Empty;

    /// <summary>Gets why the request failed, as a sentence ending with a hint about proxies; empty when it did not.</summary>
    public string Error { get; init; } = string.Empty;

    /// <summary>Gets how the request was sent, or null when it was refused before a route was chosen.</summary>
    public ProxyRoute? Route { get; init; }

    /// <summary>Gets whether a response came back: no error, whatever its status code.</summary>
    public bool Succeeded => Error.Length == 0;
}
