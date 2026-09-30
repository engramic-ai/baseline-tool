namespace Engramic.Baseline.Platform;

/// <summary>
/// One GET request for the service client: the address, the ETag of a copy already held, and how long and how
/// large the response may be.
/// </summary>
/// <remarks>The limits are the PowerShell tool's: 1 to 600 seconds, and 1 KB to 16 MB.</remarks>
public sealed record ServiceRequest
{
    /// <summary>The largest response by default, in bytes: 64 KB.</summary>
    public const int DefaultMaxBytes = 65_536;

    /// <summary>The smallest limit a request may set, in bytes: 1 KB.</summary>
    public const int SmallestMaxBytes = 1_024;

    /// <summary>The largest limit a request may set, in bytes: 16 MB.</summary>
    public const int LargestMaxBytes = 16_777_216;

    private readonly TimeSpan _timeout = DefaultTimeout;
    private readonly int _maxBytes = DefaultMaxBytes;

    /// <summary>Makes a request for an address.</summary>
    /// <param name="uri">The absolute address. The service client refuses one that is not https, or http to this device.</param>
    /// <exception cref="ArgumentException"><paramref name="uri"/> is not absolute.</exception>
    public ServiceRequest(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!uri.IsAbsoluteUri)
        {
            throw new ArgumentException("A service request needs an absolute address.", nameof(uri));
        }

        Uri = uri;
    }

    /// <summary>Gets how long a request may take by default: 20 seconds.</summary>
    public static TimeSpan DefaultTimeout { get; } = TimeSpan.FromSeconds(20);

    /// <summary>Gets the shortest time a request may be given: 1 second.</summary>
    public static TimeSpan ShortestTimeout { get; } = TimeSpan.FromSeconds(1);

    /// <summary>Gets the longest time a request may be given: 600 seconds.</summary>
    public static TimeSpan LongestTimeout { get; } = TimeSpan.FromSeconds(600);

    /// <summary>Gets the address.</summary>
    public Uri Uri { get; }

    /// <summary>Gets the ETag of the copy already held, sent as If-None-Match; null or empty for none.</summary>
    public string? ETag { get; init; }

    /// <summary>Gets how long the request may take, from connecting to the last byte of the response.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not between 1 and 600 seconds.</exception>
    public TimeSpan Timeout
    {
        get => _timeout;
        init => _timeout = value >= ShortestTimeout && value <= LongestTimeout
            ? value
            : throw new ArgumentOutOfRangeException(nameof(value), value, "A service request may take between 1 and 600 seconds.");
    }

    /// <summary>Gets the largest response body accepted, in bytes; a larger one fails the request.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not between 1 KB and 16 MB.</exception>
    public int MaxBytes
    {
        get => _maxBytes;
        init => _maxBytes = value is >= SmallestMaxBytes and <= LargestMaxBytes
            ? value
            : throw new ArgumentOutOfRangeException(nameof(value), value, "A service response may be limited to between 1024 and 16777216 bytes.");
    }
}
