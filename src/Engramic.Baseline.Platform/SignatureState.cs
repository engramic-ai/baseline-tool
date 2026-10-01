namespace Engramic.Baseline.Platform;

/// <summary>The state of a file's Authenticode signature.</summary>
public enum SignatureState
{
    /// <summary>Signed, the file unchanged since, and the certificate chain trusted.</summary>
    Valid,

    /// <summary>No signature in the file, and its hash in no catalog of Windows.</summary>
    NotSigned,

    /// <summary>
    /// Signed, but the signature does not hold: the file changed since, the chain is not trusted, or the
    /// certificate is not valid for code signing.
    /// </summary>
    NotValid,
}
