namespace Engramic.Baseline.Platform;

/// <summary>
/// What Windows says of a file's Authenticode signature, embedded in the file or in a catalog of Windows.
/// </summary>
/// <param name="State">Whether the signature is valid, missing or not valid.</param>
/// <param name="Signer">
/// The common name of the signing certificate's subject, such as Microsoft Windows, when the signature is
/// valid; otherwise null.
/// </param>
/// <param name="InCatalog">
/// Whether the signature is a catalog's, which covers the file's hash wherever the file is, rather than one
/// embedded in the file.
/// </param>
/// <param name="Status">The result Windows gave (an HRESULT, such as 0x800B0100 for no signature); 0 when valid.</param>
public sealed record FileSignature(SignatureState State, string? Signer, bool InCatalog, int Status);
