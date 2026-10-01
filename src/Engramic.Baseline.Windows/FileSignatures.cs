using System.Security.Cryptography.X509Certificates;
using Engramic.Baseline.Platform;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security.Cryptography.Catalog;
using Windows.Win32.Security.WinTrust;

namespace Engramic.Baseline.Windows;

/// <summary>
/// Checks a file's Authenticode signature, as Get-AuthenticodeSignature does: one embedded in the file, or
/// else a catalog of Windows that holds the file's hash, as most files of Windows are signed.
/// </summary>
/// <remarks>
/// The file is read through the handle the caller opened on it (WinVerifyTrust and the catalog functions take
/// one), so what is checked is what the handle holds, even if its path now names something else. The path is
/// passed beside it only for Windows to choose how to read the file's format. Revocation is not checked and no
/// certificate is fetched from the network, so a check never waits on one; a revoked certificate that Windows has
/// already learned of still fails. A catalog signature covers the file's hash, not its place: a copy of a file of
/// Windows anywhere is valid, so a caller that trusts a file for where it is checks that too.
/// </remarks>
public static class FileSignatures
{
    /// <summary>TRUST_E_NOSIGNATURE: the file has no signature.</summary>
    private const int NoSignature = unchecked((int)0x800B0100);

    /// <summary>TRUST_E_SUBJECT_FORM_UNKNOWN: Windows has no way to sign a file of its kind, such as plain text.</summary>
    private const int UnknownForm = unchecked((int)0x800B0003);

    /// <summary>TRUST_E_PROVIDER_UNKNOWN: no provider for the file's kind.</summary>
    private const int UnknownProvider = unchecked((int)0x800B0001);

    /// <summary>INVALID_HANDLE_VALUE as the window: never show anything to anyone.</summary>
    private static readonly HWND NoWindow = (HWND)(nint)(-1);

    /// <summary>Checks the Authenticode signature of a file.</summary>
    /// <param name="file">A handle open on the file with read access.</param>
    /// <param name="path">The file's path, which tells Windows its format; it is not opened.</param>
    /// <returns>What Windows says of the signature.</returns>
    public static FileSignature Verify(SafeFileHandle file, string path)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentException.ThrowIfNullOrEmpty(path);
        var embedded = VerifyEmbedded(file, path);
        return embedded.State == SignatureState.NotSigned ? VerifyInCatalog(file, path) ?? embedded : embedded;
    }

    private static unsafe FileSignature VerifyEmbedded(SafeFileHandle file, string path)
    {
        var added = false;
        try
        {
            file.DangerousAddRef(ref added);
            fixed (char* name = path)
            {
                var info = new WINTRUST_FILE_INFO
                {
                    cbStruct = (uint)sizeof(WINTRUST_FILE_INFO),
                    pcwszFilePath = name,
                    hFile = (HANDLE)file.DangerousGetHandle(),
                };
                var data = NewTrustData(WINTRUST_DATA_UNION_CHOICE.WTD_CHOICE_FILE);
                data.Anonymous.pFile = &info;
                return Run(&data, inCatalog: false);
            }
        }
        finally
        {
            if (added)
            {
                file.DangerousRelease();
            }
        }
    }

    /// <summary>Checks the file against the catalogs of Windows, by its SHA-256 hash and then its SHA-1 hash; null when no catalog holds it.</summary>
    private static FileSignature? VerifyInCatalog(SafeFileHandle file, string path)
    {
        return VerifyInCatalog(file, path, PInvoke.BCRYPT_SHA256_ALGORITHM) ?? VerifyInCatalog(file, path, null);
    }

    private static unsafe FileSignature? VerifyInCatalog(SafeFileHandle file, string path, string? hashAlgorithm)
    {
        if (!PInvoke.CryptCATAdminAcquireContext2(out var admin, null, hashAlgorithm, null))
        {
            return null;
        }

        try
        {
            uint size = 0;
            _ = PInvoke.CryptCATAdminCalcHashFromFileHandle2(admin, file, ref size, default);
            if (size == 0)
            {
                return null;
            }

            var hash = new byte[size];
            if (!PInvoke.CryptCATAdminCalcHashFromFileHandle2(admin, file, ref size, hash))
            {
                return null;
            }

            var catalog = PInvoke.CryptCATAdminEnumCatalogFromHash(admin, hash);
            if (catalog == 0)
            {
                return null;
            }

            try
            {
                var catalogInfo = new CATALOG_INFO { cbStruct = (uint)sizeof(CATALOG_INFO) };
                if (!PInvoke.CryptCATCatalogInfoFromContext(catalog, ref catalogInfo, 0))
                {
                    return null;
                }

                var added = false;
                try
                {
                    file.DangerousAddRef(ref added);

                    // A catalog names its members by their hash, in upper-case hexadecimal.
                    var tag = Convert.ToHexString(hash);
                    fixed (char* catalogPath = catalogInfo.wszCatalogFile.AsSpan())
                    fixed (char* member = tag)
                    fixed (char* name = path)
                    fixed (byte* digest = hash)
                    {
                        var info = new WINTRUST_CATALOG_INFO
                        {
                            cbStruct = (uint)sizeof(WINTRUST_CATALOG_INFO),
                            pcwszCatalogFilePath = catalogPath,
                            pcwszMemberTag = member,
                            pcwszMemberFilePath = name,
                            hMemberFile = (HANDLE)file.DangerousGetHandle(),
                            pbCalculatedFileHash = digest,
                            cbCalculatedFileHash = (uint)hash.Length,
                            hCatAdmin = admin,
                        };
                        var data = NewTrustData(WINTRUST_DATA_UNION_CHOICE.WTD_CHOICE_CATALOG);
                        data.Anonymous.pCatalog = &info;
                        return Run(&data, inCatalog: true);
                    }
                }
                finally
                {
                    if (added)
                    {
                        file.DangerousRelease();
                    }
                }
            }
            finally
            {
                _ = PInvoke.CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
            }
        }
        finally
        {
            _ = PInvoke.CryptCATAdminReleaseContext(admin, 0);
        }
    }

    private static unsafe WINTRUST_DATA NewTrustData(WINTRUST_DATA_UNION_CHOICE choice)
    {
        return new WINTRUST_DATA
        {
            cbStruct = (uint)sizeof(WINTRUST_DATA),
            dwUIChoice = WINTRUST_DATA_UICHOICE.WTD_UI_NONE,
            fdwRevocationChecks = WINTRUST_DATA_REVOCATION_CHECKS.WTD_REVOKE_NONE,
            dwUnionChoice = choice,
            dwStateAction = WINTRUST_DATA_STATE_ACTION.WTD_STATEACTION_VERIFY,
            dwProvFlags = WINTRUST_DATA_PROVIDER_FLAGS.WTD_CACHE_ONLY_URL_RETRIEVAL,
        };
    }

    /// <summary>Asks WinVerifyTrust, reads the signer when the signature is valid, and closes what it kept.</summary>
    private static unsafe FileSignature Run(WINTRUST_DATA* data, bool inCatalog)
    {
        var action = PInvoke.WINTRUST_ACTION_GENERIC_VERIFY_V2;
        var status = PInvoke.WinVerifyTrust(NoWindow, &action, data);
        try
        {
            if (status != 0)
            {
                var state = status is NoSignature or UnknownForm or UnknownProvider ? SignatureState.NotSigned : SignatureState.NotValid;
                return new FileSignature(state, null, inCatalog, status);
            }

            return new FileSignature(SignatureState.Valid, ReadSigner(data->hWVTStateData), inCatalog, 0);
        }
        finally
        {
            data->dwStateAction = WINTRUST_DATA_STATE_ACTION.WTD_STATEACTION_CLOSE;
            _ = PInvoke.WinVerifyTrust(NoWindow, &action, data);
        }
    }

    /// <summary>Reads the common name of the signing certificate from what WinVerifyTrust kept, or null.</summary>
    private static unsafe string? ReadSigner(HANDLE state)
    {
        var provider = PInvoke.WTHelperProvDataFromStateData(state);
        if (provider is null)
        {
            return null;
        }

        var signer = PInvoke.WTHelperGetProvSignerFromChain(provider, 0, false, 0);
        if (signer is null || signer->csCertChain == 0 || signer->pasCertChain is null || signer->pasCertChain[0].pCert is null)
        {
            return null;
        }

        var certificate = signer->pasCertChain[0].pCert;
        using var leaf = X509CertificateLoader.LoadCertificate(new ReadOnlySpan<byte>(certificate->pbCertEncoded, (int)certificate->cbCertEncoded));
        var name = leaf.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        return name.Length == 0 ? null : name;
    }
}
