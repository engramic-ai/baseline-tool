using System.Runtime.InteropServices;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// Checks real files' signatures: the .NET runtime's, embedded in each file; the Windows command processor's,
/// in a catalog of Windows; this test assembly, unsigned; and copies of them changed by one byte.
/// </summary>
public sealed class FileSignaturesTests
{
    /// <summary>TRUST_E_BAD_DIGEST: the file changed since it was signed.</summary>
    private const int BadDigest = unchecked((int)0x80096010);

    /// <summary>TRUST_E_NOSIGNATURE.</summary>
    private const int NoSignature = unchecked((int)0x800B0100);

    /// <summary>A small file of the .NET runtime, signed with a signature embedded in it.</summary>
    private static readonly string EmbeddedSigned = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Runtime.dll");

    /// <summary>A file of Windows, signed in a catalog of Windows rather than in the file.</summary>
    private static readonly string CatalogSigned = Path.Combine(Environment.SystemDirectory, "cmd.exe");

    [Fact]
    public void An_embedded_signature_is_valid_and_names_its_signer()
    {
        var signature = Verify(EmbeddedSigned);

        Assert.Equal(SignatureState.Valid, signature.State);
        Assert.False(signature.InCatalog);
        Assert.False(string.IsNullOrEmpty(signature.Signer));
        Assert.Equal(0, signature.Status);
    }

    [Fact]
    public void A_file_of_Windows_is_valid_through_its_catalog()
    {
        var signature = Verify(CatalogSigned);

        Assert.Equal(new FileSignature(SignatureState.Valid, "Microsoft Windows", InCatalog: true, Status: 0), signature);
    }

    [Fact]
    public void An_unsigned_file_is_not_signed()
    {
        var signature = Verify(typeof(FileSignaturesTests).Assembly.Location);

        Assert.Equal(new FileSignature(SignatureState.NotSigned, null, InCatalog: false, NoSignature), signature);
    }

    [Fact]
    public void A_changed_byte_breaks_an_embedded_signature()
    {
        using var tree = new TempTree();
        var copy = CopyWithOneByteChanged(EmbeddedSigned, tree.PathOf("changed.dll"));

        var signature = Verify(copy);

        Assert.Equal(new FileSignature(SignatureState.NotValid, null, InCatalog: false, BadDigest), signature);
    }

    [Fact]
    public void A_copy_of_a_file_of_Windows_is_valid_anywhere_and_a_changed_one_is_not_signed()
    {
        // A catalog holds the file's hash, not its place: the trusted runner must check where a tool is too.
        using var tree = new TempTree();
        var copy = tree.PathOf("cmd.exe");
        File.Copy(CatalogSigned, copy);
        var changed = CopyWithOneByteChanged(CatalogSigned, tree.PathOf("changed.exe"));

        Assert.Equal(new FileSignature(SignatureState.Valid, "Microsoft Windows", InCatalog: true, Status: 0), Verify(copy));
        Assert.Equal(SignatureState.NotSigned, Verify(changed).State);
    }

    [Fact]
    public void Checks_what_the_handle_holds_not_what_the_path_names()
    {
        // The handle is on the unsigned test assembly; the path given beside it names a signed file.
        using var file = File.OpenHandle(typeof(FileSignaturesTests).Assembly.Location);

        var signature = FileSignatures.Verify(file, EmbeddedSigned);

        Assert.Equal(SignatureState.NotSigned, signature.State);
    }

    private static FileSignature Verify(string path)
    {
        using var file = File.OpenHandle(path);
        return FileSignatures.Verify(file, path);
    }

    /// <summary>Copies a file with one byte a quarter of the way in changed: past the headers, before the signature, so its hash covers it.</summary>
    private static string CopyWithOneByteChanged(string source, string destination)
    {
        var bytes = File.ReadAllBytes(source);
        bytes[bytes.Length / 4] ^= 0xFF;
        File.WriteAllBytes(destination, bytes);
        return destination;
    }
}
