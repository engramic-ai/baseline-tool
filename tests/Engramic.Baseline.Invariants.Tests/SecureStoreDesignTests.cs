using System.Text.RegularExpressions;

namespace Engramic.Baseline.Invariants.Tests;

/// <summary>
/// How SecureStore walks paths, as decided in docs/DOTNET.md (spike 1): ProgramData is the one folder it
/// opens by its path, held for its attributes and permissions alone, and everything below it is opened one
/// name at a time, relative to the handle of a folder it holds, as itself. A second open by path would bring
/// back path parsing, and with it the links on the way that the relative opens never meet.
/// </summary>
public sealed partial class SecureStoreDesignTests
{
    private const string SecureStoreFile = "src/Engramic.Baseline.Windows/SecureStore.cs";

    [Fact]
    public void SecureStore_opens_only_ProgramData_by_its_path()
    {
        var calls = Code().Where(l => PathOpen().IsMatch(l)).ToList();

        Assert.True(calls.Count == 1, $"{SecureStoreFile} opens by path in {calls.Count} places; only OpenByPath, for ProgramData, may:\n" + string.Join('\n', calls));
    }

    [Fact]
    public void SecureStore_holds_ProgramData_with_no_right_that_sharing_checks_count()
    {
        // A handle that may read, write or delete ProgramData is subject to sharing, so a standard user, who may
        // write there, could keep the store out by holding ProgramData open without sharing it.
        var code = Code();
        var start = code.FindIndex(l => PathOpen().IsMatch(l));
        var call = string.Join('\n', code.Skip(start).TakeWhile(l => !l.TrimEnd().EndsWith(");", StringComparison.Ordinal)));

        Assert.Contains(code, l => l.Trim() == "private const uint ProgramDataRights = FileReadAttributes | ReadControl | Synchronize;");
        Assert.Contains("ProgramDataRights,", call, StringComparison.Ordinal);
    }

    [Fact]
    public void SecureStore_opens_everything_else_in_one_place_relative_to_a_folder_and_as_itself()
    {
        var code = Code();
        var calls = code.Where(l => RelativeOpen().IsMatch(l)).ToList();

        Assert.True(calls.Count == 1, $"{SecureStoreFile} calls the native open in {calls.Count} places; only OpenRelative may:\n" + string.Join('\n', calls));
        Assert.Contains(code, l => l.Contains("RootDirectory = (HANDLE)folder.DangerousGetHandle()", StringComparison.Ordinal));
        Assert.Contains(code, l => l.Contains("var always = NTCREATEFILE_CREATE_OPTIONS.FILE_OPEN_REPARSE_POINT", StringComparison.Ordinal));
    }

    [Fact]
    public void SecureStore_renames_only_relative_to_a_folder_it_holds()
    {
        var code = Code();

        Assert.Contains(code, l => l.Contains("information->RootDirectory = (HANDLE)folder.DangerousGetHandle();", StringComparison.Ordinal));
        Assert.DoesNotContain(code, l => l.Contains("FILE_RENAME_INFO ", StringComparison.Ordinal) || l.Contains("FileRenameInfo,", StringComparison.Ordinal));
    }

    /// <summary>The lines of SecureStore that are code, not comments.</summary>
    private static List<string> Code()
    {
        return [.. File.ReadAllLines(Repository.PathOf(SecureStoreFile)).Where(l => !l.TrimStart().StartsWith("//", StringComparison.Ordinal))];
    }

    [GeneratedRegex(@"\bPInvoke\.CreateFile\(")]
    private static partial Regex PathOpen();

    [GeneratedRegex(@"\bNtCreateFile\(")]
    private static partial Regex RelativeOpen();
}
