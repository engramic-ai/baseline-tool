using System.Text.Json;
using System.Text.RegularExpressions;

namespace Engramic.Baseline.Invariants.Tests;

/// <summary>
/// Native code must not become a way round the banned APIs. Product code reaches Win32 only through the
/// functions CsWin32 generates in Engramic.Baseline.Windows from NativeMethods.txt, and a Win32 function
/// that does what a banned API does (open a file by path, touch the registry, start a process, set a
/// security descriptor, read the environment, load a library) is held to the same exemption rules as
/// the banned API: used only in a file that src/BannedApiExemptions.txt names, and only inside a
/// commented "#pragma warning disable RS0030" region.
/// </summary>
/// <remarks>
/// The analyser cannot ban these functions itself: CsWin32's own generated overloads call one another,
/// and RS0030 would fail the generated code. So the rule is enforced here, on the source text.
/// </remarks>
public sealed partial class NativeCodeTests
{
    private const string WindowsProject = "src/Engramic.Baseline.Windows";
    private const string NativeMethodsFile = WindowsProject + "/NativeMethods.txt";

    /// <summary>
    /// Win32 functions that do what src/BannedSymbols.txt bans in .NET, matched against the names in
    /// NativeMethods.txt (with or without the A or W suffix).
    /// </summary>
    private static readonly (string Why, Regex Names)[] Sensitive =
    [
        ("opens, creates, copies, moves or deletes a file or folder by path",
            Names(@"(Nt|Zw)?(Create|Open|ReOpen)File(2|Transacted|ById)?", @"(Copy|Move|Delete|Replace)File\w*", @"(Nt|Zw)DeleteFile",
                @"(Create|Remove)Directory\w*", @"SHCreateDirectory\w*", @"SHFileOperation", @"Create(Symbolic|Hard)Link\w*",
                @"FindFirstFile\w*", @"(Get|Set)FileAttributes\w*")),
        // Through a handle, but a rename names where the file goes, and SetFileInformationByHandle reads a
        // relative name against the current directory: a move by path in all but name.
        ("renames or deletes an open file, moving it to a path it names",
            Names(@"SetFileInformationByHandle", @"(Nt|Zw)SetInformationFile")),
        ("uses the shared temp folder", Names(@"GetTemp(Path2?|FileName)")),
        ("reads or writes the registry",
            Names(@"Reg[A-Z]\w*", @"(Nt|Zw)\w*Key(Ex)?", @"SH(Reg\w+|(Get|Set|Delete|Query)Value\w*|(Delete|Copy|Enum)(Empty)?Key\w*|OpenRegStream\w*)")),
        ("starts a process", Names(@"CreateProcess\w*", @"ShellExecute\w*", @"WinExec", @"(Nt|Rtl)Create(User)?Process\w*")),
        ("sets a security descriptor or an owner",
            Names(@"(TreeSet|TreeReset|Set)(Named)?SecurityInfo\w*", @"Set\w*ObjectSecurity\w*", @"SetFileSecurity", @"(Nt|Zw)SetSecurityObject")),
        // The known-folder API builds some folders from the process environment: ProgramData is
        // %SystemDrive%\ProgramData, so a process started with SystemDrive changed is told another folder.
        ("reads or sets environment variables, or answers from them",
            Names(@"(Get|Set)EnvironmentVariable", @"(Get|Set|Free)EnvironmentStrings\w*", @"ExpandEnvironmentStrings\w*",
                @"SHGetKnownFolder\w*", @"SHGetFolderPath\w*", @"SHGetSpecialFolder\w*")),
        ("loads a library or finds a function by name",
            Names(@"LoadLibrary\w*", @"LoadPackagedLibrary", @"GetProcAddress", @"Ldr(LoadDll|GetProcedureAddress\w*)")),
        ("creates a COM object, which can do any of the above",
            Names(@"CoCreateInstance\w*", @"CoGetClassObject", @"CoGetObject")),
    ];

    [Fact]
    public void Hand_written_code_declares_and_loads_no_native_code()
    {
        var offenders = SourceFiles()
            .SelectMany(f => f.Lines.Select((line, i) => (f.Path, Line: i + 1, Text: line)))
            .Where(l => HandWrittenInterop().IsMatch(l.Text))
            .Select(l => $"{l.Path}({l.Line}): {l.Text.Trim()}")
            .ToList();

        Assert.True(offenders.Count == 0, $"Reach Win32 through the functions CsWin32 generates from {NativeMethodsFile}, not by declaring or loading native code:\n" + string.Join('\n', offenders));
    }

    [Fact]
    public void Only_the_Windows_library_generates_native_calls_and_keeps_them_internal()
    {
        var problems = new List<string>();
        foreach (var file in Repository.FilesUnder("src", "NativeMethods.*"))
        {
            var path = Repository.RelativePathOf(file);
            if (!path.StartsWith(WindowsProject + "/", StringComparison.Ordinal))
            {
                problems.Add($"{path}: only {WindowsProject} generates native calls");
            }
        }

        foreach (var file in Repository.FilesUnder("src", "*.csproj").Append(Repository.PathOf("src/Directory.Build.props")))
        {
            var path = Repository.RelativePathOf(file);
            if (File.ReadAllText(file).Contains("Microsoft.Windows.CsWin32", StringComparison.Ordinal) && !path.StartsWith(WindowsProject + "/", StringComparison.Ordinal))
            {
                problems.Add($"{path}: only {WindowsProject} references CsWin32");
            }
        }

        // Public generated code would let every other assembly call Win32 directly.
        using var options = JsonDocument.Parse(File.ReadAllText(Repository.PathOf(WindowsProject + "/NativeMethods.json")));
        if (!options.RootElement.TryGetProperty("public", out var isPublic) || isPublic.ValueKind != JsonValueKind.False)
        {
            problems.Add($"{WindowsProject}/NativeMethods.json: set \"public\": false, so the generated functions stay internal");
        }

        Assert.True(problems.Count == 0, string.Join('\n', problems));
    }

    [Fact]
    public void NativeMethods_txt_names_each_function_or_type_on_its_own()
    {
        // A wildcard, a module or a namespace would generate functions that no one reviewed by name.
        var bad = NativeMethodEntries().Where(e => !PlainName().IsMatch(e)).ToList();

        Assert.True(bad.Count == 0, $"{NativeMethodsFile} may list plain names only, one per line:\n" + string.Join('\n', bad));
    }

    [Fact]
    public void A_sensitive_Win32_function_is_used_only_where_a_banned_API_could_be()
    {
        var files = SourceFiles().ToList();
        var problems = new List<string>();
        foreach (var entry in NativeMethodEntries())
        {
            var why = WhySensitive(entry);
            if (why is null)
            {
                continue;
            }

            var mention = new Regex(@"\b(" + string.Join('|', NamesFor(entry).Select(Regex.Escape)) + @")\b", RegexOptions.CultureInvariant);
            var uses = 0;
            foreach (var file in files)
            {
                var exemptFile = BannedList.Exemptions.ContainsKey(file.Path);
                var exemptLines = BannedApiPragmas.ExemptLines(file.Lines);
                for (var i = 0; i < file.Lines.Count; i++)
                {
                    if (!mention.IsMatch(file.Lines[i]))
                    {
                        continue;
                    }

                    uses++;
                    if (!exemptFile)
                    {
                        problems.Add($"{file.Path}({i + 1}): {entry} {why}; only a file that src/BannedApiExemptions.txt names may use it");
                    }
                    else if (!exemptLines[i])
                    {
                        problems.Add($"{file.Path}({i + 1}): {entry} {why}; name it only between \"#pragma warning disable RS0030 // <reason>\" and its restore");
                    }
                }
            }

            if (uses == 0)
            {
                problems.Add($"{NativeMethodsFile}: {entry} {why}, and no exempt file uses it; take it off the list");
            }
        }

        Assert.True(problems.Count == 0, string.Join('\n', problems));
    }

    [Theory]
    [InlineData("CreateFile")]
    [InlineData("CreateFileW")]
    [InlineData("NtCreateFile")]
    [InlineData("CreateDirectory")]
    [InlineData("MoveFileEx")]
    [InlineData("SetFileInformationByHandle")]
    [InlineData("NtSetInformationFile")]
    [InlineData("ZwSetInformationFile")]
    [InlineData("GetTempPath2")]
    [InlineData("RegOpenKeyEx")]
    [InlineData("RegSetValueExW")]
    [InlineData("NtSetValueKey")]
    [InlineData("CreateProcess")]
    [InlineData("CreateProcessAsUser")]
    [InlineData("ShellExecuteEx")]
    [InlineData("SetNamedSecurityInfo")]
    [InlineData("SetKernelObjectSecurity")]
    [InlineData("GetEnvironmentVariableW")]
    [InlineData("ExpandEnvironmentStrings")]
    [InlineData("SHGetKnownFolderPath")]
    [InlineData("SHGetKnownFolderIDList")]
    [InlineData("SHGetFolderPathW")]
    [InlineData("SHGetSpecialFolderPath")]
    [InlineData("LoadLibraryEx")]
    [InlineData("GetProcAddress")]
    [InlineData("CoCreateInstance")]
    public void The_sensitive_list_holds_the_functions_that_do_what_a_banned_API_does(string name)
    {
        Assert.NotNull(WhySensitive(name));
    }

    [Theory]
    [InlineData("WTSGetActiveConsoleSessionId")]
    [InlineData("CloseHandle")]
    [InlineData("GetFileInformationByHandleEx")]
    [InlineData("GetFinalPathNameByHandle")]
    [InlineData("GetSecurityInfo")]
    [InlineData("GetSecurityDescriptorLength")]
    [InlineData("FlushFileBuffers")]
    [InlineData("GetSystemWindowsDirectory")]
    [InlineData("OpenProcessToken")]
    [InlineData("GetTokenInformation")]
    [InlineData("ConvertStringSidToSid")]
    public void The_sensitive_list_leaves_out_functions_that_work_on_a_handle_or_read_state(string name)
    {
        Assert.Null(WhySensitive(name));
    }

    private static string? WhySensitive(string entry)
    {
        return NamesFor(entry).SelectMany(n => Sensitive.Where(s => s.Names.IsMatch(n)).Select(s => s.Why)).FirstOrDefault();
    }

    /// <summary>The name as written, and without an A or W suffix, which CsWin32 drops.</summary>
    private static IEnumerable<string> NamesFor(string entry)
    {
        yield return entry;
        if (entry.Length > 1 && entry[^1] is 'A' or 'W' && char.IsLower(entry[^2]))
        {
            yield return entry[..^1];
        }
    }

    private static Regex Names(params string[] patterns)
    {
        return new Regex("^(" + string.Join('|', patterns) + ")[AW]?$", RegexOptions.CultureInvariant);
    }

    private static List<string> NativeMethodEntries()
    {
        return File.ReadAllLines(Repository.PathOf(NativeMethodsFile))
            .Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith("//", StringComparison.Ordinal))
            .ToList();
    }

    private static IEnumerable<(string Path, IReadOnlyList<string> Lines)> SourceFiles()
    {
        foreach (var file in Repository.FilesUnder("src", "*.cs"))
        {
            yield return (Repository.RelativePathOf(file), File.ReadAllText(file).ReplaceLineEndings("\n").Split('\n'));
        }
    }

    /// <summary>
    /// Native interop written by hand: a DllImport or LibraryImport declaration, an extern method, an
    /// unmanaged function pointer, loading a native library, or a COM class declared or created by hand.
    /// </summary>
    [GeneratedRegex(@"\b(DllImport|LibraryImport|ComImport|GeneratedComInterface|NativeLibrary|GetDelegateForFunctionPointer|LoadUnmanagedDll\w*|GetTypeFromCLSID|GetTypeFromProgID)\b|\bextern\b(?!\s+alias\b)|\bdelegate\s*\*\s*unmanaged\b")]
    private static partial Regex HandWrittenInterop();

    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_]*$")]
    private static partial Regex PlainName();
}
