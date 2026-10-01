using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Text.Json;

namespace Engramic.Baseline.Invariants.Tests;

/// <summary>
/// src/BannedSymbols.txt must ban every overload of what it bans, and every line must name a real API:
/// the analyser silently ignores a line that names nothing, and .NET adds overloads over time.
/// </summary>
public sealed class BannedApiTests
{
    private const BindingFlags Public = BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance;

    private static readonly Lazy<IReadOnlyList<Assembly>> Framework = new(LoadFramework);

    [Fact]
    public void Every_reflection_based_JsonSerializer_overload_is_banned()
    {
        AssertBanned(
            "reflection-based JsonSerializer overload (JSON is source-generated)",
            typeof(JsonSerializer).GetMethods(BindingFlags.Public | BindingFlags.Static)
                .Where(m => m.IsDefined(typeof(RequiresUnreferencedCodeAttribute)) || m.IsDefined(typeof(RequiresDynamicCodeAttribute))));
    }

    [Fact]
    public void Every_way_to_start_a_process_is_banned()
    {
        AssertBanned(
            "way to start a process (only the trusted process runner starts one)",
            typeof(Process).GetMethods(Public).Where(m => m.Name == nameof(Process.Start)).Append<MemberInfo>(typeof(ProcessStartInfo)));
    }

    [Fact]
    public void Every_constructor_that_opens_a_file_by_path_is_banned()
    {
        AssertBanned(
            "constructor that opens a file by path (files are opened by handle)",
            new[] { typeof(FileStream), typeof(StreamReader), typeof(StreamWriter) }
                .SelectMany(t => t.GetConstructors())
                .Where(c => c.GetParameters() is [{ ParameterType: var first }, ..] && first == typeof(string)));
    }

    [Fact]
    public void Every_way_to_read_an_environment_variable_is_banned()
    {
        AssertBanned(
            "way to read an environment variable (a user can set them)",
            typeof(Environment).GetMethods(Public).Where(m => m.Name is "GetEnvironmentVariable" or "GetEnvironmentVariables" or "ExpandEnvironmentVariables"));
    }

    [Fact]
    public void Every_way_to_set_an_access_control_list_or_an_owner_is_banned()
    {
        var setters = new[] { "System.Threading.ThreadingAclExtensions", "System.IO.Pipes.PipesAclExtensions" }
            .Select(TypeNamed)
            .SelectMany(t => t.GetMethods(Public))
            .Where(m => m.Name == "SetAccessControl")
            .Concat(TypeNamed("System.Security.AccessControl.ObjectSecurity").GetMethods(Public).Where(m => m.Name == "SetOwner"))
            .Append<MemberInfo>(TypeNamed("System.IO.FileSystemAclExtensions"));

        AssertBanned("way to set an access control list or an owner (only SecureStore sets them)", setters);
    }

    [Fact]
    public void Every_way_to_read_the_clock_directly_is_banned()
    {
        AssertBanned(
            "way to read the clock directly (take a TimeProvider)",
            new[] { typeof(DateTime), typeof(DateTimeOffset) }
                .SelectMany(t => t.GetProperties(BindingFlags.Public | BindingFlags.Static))
                .Where(p => p.Name is "Now" or "UtcNow" or "Today"));
    }

    [Fact]
    public void Every_way_to_load_code_from_a_path_is_banned()
    {
        AssertBanned(
            "way to load code from a path (nothing is loaded that did not ship with the product)",
            typeof(Assembly).GetMethods(BindingFlags.Public | BindingFlags.Static)
                .Where(m => m.Name is "LoadFrom" or "LoadFile" or "UnsafeLoadFrom")
                .Concat(typeof(AssemblyLoadContext).GetMethods(Public).Where(m => m.Name is "LoadFromAssemblyPath" or "LoadFromNativeImagePath")));
    }

    [Fact]
    public void Every_way_to_reach_native_code_by_hand_is_banned()
    {
        AssertBanned(
            "way to reach native code by hand (Win32 is reached through CsWin32 only)",
            typeof(Marshal).GetMethods(BindingFlags.Public | BindingFlags.Static)
                .Where(m => m.Name == nameof(Marshal.GetDelegateForFunctionPointer))
                .Append<MemberInfo>(typeof(NativeLibrary)));
    }

    [Fact]
    public void Every_way_to_send_an_HTTP_request_is_banned()
    {
        // A client or handler made anywhere but the service client would fall back to .NET's default proxy.
        AssertBanned(
            "way to send an HTTP request (only the service client sends one, through the proxy it chose)",
            new MemberInfo[] { typeof(HttpClient), typeof(HttpClientHandler), typeof(SocketsHttpHandler) });
    }

    [Fact]
    public void Every_line_names_an_API_that_exists()
    {
        var unknown = new List<string>();
        foreach (var id in BannedList.Banned.Keys)
        {
            if (id.StartsWith("N:", StringComparison.Ordinal))
            {
                // A namespace ban needs no assembly: System.Management is not even referenced.
                continue;
            }

            var type = TryTypeNamed(TypeNameIn(id));
            if (type is null || !DocumentationIds.OfTypeAndMembers(type).Contains(id, StringComparer.Ordinal))
            {
                unknown.Add(id);
            }
        }

        Assert.True(unknown.Count == 0, "src/BannedSymbols.txt names APIs that do not exist in .NET, so the analyser ignores them:\n" + string.Join('\n', unknown));
    }

    [Fact]
    public void Every_line_says_what_to_use_instead()
    {
        var bare = BannedList.Banned.Where(e => e.Value.Length == 0).Select(e => e.Key).ToList();

        Assert.True(bare.Count == 0, "Each line of src/BannedSymbols.txt ends with ';' and the message the build shows:\n" + string.Join('\n', bare));
    }

    private static void AssertBanned(string what, IEnumerable<MemberInfo> members)
    {
        var ids = members.Select(DocumentationIds.Of).Distinct().ToList();
        Assert.NotEmpty(ids);

        var missing = ids.Where(id => !BannedList.Banned.ContainsKey(id)).Order(StringComparer.Ordinal).ToList();
        Assert.True(missing.Count == 0, $"src/BannedSymbols.txt misses a {what}. Add:\n" + string.Join('\n', missing));
    }

    /// <summary>The type part of a documentation ID: M:A.B.C(D) and M:A.B.C``1(D) give A.B.</summary>
    private static string TypeNameIn(string id)
    {
        var name = id[2..];
        if (id.StartsWith("T:", StringComparison.Ordinal))
        {
            return name;
        }

        var end = name.IndexOfAny(['(', '~']);
        if (end >= 0)
        {
            name = name[..end];
        }

        var generic = name.IndexOf("``", StringComparison.Ordinal);
        if (generic >= 0)
        {
            name = name[..generic];
        }

        return name[..name.LastIndexOf('.')];
    }

    private static Type TypeNamed(string fullName)
    {
        return TryTypeNamed(fullName) ?? throw new InvalidOperationException(fullName + " is not a type in the shared framework.");
    }

    private static Type? TryTypeNamed(string fullName)
    {
        return Framework.Value.Select(a => a.GetType(fullName, throwOnError: false)).FirstOrDefault(t => t is not null);
    }

    /// <summary>Every managed assembly of the shared framework the tests run on.</summary>
    private static IReadOnlyList<Assembly> LoadFramework()
    {
        var assemblies = new List<Assembly>();
        foreach (var file in Directory.EnumerateFiles(RuntimeEnvironment.GetRuntimeDirectory(), "*.dll"))
        {
            try
            {
                assemblies.Add(Assembly.Load(AssemblyName.GetAssemblyName(file)));
            }
            catch (BadImageFormatException)
            {
                // A native library, such as the runtime itself.
            }
        }

        return assemblies;
    }
}
