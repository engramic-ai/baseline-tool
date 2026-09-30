using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Engramic.Baseline.Platform;
using Microsoft.Win32.SafeHandles;

namespace Engramic.Baseline.Testing.Windows;

/// <summary>
/// The attacker of the security tests: a standard user, a local account in Users and no other group, that
/// the Security job in CI makes for its run (tools/ci/Invoke-SecurityTests.ps1) and names in
/// <see cref="UserVariable"/> and <see cref="PasswordVariable"/>. A test acts as it by impersonating a logon
/// of it, which needs an elevated administrator or SYSTEM, so without both the tests that need it skip.
/// </summary>
/// <remarks>
/// What the attacker makes it owns and can change, and a handle it opens keeps the access it was opened
/// with, whatever happens to the item later: the case SecureStore exists for. Such items can deny the test's
/// own account, so a test that makes them removes them as the attacker (<see cref="Remove"/>).
/// </remarks>
public static partial class Attacker
{
    /// <summary>The environment variable that names the attacker's account.</summary>
    public const string UserVariable = "BASELINE_TEST_ATTACKER_USER";

    /// <summary>The environment variable that holds the attacker's password.</summary>
    public const string PasswordVariable = "BASELINE_TEST_ATTACKER_PASSWORD";

    /// <summary>The reason a test that needs the attacker gives when it skips.</summary>
    public const string Unavailable = "Needs the standard-user attacker that the Security job in CI makes, and elevation to act as it; skipped here.";

    private const int NetworkLogon = 3;
    private const int InteractiveLogon = 2;
    private const int DefaultProvider = 0;

    private static readonly Lazy<Account?> LoggedOn = new(LogOn);

    /// <summary>Gets whether the attacker exists and this process may act as it.</summary>
    public static bool IsAvailable => Elevation.IsElevated && LoggedOn.Value is not null;

    /// <summary>Gets the attacker's account.</summary>
    public static Sid Sid => Logon().Sid;

    /// <summary>Runs something as the attacker, on this thread.</summary>
    /// <param name="action">What to run.</param>
    public static void Run(Action action) => WindowsIdentity.RunImpersonated(Logon().Token, action);

    /// <summary>Runs something as the attacker, on this thread, and gives what it gives.</summary>
    /// <typeparam name="T">What it gives.</typeparam>
    /// <param name="action">What to run.</param>
    /// <returns>What it gave.</returns>
    public static T Run<T>(Func<T> action) => WindowsIdentity.RunImpersonated(Logon().Token, action);

    /// <summary>
    /// Removes, as the attacker, what the attacker made: a link as a link, a folder with what is in it. Its
    /// access list is first given back to its owner, the attacker, so that what it denied does not stop it.
    /// </summary>
    /// <param name="path">What to remove.</param>
    public static void Remove(string path) => Run(() => RemoveAsOwner(path));

    private static Account Logon() => LoggedOn.Value ?? throw new InvalidOperationException(Unavailable);

    private static Account? LogOn()
    {
        var user = Environment.GetEnvironmentVariable(UserVariable);
        var password = Environment.GetEnvironmentVariable(PasswordVariable);
        if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(password) || !Elevation.IsElevated)
        {
            return null;
        }

        // A network logon needs no right to log on locally, which a server may not give Users.
        if (!LogonUser(user, ".", password, NetworkLogon, DefaultProvider, out var token)
            && !LogonUser(user, ".", password, InteractiveLogon, DefaultProvider, out token))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), $"The Security job named the attacker {user}, but it could not log on");
        }

        using var identity = new WindowsIdentity(token.DangerousGetHandle());
        var groups = identity.Groups!.Select(g => g.Value).ToList();
        if (groups.Contains("S-1-5-32-544"))
        {
            throw new InvalidOperationException($"The attacker {user} is an administrator, not a standard user.");
        }

        return new Account(token, Sid.Parse(identity.User!.Value));
    }

    private static void RemoveAsOwner(string path)
    {
        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(path);
        }
        catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException)
        {
            return;
        }

        var isFolder = (attributes & FileAttributes.Directory) != 0;
        if ((attributes & FileAttributes.ReparsePoint) == 0)
        {
            Acls.Reset(path, $"D:P(A;OICI;FA;;;{Sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        }

        if (isFolder && (attributes & FileAttributes.ReparsePoint) == 0)
        {
            foreach (var entry in Directory.GetFileSystemEntries(path))
            {
                RemoveAsOwner(entry);
            }

            Directory.Delete(path, recursive: false);
        }
        else if (isFolder)
        {
            Directory.Delete(path, recursive: false);
        }
        else
        {
            File.SetAttributes(path, FileAttributes.Normal);
            File.Delete(path);
        }
    }

    [LibraryImport("advapi32.dll", EntryPoint = "LogonUserW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool LogonUser(string user, string domain, string password, int logonType, int provider, out SafeAccessTokenHandle token);

    private sealed record Account(SafeAccessTokenHandle Token, Sid Sid);
}
