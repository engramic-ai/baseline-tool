using System.Security.Principal;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Testing.Windows;

/// <summary>
/// Who the tests run as. Tests that need an elevated administrator, as in CI, skip themselves otherwise:
/// the maintainer runs the tests without elevation.
/// </summary>
public static class Elevation
{
    /// <summary>The reason a test that needs elevation gives when it skips.</summary>
    public const string NeedsElevation = "Needs an elevated administrator, as CI runs the tests; skipped without elevation.";

    private static readonly Lazy<(bool Elevated, bool System, Sid User, Sid Owner)> Account = new(Read);

    /// <summary>Gets whether the tests run as an elevated administrator or as SYSTEM.</summary>
    public static bool IsElevated => Account.Value.Elevated;

    /// <summary>Gets whether the tests run as SYSTEM.</summary>
    public static bool IsSystem => Account.Value.System;

    /// <summary>Gets the account the tests run as.</summary>
    public static Sid CurrentUser => Account.Value.User;

    /// <summary>
    /// Gets the owner Windows gives what the tests create when they name none: their own account, or, for an
    /// administrator where policy says so (as on Windows Server) and for SYSTEM, the Administrators group.
    /// </summary>
    public static Sid DefaultOwner => Account.Value.Owner;

    /// <summary>
    /// Gets SYSTEM, Administrators and the account running the tests, without repeats: the accounts a test's
    /// folders grant full control, and the ones SecureStore gives full control under the tests' rules.
    /// </summary>
    public static IReadOnlyList<Sid> FullControl => [.. new[] { Sid.LocalSystem, Sid.Administrators, CurrentUser }.Distinct()];

    private static (bool Elevated, bool System, Sid User, Sid Owner) Read()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator), identity.IsSystem, Sid.Parse(identity.User!.Value), Sid.Parse(identity.Owner!.Value));
    }
}
