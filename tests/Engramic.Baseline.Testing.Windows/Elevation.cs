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

    private static readonly Lazy<(bool Elevated, bool System, Sid User)> Account = new(Read);

    /// <summary>Gets whether the tests run as an elevated administrator or as SYSTEM.</summary>
    public static bool IsElevated => Account.Value.Elevated;

    /// <summary>Gets whether the tests run as SYSTEM.</summary>
    public static bool IsSystem => Account.Value.System;

    /// <summary>Gets the account the tests run as.</summary>
    public static Sid CurrentUser => Account.Value.User;

    private static (bool Elevated, bool System, Sid User) Read()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator), identity.IsSystem, Sid.Parse(identity.User!.Value));
    }
}
