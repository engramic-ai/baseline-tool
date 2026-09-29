namespace Engramic.Baseline.Testing.Windows;

/// <summary>
/// Security descriptors, in SDDL, of the folders the installer makes. Only an elevated administrator can
/// create a folder owned by Administrators, so the tests that use them need elevation.
/// </summary>
public static class Descriptors
{
    /// <summary>Like ProgramData: SYSTEM and Administrators in full control, and users may read.</summary>
    public const string ProgramDataLike = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

    /// <summary>The data folder as the installer's New-CEDataDirectorySecurity makes it: locked from birth.</summary>
    public const string InstallerLocked = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
}
