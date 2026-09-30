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

    /// <summary>
    /// The config folder as the installer makes it: locked from birth, and standard users may read it.
    /// </summary>
    public const string InstallerLockedUsersRead = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

    /// <summary>
    /// Like the real ProgramData folder, where the attacker works: standard users may read it and create files
    /// and folders in it (FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, and writing extended attributes and attributes),
    /// and whoever creates something there has full control of it (CREATOR OWNER). They may not delete what
    /// others made (no FILE_DELETE_CHILD). Owned by Administrators rather than SYSTEM, which only SYSTEM may name.
    /// </summary>
    public const string RealProgramData = "O:BAD:P(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;0x116;;;BU)";
}
