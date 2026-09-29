using System.Globalization;

namespace Engramic.Baseline.Engine;

/// <summary>
/// What an audit knows about the device before any check runs: the Windows release, who runs the audit
/// and when. Read once per audit and given to every check.
/// </summary>
/// <remarks>
/// The fields of the PowerShell tool's device context that the ported checks and status.json use so far;
/// the rest (join state, management, console user, hardware) join as the checks that need them are ported.
/// </remarks>
public sealed record DeviceContext
{
    /// <summary>Gets the name of the computer.</summary>
    public required string ComputerName { get; init; }

    /// <summary>Gets the Windows family: Windows Server, Windows 11, Windows 10 or Unknown.</summary>
    public required string OSFamily { get; init; }

    /// <summary>Gets the installation type, such as Client, Server or Server Core; Client when it could not be read.</summary>
    public required string InstallationType { get; init; }

    /// <summary>Gets the product name the registry holds, which still says Windows 10 on Windows 11.</summary>
    public required string ProductName { get; init; }

    /// <summary>Gets the edition identifier, such as Professional, Enterprise or ServerDatacenter.</summary>
    public required string EditionId { get; init; }

    /// <summary>Gets the edition class: Enterprise, Pro, Home, Server or Unknown.</summary>
    public required string EditionClass { get; init; }

    /// <summary>Gets the version shown to people, such as 24H2; empty when it could not be read.</summary>
    public required string DisplayVersion { get; init; }

    /// <summary>Gets the build number, such as 26100; 0 when it could not be read.</summary>
    public required int Build { get; init; }

    /// <summary>Gets the update build revision, such as 4946; 0 when it could not be read.</summary>
    public required int Ubr { get; init; }

    /// <summary>Gets the build and the update build revision, such as 26100.4946.</summary>
    public string FullBuild => string.Create(CultureInfo.InvariantCulture, $"{Build}.{Ubr}");

    /// <summary>Gets the account the audit runs as, such as NT AUTHORITY\SYSTEM.</summary>
    public required string RunningAs { get; init; }

    /// <summary>Gets whether the audit runs elevated or as SYSTEM, which admin-only checks need.</summary>
    public required bool IsElevated { get; init; }

    /// <summary>Gets whether the audit runs as SYSTEM.</summary>
    public required bool IsSystem { get; init; }

    /// <summary>Gets when the audit started.</summary>
    public required DateTimeOffset AuditTime { get; init; }
}
