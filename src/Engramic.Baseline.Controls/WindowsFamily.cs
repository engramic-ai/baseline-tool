namespace Engramic.Baseline.Controls;

/// <summary>
/// Names the Windows family of a device, as reports show it, from its build number and installation type.
/// </summary>
/// <remarks>
/// Windows Server shares build numbers with client releases (Server 2025 and Windows 11 24H2 are both
/// build 26100), so the installation type decides first, as it does in the PowerShell tool.
/// </remarks>
public static class WindowsFamily
{
    /// <summary>Any installation type that mentions Server, such as Server or Server Core.</summary>
    public const string Server = "Windows Server";

    /// <summary>A client from build 22000.</summary>
    public const string Windows11 = "Windows 11";

    /// <summary>A client from build 10240 up to build 22000.</summary>
    public const string Windows10 = "Windows 10";

    /// <summary>Anything older, or a build that could not be read.</summary>
    public const string Unknown = "Unknown";

    /// <summary>Names the Windows family.</summary>
    /// <param name="build">The build number, CurrentBuildNumber in the registry; 0 when it could not be read.</param>
    /// <param name="installationType">The InstallationType registry value, such as Client, Server or Server Core.</param>
    /// <returns>One of <see cref="Server"/>, <see cref="Windows11"/>, <see cref="Windows10"/> or <see cref="Unknown"/>.</returns>
    public static string FromBuild(int build, string? installationType)
    {
        if (installationType is not null && installationType.Contains("Server", StringComparison.OrdinalIgnoreCase))
        {
            return Server;
        }

        if (build >= 22000)
        {
            return Windows11;
        }

        return build >= 10240 ? Windows10 : Unknown;
    }
}
