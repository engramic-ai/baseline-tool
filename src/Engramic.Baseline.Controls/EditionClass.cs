namespace Engramic.Baseline.Controls;

/// <summary>
/// Groups Windows editions by the servicing they get, from the edition identifier in the registry, as the
/// PowerShell tool's Get-CEDeviceContext does.
/// </summary>
/// <remarks>
/// Enterprise, Education and IoT Enterprise editions, including their LTSC and N variants (EnterpriseS,
/// IoTEnterpriseS, EducationN), get Enterprise servicing dates; Pro editions and Home editions (Core)
/// get the Home and Pro dates. Matching ignores case. Anything else, such as ServerRdsh (multi-session)
/// or Cloud (SE), is Unknown, and SU-01 gives it the Home and Pro dates.
/// </remarks>
public static class EditionClass
{
    /// <summary>Enterprise, Education and IoT Enterprise editions.</summary>
    public const string Enterprise = "Enterprise";

    /// <summary>Pro editions, including Pro for Workstations and Pro Education.</summary>
    public const string Pro = "Pro";

    /// <summary>Home editions, whose edition identifiers start with Core.</summary>
    public const string Home = "Home";

    /// <summary>Any Windows Server edition.</summary>
    public const string Server = "Server";

    /// <summary>Any other edition.</summary>
    public const string Unknown = "Unknown";

    /// <summary>Groups an edition.</summary>
    /// <param name="osFamily">The Windows family (<see cref="WindowsFamily"/>): every Windows Server edition is Server.</param>
    /// <param name="editionId">The EditionID registry value, such as Professional or EnterpriseS.</param>
    /// <returns>One of <see cref="Enterprise"/>, <see cref="Pro"/>, <see cref="Home"/>, <see cref="Server"/> or <see cref="Unknown"/>.</returns>
    public static string FromEdition(string osFamily, string? editionId)
    {
        if (string.Equals(osFamily, WindowsFamily.Server, StringComparison.Ordinal))
        {
            return Server;
        }

        var edition = editionId ?? string.Empty;
        if (StartsWith(edition, "Enterprise") || StartsWith(edition, "Education") || StartsWith(edition, "IoTEnterprise"))
        {
            return Enterprise;
        }

        if (StartsWith(edition, "Professional"))
        {
            return Pro;
        }

        return StartsWith(edition, "Core") ? Home : Unknown;
    }

    private static bool StartsWith(string edition, string prefix) => edition.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
}
