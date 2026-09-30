using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// The theme a check belongs to, written by name in findings.json. The members are in report order.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<CheckCategory>))]
public enum CheckCategory
{
    /// <summary>Firewalls.</summary>
    [JsonStringEnumMemberName("Firewalls")]
    Firewalls,

    /// <summary>Secure configuration.</summary>
    [JsonStringEnumMemberName("SecureConfiguration")]
    SecureConfiguration,

    /// <summary>Security update management.</summary>
    [JsonStringEnumMemberName("SecurityUpdateManagement")]
    SecurityUpdateManagement,

    /// <summary>User access control.</summary>
    [JsonStringEnumMemberName("UserAccessControl")]
    UserAccessControl,

    /// <summary>Malware protection.</summary>
    [JsonStringEnumMemberName("MalwareProtection")]
    MalwareProtection,

    /// <summary>NCSC device hardening beyond Cyber Essentials.</summary>
    [JsonStringEnumMemberName("NCSCHardening")]
    NCSCHardening,
}
