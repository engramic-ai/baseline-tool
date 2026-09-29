namespace Engramic.Baseline.Controls.Tests;

public sealed class EditionClassTests
{
    [Theory]
    [InlineData("Enterprise", "Enterprise")]
    [InlineData("EnterpriseN", "Enterprise")]
    // LTSC and IoT editions get the Enterprise servicing dates, as in the PowerShell tool.
    [InlineData("EnterpriseS", "Enterprise")]
    [InlineData("EnterpriseSN", "Enterprise")]
    [InlineData("IoTEnterprise", "Enterprise")]
    [InlineData("IoTEnterpriseS", "Enterprise")]
    [InlineData("Education", "Enterprise")]
    [InlineData("EducationN", "Enterprise")]
    [InlineData("enterprise", "Enterprise")]
    [InlineData("Professional", "Pro")]
    [InlineData("ProfessionalN", "Pro")]
    [InlineData("ProfessionalWorkstation", "Pro")]
    [InlineData("ProfessionalEducation", "Pro")]
    [InlineData("Core", "Home")]
    [InlineData("CoreN", "Home")]
    [InlineData("CoreSingleLanguage", "Home")]
    [InlineData("CoreCountrySpecific", "Home")]
    // Multi-session, SE and anything unknown.
    [InlineData("ServerRdsh", "Unknown")]
    [InlineData("Cloud", "Unknown")]
    [InlineData("", "Unknown")]
    [InlineData(null, "Unknown")]
    public void Groups_a_client_edition_by_its_identifier(string? editionId, string expected)
    {
        Assert.Equal(expected, EditionClass.FromEdition(WindowsFamily.Windows11, editionId));
    }

    [Theory]
    [InlineData("ServerDatacenter")]
    [InlineData("ServerStandard")]
    [InlineData("Enterprise")]
    public void Every_Windows_Server_edition_is_Server(string editionId)
    {
        Assert.Equal("Server", EditionClass.FromEdition(WindowsFamily.Server, editionId));
    }
}
