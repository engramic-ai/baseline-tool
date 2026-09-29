using System.Text.Json;

namespace Engramic.Baseline.Model.Tests;

/// <summary>
/// The words the files hold for each enum member are the file format: the PowerShell tool writes them and
/// the Intune scripts and reports read them. Renaming a member must not change them.
/// </summary>
public sealed class EnumNameTests
{
    [Fact]
    public void Statuses_are_written_as_the_PowerShell_tool_writes_them_in_its_order()
    {
        Assert.Equal(["Pass", "Fail", "Warn", "Manual", "Info", "NotApplicable", "Skipped", "Error"], NamesOf<FindingStatus>());
    }

    [Fact]
    public void Severities_are_written_as_the_PowerShell_tool_writes_them()
    {
        Assert.Equal(["Critical", "High", "Medium", "Low", "Info"], NamesOf<Severity>());
    }

    [Fact]
    public void Categories_are_written_as_the_PowerShell_tool_writes_them_in_report_order()
    {
        Assert.Equal(
            ["Firewalls", "SecureConfiguration", "SecurityUpdateManagement", "UserAccessControl", "MalwareProtection", "NCSCHardening"],
            NamesOf<CheckCategory>());
    }

    [Fact]
    public void Scopes_are_written_as_the_PowerShell_tool_writes_them()
    {
        Assert.Equal(["Machine", "User"], NamesOf<CheckScope>());
    }

    [Fact]
    public void Cyber_Essentials_Plus_estimates_are_written_in_words()
    {
        Assert.Equal(["Not assessed", "Likely fail", "Check", "Likely pass"], NamesOf<CePlusState>());
    }

    [Fact]
    public void Names_are_read_back_exactly_as_written()
    {
        Assert.Equal(CePlusState.NotAssessed, JsonSerializer.Deserialize<CePlusState>("\"Not assessed\""));
        Assert.Equal(FindingStatus.NotApplicable, JsonSerializer.Deserialize<FindingStatus>("\"NotApplicable\""));
    }

    private static List<string> NamesOf<T>()
        where T : struct, Enum
    {
        // The enum's own converter attribute applies, as it does in the generated serializer.
        return [.. Enum.GetValues<T>().Select(v => JsonSerializer.Deserialize<string>(JsonSerializer.Serialize(v))!)];
    }
}
