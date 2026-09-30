using System.Text;
using System.Text.Json;

namespace Engramic.Baseline.Model.Tests;

public sealed class FindingsFileTests
{
    private const string Su01FindingJson = """
        {
          "Findings": [
            {
              "FindingId": "SU-01",
              "CheckId": "SU-01",
              "Title": "Operating system is licensed and supported by Microsoft",
              "Subject": "",
              "Category": "SecurityUpdateManagement",
              "Frameworks": [
                "CE v3.3",
                "CE+ TC2"
              ],
              "Reference": "CE v3.3 Security update management: all software must be licensed and supported, and removed when it becomes unsupported.",
              "Scope": "Machine",
              "Status": "Pass",
              "Severity": "Info",
              "AutoFail": false,
              "Expected": "Supported Windows version",
              "Actual": "Windows 11 25H2 Professional (build 26200.9457): supported until 2027-10-12",
              "Recommendation": "",
              "Evidence": [],
              "Remediation": null,
              "Pack": null
            }
          ]
        }
        """;

    [Fact]
    public void Writes_all_17_fields_of_a_finding_in_order_with_the_PowerShell_names()
    {
        var bytes = FindingsFile.ToBytes(new FindingsDocument { Findings = [Su01Passing()] });

        Assert.Equal(Su01FindingJson.ReplaceLineEndings("\r\n") + "\r\n", Encoding.UTF8.GetString(bytes.AsSpan(Utf8Bom.Preamble.Length)));
        Assert.Equal(Utf8Bom.Preamble.ToArray(), bytes[..3]);
    }

    [Fact]
    public void A_fix_is_written_with_its_identifier_and_parameters()
    {
        using var parameters = JsonDocument.Parse("""{ "Seconds": 900, "RuleName": "Remote Desktop", "Enabled": true }""");
        var finding = Su01Passing() with
        {
            Remediation = new RemediationRef
            {
                Id = "Lock-InactivityTimeout",
                Parameters = parameters.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone()),
            },
        };

        using var json = JsonDocument.Parse(FindingsFile.ToBytes(new FindingsDocument { Findings = [finding] }).AsMemory(3));
        var remediation = json.RootElement.GetProperty("Findings")[0].GetProperty("Remediation");

        Assert.Equal("Lock-InactivityTimeout", remediation.GetProperty("Id").GetString());
        Assert.Equal(900, remediation.GetProperty("Parameters").GetProperty("Seconds").GetInt32());
        Assert.Equal("Remote Desktop", remediation.GetProperty("Parameters").GetProperty("RuleName").GetString());
        Assert.True(remediation.GetProperty("Parameters").GetProperty("Enabled").GetBoolean());
    }

    [Fact]
    public void Reads_back_what_it_writes()
    {
        var written = Su01Passing() with { Subject = "Lifecycle data", FindingId = "SU-01:Lifecycle-data", Evidence = ["one", "two"] };

        var read = Assert.Single(FindingsFile.Parse(FindingsFile.ToBytes(new FindingsDocument { Findings = [written] })).Findings);

        Assert.Equal(written.FindingId, read.FindingId);
        Assert.Equal(written.Category, read.Category);
        Assert.Equal(written.Frameworks, read.Frameworks);
        Assert.Equal(written.Evidence, read.Evidence);
        Assert.Null(read.Remediation);
        Assert.Null(read.Pack);
    }

    [Fact]
    public void Reads_a_finding_as_Windows_PowerShell_writes_it()
    {
        var json = """
            {"Findings":[{"FindingId":"SU-03:Overdue","CheckId":"SU-03","Title":"No Windows security updates outstanding for more than 14 days","Subject":"Overdue","Category":"SecurityUpdateManagement","Frameworks":["CE v3.3","CE+ TC2"],"Reference":"CE v3.3 A6.4 (auto-fail): critical/high-risk (CVSS v3 \u003e= 7)","Scope":"Machine","Status":"Fail","Severity":"Critical","AutoFail":true,"Expected":"e","Actual":"a","Recommendation":"","Evidence":[],"Remediation":{"Id":"WindowsUpdate-InstallSecurity","Parameters":{}},"Pack":null}]}
            """;

        var finding = Assert.Single(FindingsFile.Parse(Utf8Bom.GetBytes(json)).Findings);

        Assert.Equal("SU-03:Overdue", finding.FindingId);
        Assert.Equal(FindingStatus.Fail, finding.Status);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.True(finding.AutoFail);
        Assert.Equal("CE v3.3 A6.4 (auto-fail): critical/high-risk (CVSS v3 >= 7)", finding.Reference);
        Assert.Equal("WindowsUpdate-InstallSecurity", finding.Remediation!.Id);
        Assert.Empty(finding.Remediation.Parameters);
    }

    private static Finding Su01Passing() => new()
    {
        FindingId = "SU-01",
        CheckId = "SU-01",
        Title = "Operating system is licensed and supported by Microsoft",
        Subject = string.Empty,
        Category = CheckCategory.SecurityUpdateManagement,
        Frameworks = ["CE v3.3", "CE+ TC2"],
        Reference = "CE v3.3 Security update management: all software must be licensed and supported, and removed when it becomes unsupported.",
        Scope = CheckScope.Machine,
        Status = FindingStatus.Pass,
        Severity = Severity.Info,
        AutoFail = false,
        Expected = "Supported Windows version",
        Actual = "Windows 11 25H2 Professional (build 26200.9457): supported until 2027-10-12",
        Recommendation = string.Empty,
        Evidence = [],
    };
}
