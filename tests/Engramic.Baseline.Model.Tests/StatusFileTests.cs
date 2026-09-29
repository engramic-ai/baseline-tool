using System.Text;
using System.Text.Json;

namespace Engramic.Baseline.Model.Tests;

public sealed class StatusFileTests
{
    [Fact]
    public void Writes_status_json_byte_for_byte_with_a_byte_order_mark_and_Windows_line_ends()
    {
        var expected = Utf8Bom.GetBytes(StatusSamples.Su01PassingJson.ReplaceLineEndings("\r\n") + "\r\n");

        var bytes = StatusFile.ToBytes(StatusSamples.Su01Passing());

        Assert.Equal(Encoding.UTF8.GetString(expected), Encoding.UTF8.GetString(bytes));
        Assert.Equal(expected, bytes);
    }

    [Fact]
    public void The_file_starts_with_the_byte_order_mark()
    {
        var bytes = StatusFile.ToBytes(StatusSamples.Su01Passing());

        Assert.Equal([0xEF, 0xBB, 0xBF, (byte)'{'], bytes[..4]);
    }

    [Fact]
    public void Every_key_has_the_name_and_casing_the_Intune_scripts_read()
    {
        using var json = Parse(StatusSamples.Su01Passing());
        var root = json.RootElement;

        Assert.Equal(
            ["schemaVersion", "toolVersion", "scope", "platform", "computerName", "auditTime", "runAs", "elevated", "os", "counts", "autoFailCount", "autoFails", "checks", "frameworks", "hardware", "packs", "reportFolder"],
            Names(root));
        Assert.Equal(["Pass", "Fail", "Warn", "Manual", "Info", "NotApplicable", "Skipped", "Error"], Names(root.GetProperty("counts")));
        Assert.Equal(["status", "frameworks", "scope", "autoFail"], Names(root.GetProperty("checks").GetProperty("SU-01")));
        Assert.Equal(["ce-v3.3", "ce-plus"], Names(root.GetProperty("frameworks")));
        Assert.Equal(["label", "applicable", "met", "attention", "confirm", "notApplicable", "metPct"], Names(root.GetProperty("frameworks").GetProperty("ce-v3.3")));
        Assert.Equal(["label", "tcs", "onTrack", "total"], Names(root.GetProperty("frameworks").GetProperty("ce-plus")));
        Assert.Equal(["TC1", "TC2", "TC3", "TC4", "TC5"], Names(root.GetProperty("frameworks").GetProperty("ce-plus").GetProperty("tcs")));
    }

    [Fact]
    public void Values_have_the_types_the_Intune_scripts_expect()
    {
        using var json = Parse(StatusSamples.Su01Passing());
        var root = json.RootElement;

        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(JsonValueKind.False, root.GetProperty("elevated").ValueKind);
        Assert.Equal(0, root.GetProperty("autoFailCount").GetInt32());
        Assert.Equal(JsonValueKind.True, root.GetProperty("checks").GetProperty("SU-01").GetProperty("autoFail").ValueKind);
        Assert.Equal(100, root.GetProperty("frameworks").GetProperty("ce-v3.3").GetProperty("metPct").GetInt32());
        Assert.Equal("Likely pass", root.GetProperty("frameworks").GetProperty("ce-plus").GetProperty("tcs").GetProperty("TC2").GetString());
    }

    [Fact]
    public void A_framework_that_no_check_evidences_is_left_out()
    {
        var status = StatusSamples.Su01Passing() with { Frameworks = new StatusFrameworks() };

        using var json = Parse(status);

        Assert.Equal(JsonValueKind.Object, json.RootElement.GetProperty("frameworks").ValueKind);
        Assert.Empty(Names(json.RootElement.GetProperty("frameworks")));
    }

    [Fact]
    public void The_NCSC_rollup_sits_between_Cyber_Essentials_and_Cyber_Essentials_Plus()
    {
        var sample = StatusSamples.Su01Passing();
        var status = sample with
        {
            Frameworks = sample.Frameworks with { Ncsc = new FrameworkRollup { Label = "NCSC device hardening", Met = 2, Attention = 1, Confirm = 0, NotApplicable = 3 } },
        };

        using var json = Parse(status);

        Assert.Equal(["ce-v3.3", "ncsc", "ce-plus"], Names(json.RootElement.GetProperty("frameworks")));
        Assert.Equal(67, json.RootElement.GetProperty("frameworks").GetProperty("ncsc").GetProperty("metPct").GetInt32());
    }

    [Fact]
    public void A_list_of_one_stays_a_list()
    {
        var sample = StatusSamples.Su01Passing();
        var status = sample with
        {
            AutoFails = ["SU-01"],
            Checks = new Dictionary<string, StatusCheck> { ["SU-01"] = sample.Checks["SU-01"] with { Frameworks = ["CE v3.3"] } },
        };

        using var json = Parse(status);

        Assert.Equal(JsonValueKind.Array, json.RootElement.GetProperty("autoFails").ValueKind);
        Assert.Equal("SU-01", Assert.Single(json.RootElement.GetProperty("autoFails").EnumerateArray()).GetString());
        Assert.Equal(1, json.RootElement.GetProperty("autoFailCount").GetInt32());
        Assert.Equal(JsonValueKind.Array, json.RootElement.GetProperty("checks").GetProperty("SU-01").GetProperty("frameworks").ValueKind);
    }

    [Fact]
    public void Packs_is_an_empty_list_and_hardware_is_null()
    {
        using var json = Parse(StatusSamples.Su01Passing());

        Assert.Equal(JsonValueKind.Array, json.RootElement.GetProperty("packs").ValueKind);
        Assert.Empty(json.RootElement.GetProperty("packs").EnumerateArray());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("hardware").ValueKind);
    }

    [Fact]
    public void Hardware_is_written_with_the_keys_the_PowerShell_tool_uses()
    {
        var status = StatusSamples.Su01Passing() with
        {
            Hardware = new StatusHardware
            {
                Manufacturer = "Contoso",
                Model = "Laptop 14 G5",
                SystemSku = "CT14G5",
                SerialNumber = "SN-TEST-001",
                IsVirtualMachine = false,
                FirmwareVersion = "1.17.0",
                FirmwareDate = "2026-08-03",
                FirmwareType = "UEFI",
                TpmManufacturer = "IFX",
                TpmFirmware = "7.40.2098.0",
                TpmSpec = "2.0",
                Cpu = "Contoso CPU",
                Disks = [new StatusDisk { Model = "Contoso NVMe 1TB", Firmware = "4B2QJXD7" }],
            },
        };

        using var json = Parse(status);
        var hardware = json.RootElement.GetProperty("hardware");

        Assert.Equal(
            ["manufacturer", "model", "systemSku", "serialNumber", "isVirtualMachine", "firmwareVersion", "firmwareDate", "firmwareType", "tpmManufacturer", "tpmFirmware", "tpmSpec", "cpu", "disks"],
            Names(hardware));
        Assert.Equal(["model", "firmware"], Names(Assert.Single(hardware.GetProperty("disks").EnumerateArray())));
    }

    [Theory]
    // The PowerShell tool writes ([datetime]$time).ToUniversalTime().ToString('o'): UTC, seven fraction digits and Z.
    [InlineData(0, "2026-09-29T14:03:49.1675407Z")]
    [InlineData(1, "2026-09-29T14:03:49.1675407Z")]
    [InlineData(-5, "2026-09-29T14:03:49.1675407Z")]
    public void The_audit_time_is_written_in_UTC_in_the_round_trip_format(int offsetHours, string expected)
    {
        var utc = new DateTimeOffset(2026, 9, 29, 14, 3, 49, TimeSpan.Zero).AddTicks(1675407);
        var status = StatusSamples.Su01Passing() with { AuditTime = utc.ToOffset(TimeSpan.FromHours(offsetHours)) };

        using var json = Parse(status);

        Assert.Equal(expected, json.RootElement.GetProperty("auditTime").GetString());
    }

    [Fact]
    public void A_whole_second_keeps_its_seven_zero_digits()
    {
        var status = StatusSamples.Su01Passing() with { AuditTime = new DateTimeOffset(2026, 9, 29, 14, 3, 49, TimeSpan.Zero) };

        using var json = Parse(status);

        Assert.Equal("2026-09-29T14:03:49.0000000Z", json.RootElement.GetProperty("auditTime").GetString());
    }

    [Fact]
    public void Text_beyond_ASCII_is_written_as_UTF8_not_escaped()
    {
        var status = StatusSamples.Su01Passing() with { ComputerName = "B\u00FCRO-PC" };

        var text = Encoding.UTF8.GetString(StatusFile.ToBytes(status));

        Assert.Contains("\"computerName\": \"B\u00FCRO-PC\"", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Plus_and_greater_than_are_written_as_they_are()
    {
        var text = Encoding.UTF8.GetString(StatusFile.ToBytes(StatusSamples.Su01Passing() with { Os = "Windows > 11" }));

        Assert.Contains("\"CE+ TC2\"", text, StringComparison.Ordinal);
        Assert.Contains("\"Windows > 11\"", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Text_that_is_not_valid_UTF16_becomes_a_replacement_character_rather_than_failing_the_file()
    {
        // A lone surrogate, which a registry value can hold, is written as U+FFFD, as the PowerShell tool's
        // UTF-8 encoder writes it, so one odd value never stops status.json being written.
        var status = StatusSamples.Su01Passing() with { ComputerName = "before \uD800 after" };

        var bytes = StatusFile.ToBytes(status);

        Assert.Contains("\"computerName\": \"before \\uFFFD after\"", Encoding.UTF8.GetString(bytes), StringComparison.Ordinal);
        Assert.Equal("before \uFFFD after", StatusFile.Parse(bytes).ComputerName);
    }

    [Fact]
    public void Reads_back_what_it_writes()
    {
        var written = StatusSamples.Su01Passing();

        var read = StatusFile.Parse(StatusFile.ToBytes(written));

        Assert.Equal(written.AuditTime, read.AuditTime);
        Assert.Equal(written.ComputerName, read.ComputerName);
        Assert.Equal(written.Counts, read.Counts);
        Assert.Equal(written.Frameworks.CeV33, read.Frameworks.CeV33);
        Assert.Equal(written.Frameworks.CePlus!.TestCases, read.Frameworks.CePlus!.TestCases);
        Assert.Null(read.Frameworks.Ncsc);
        var check = Assert.Single(read.Checks);
        Assert.Equal("SU-01", check.Key);
        Assert.Equal(["CE v3.3", "CE+ TC2"], check.Value.Frameworks);
        Assert.Equal(StatusFile.ToBytes(written), StatusFile.ToBytes(read));
    }

    [Fact]
    public void Reads_status_json_as_Windows_PowerShell_writes_it()
    {
        var status = StatusFile.Parse(Utf8Bom.GetBytes(StatusSamples.WrittenByPowerShellJson));

        Assert.Equal(StatusDocument.CurrentSchemaVersion, status.SchemaVersion);
        Assert.Equal("0.3.2", status.ToolVersion);
        Assert.Equal(new DateTimeOffset(2026, 9, 29, 14, 3, 49, TimeSpan.Zero).AddTicks(1675407), status.AuditTime);
        Assert.True(status.Elevated);
        Assert.Equal(["SU-01"], status.AutoFails);
        Assert.Equal(1, status.AutoFailCount);
        Assert.Equal(FindingStatus.Fail, status.Checks["SU-01"].Status);
        Assert.Equal(0, status.Frameworks.CeV33!.MetPct);
        Assert.Equal(CePlusState.LikelyFail, status.Frameworks.CePlus!.TestCases.TC2);
        Assert.Equal("Contoso CPU > 3 GHz", status.Hardware!.Cpu);
        Assert.Equal("4B2QJXD7", Assert.Single(status.Hardware.Disks).Firmware);
        // Code packs are retired: a pack listed by the PowerShell tool is not read.
        Assert.Empty(status.Packs);
    }

    [Fact]
    public void Reading_a_file_that_is_not_a_status_throws()
    {
        Assert.Throws<JsonException>(() => StatusFile.Parse("null"u8));
        Assert.Throws<JsonException>(() => StatusFile.Parse("{\"schemaVersion\": 1}"u8));
    }

    private static JsonDocument Parse(StatusDocument status)
    {
        var bytes = StatusFile.ToBytes(status);
        return JsonDocument.Parse(bytes.AsMemory(Utf8Bom.Preamble.Length));
    }

    private static List<string> Names(JsonElement element) => [.. element.EnumerateObject().Select(p => p.Name)];
}
