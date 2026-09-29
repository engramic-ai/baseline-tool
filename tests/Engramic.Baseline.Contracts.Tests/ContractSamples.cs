using Engramic.Baseline.Model;

namespace Engramic.Baseline.Contracts.Tests;

/// <summary>
/// The documents whose status.json the golden files hold, byte for byte: what the scheduled audit writes as
/// SYSTEM when SU-01 passes and when it fails, and a probe that gives every value the Intune scripts read a
/// value they can tell from their default.
/// </summary>
internal static class ContractSamples
{
    /// <summary>The name of each sample, which is also its golden file's name without status- and .json.</summary>
    public static IReadOnlyList<string> Names { get; } = ["su01-pass", "su01-fail", "reader-probe"];

    /// <summary>When the samples' audits ran: 2026-09-29 14:03:49.1675407 UTC, with every digit of the fraction used.</summary>
    public static DateTimeOffset AuditTime { get; } = new DateTimeOffset(2026, 9, 29, 14, 3, 49, TimeSpan.Zero).AddTicks(1675407);

    /// <summary>
    /// The version the probe gives as toolVersion: not ASCII, so a file read in the ANSI code page, as Windows
    /// PowerShell 5.1 reads one without a byte order mark, changes what both Intune scripts print.
    /// </summary>
    public static string ProbeToolVersion { get; } = "1.0.0-caf\u00e9";

    /// <summary>Gets a sample by name.</summary>
    public static StatusDocument Named(string name) => name switch
    {
        "su01-pass" => Su01Pass(),
        "su01-fail" => Su01Fail(),
        "reader-probe" => ReaderProbe(),
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, "Not a sample."),
    };

    /// <summary>The scheduled audit as SYSTEM on a supported Windows 11: SU-01 passes.</summary>
    public static StatusDocument Su01Pass() => new()
    {
        ToolVersion = "1.0.0-alpha.0",
        ComputerName = "DEVICE01",
        AuditTime = AuditTime,
        RunAs = @"NT AUTHORITY\SYSTEM",
        Elevated = true,
        Os = "Windows 11 25H2 Enterprise (26200.6584)",
        Counts = new StatusCounts { Pass = 1 },
        AutoFails = [],
        Checks = new Dictionary<string, StatusCheck>
        {
            ["SU-01"] = Check(FindingStatus.Pass, autoFail: true, "CE v3.3", "CE+ TC2"),
        },
        Frameworks = new StatusFrameworks
        {
            CeV33 = new FrameworkRollup { Label = "Cyber Essentials v3.3", Met = 1, Attention = 0, Confirm = 0, NotApplicable = 0 },
            CePlus = CePlus(CePlusState.NotAssessed, CePlusState.LikelyPass, CePlusState.NotAssessed, CePlusState.NotAssessed, CePlusState.NotAssessed),
        },
        ReportFolder = string.Empty,
    };

    /// <summary>The scheduled audit as SYSTEM on Windows 10 22H2 after its support ended: SU-01 fails, an auto-fail.</summary>
    public static StatusDocument Su01Fail() => new()
    {
        ToolVersion = "1.0.0-alpha.0",
        ComputerName = "DEVICE02",
        AuditTime = AuditTime,
        RunAs = @"NT AUTHORITY\SYSTEM",
        Elevated = true,
        Os = "Windows 10 22H2 Professional (19045.6456)",
        Counts = new StatusCounts { Fail = 1 },
        AutoFails = ["SU-01"],
        Checks = new Dictionary<string, StatusCheck>
        {
            ["SU-01"] = Check(FindingStatus.Fail, autoFail: true, "CE v3.3", "CE+ TC2"),
        },
        Frameworks = new StatusFrameworks
        {
            CeV33 = new FrameworkRollup { Label = "Cyber Essentials v3.3", Met = 0, Attention = 1, Confirm = 0, NotApplicable = 0 },
            CePlus = CePlus(CePlusState.NotAssessed, CePlusState.LikelyFail, CePlusState.NotAssessed, CePlusState.NotAssessed, CePlusState.NotAssessed),
        },
        ReportFolder = string.Empty,
    };

    /// <summary>
    /// Every status, auto-fail checks that fail, error and ask for review, all three frameworks and all five CE+
    /// test cases, the hardware block the PowerShell tool writes, a report folder, and text beyond ASCII: so each
    /// value the Intune scripts read differs from the value they fall back to, and a change to a key, its casing
    /// or the byte order mark can show in what they print.
    /// </summary>
    public static StatusDocument ReaderProbe() => new()
    {
        ToolVersion = ProbeToolVersion,
        ComputerName = "B\u00dcRO-PC",
        AuditTime = AuditTime,
        RunAs = @"NT AUTHORITY\SYSTEM",
        Elevated = true,
        Os = "Windows 11 24H2 Professional (26100.4946)",
        Counts = new StatusCounts { Pass = 4, Fail = 2, Warn = 2, Manual = 1, Info = 1, NotApplicable = 1, Skipped = 1, Error = 1 },
        AutoFails = ["SU-03", "SU-05"],
        Checks = new Dictionary<string, StatusCheck>
        {
            ["FW-01"] = Check(FindingStatus.Pass, autoFail: false, "CE v3.3", "NCSC"),
            ["FW-02"] = Check(FindingStatus.Fail, autoFail: false, "CE v3.3", "CE+ TC1"),
            ["MP-01"] = Check(FindingStatus.Pass, autoFail: false, "CE v3.3", "CE+ TC3"),
            ["MP-09"] = Check(FindingStatus.Warn, autoFail: false, "NCSC", "CE v3.3"),
            ["NC-01"] = Check(FindingStatus.Skipped, autoFail: false, "NCSC"),
            ["NC-03"] = Check(FindingStatus.Info, autoFail: false, "NCSC"),
            ["NC-04"] = Check(FindingStatus.NotApplicable, autoFail: false, "NCSC"),
            ["SU-01"] = Check(FindingStatus.Warn, autoFail: true, "CE v3.3", "CE+ TC2"),
            ["SU-03"] = Check(FindingStatus.Fail, autoFail: true, "CE v3.3", "CE+ TC2"),
            ["SU-05"] = Check(FindingStatus.Error, autoFail: true, "CE v3.3", "CE+ TC2"),
            ["UA-01"] = Check(FindingStatus.Pass, autoFail: false, "CE v3.3", "CE+ TC5", "NCSC"),
            ["UA-07"] = Check(FindingStatus.Manual, autoFail: true, "CE v3.3", "CE+ TC4"),
        },
        Frameworks = new StatusFrameworks
        {
            CeV33 = new FrameworkRollup { Label = "Cyber Essentials v3.3", Met = 3, Attention = 5, Confirm = 1, NotApplicable = 0 },
            Ncsc = new FrameworkRollup { Label = "NCSC device hardening", Met = 2, Attention = 1, Confirm = 0, NotApplicable = 3 },
            CePlus = CePlus(CePlusState.LikelyFail, CePlusState.LikelyFail, CePlusState.Check, CePlusState.Check, CePlusState.LikelyPass),
        },
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
            Cpu = "Contoso CPU > 3 GHz",
            Disks = [new StatusDisk { Model = "Contoso NVMe 1TB", Firmware = "4B2QJXD7" }],
        },
        ReportFolder = "C:\\ProgramData\\EngramicBaseline\\reports\\B\u00dcRO-PC-20260929-150349",
    };

    private static StatusCheck Check(FindingStatus status, bool autoFail, params string[] frameworks) => new()
    {
        Status = status,
        Frameworks = frameworks,
        Scope = CheckScope.Machine,
        AutoFail = autoFail,
    };

    private static CePlusRollup CePlus(CePlusState tc1, CePlusState tc2, CePlusState tc3, CePlusState tc4, CePlusState tc5) => new()
    {
        TestCases = new CePlusTestCaseStates { TC1 = tc1, TC2 = tc2, TC3 = tc3, TC4 = tc4, TC5 = tc5 },
    };
}
