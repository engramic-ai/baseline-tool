namespace Engramic.Baseline.Model.Tests;

/// <summary>Status documents for the tests, like the ones an SU-01 audit writes.</summary>
internal static class StatusSamples
{
    /// <summary>A status with SU-01 passing, and the JSON it must be written as.</summary>
    public static StatusDocument Su01Passing() => new()
    {
        ToolVersion = "1.0.0-alpha.0",
        ComputerName = "DEVICE01",
        AuditTime = new DateTimeOffset(2026, 9, 29, 14, 3, 49, TimeSpan.Zero).AddTicks(1675407),
        RunAs = @"CONTOSO\alex",
        Elevated = false,
        Os = "Windows 11 25H2 Professional (26200.9457)",
        Counts = new StatusCounts { Pass = 1 },
        AutoFails = [],
        Checks = new Dictionary<string, StatusCheck>
        {
            ["SU-01"] = new() { Status = FindingStatus.Pass, Frameworks = ["CE v3.3", "CE+ TC2"], Scope = CheckScope.Machine, AutoFail = true },
        },
        Frameworks = new StatusFrameworks
        {
            CeV33 = new FrameworkRollup { Label = "Cyber Essentials v3.3", Met = 1, Attention = 0, Confirm = 0, NotApplicable = 0 },
            CePlus = new CePlusRollup
            {
                TestCases = new CePlusTestCaseStates
                {
                    TC1 = CePlusState.NotAssessed,
                    TC2 = CePlusState.LikelyPass,
                    TC3 = CePlusState.NotAssessed,
                    TC4 = CePlusState.NotAssessed,
                    TC5 = CePlusState.NotAssessed,
                },
            },
        },
        ReportFolder = string.Empty,
    };

    /// <summary>The JSON of <see cref="Su01Passing"/>, as the PowerShell tool writes the same audit, apart from the layout.</summary>
    public const string Su01PassingJson = """
        {
          "schemaVersion": 1,
          "toolVersion": "1.0.0-alpha.0",
          "scope": "Machine",
          "platform": "windows",
          "computerName": "DEVICE01",
          "auditTime": "2026-09-29T14:03:49.1675407Z",
          "runAs": "CONTOSO\\alex",
          "elevated": false,
          "os": "Windows 11 25H2 Professional (26200.9457)",
          "counts": {
            "Pass": 1,
            "Fail": 0,
            "Warn": 0,
            "Manual": 0,
            "Info": 0,
            "NotApplicable": 0,
            "Skipped": 0,
            "Error": 0
          },
          "autoFailCount": 0,
          "autoFails": [],
          "checks": {
            "SU-01": {
              "status": "Pass",
              "frameworks": [
                "CE v3.3",
                "CE+ TC2"
              ],
              "scope": "Machine",
              "autoFail": true
            }
          },
          "frameworks": {
            "ce-v3.3": {
              "label": "Cyber Essentials v3.3",
              "applicable": 1,
              "met": 1,
              "attention": 0,
              "confirm": 0,
              "notApplicable": 0,
              "metPct": 100
            },
            "ce-plus": {
              "label": "Cyber Essentials Plus",
              "tcs": {
                "TC1": "Not assessed",
                "TC2": "Likely pass",
                "TC3": "Not assessed",
                "TC4": "Not assessed",
                "TC5": "Not assessed"
              },
              "onTrack": 1,
              "total": 5
            }
          },
          "hardware": null,
          "packs": [],
          "reportFolder": ""
        }
        """;

    /// <summary>
    /// A status.json as Windows PowerShell 5.1 writes it (ConvertTo-Json's layout, &lt; and &gt; escaped),
    /// with the hardware block and a pack entry the PowerShell tool could write.
    /// </summary>
    public const string WrittenByPowerShellJson = """
        {
            "schemaVersion":  1,
            "toolVersion":  "0.3.2",
            "scope":  "Machine",
            "platform":  "windows",
            "computerName":  "DEVICE01",
            "auditTime":  "2026-09-29T14:03:49.1675407Z",
            "runAs":  "NT AUTHORITY\\SYSTEM",
            "elevated":  true,
            "os":  "Windows Server 2025 ServerDatacenter (26100.4946)",
            "counts":  {
                           "Pass":  0,
                           "Fail":  1,
                           "Warn":  0,
                           "Manual":  0,
                           "Info":  0,
                           "NotApplicable":  0,
                           "Skipped":  0,
                           "Error":  0
                       },
            "autoFailCount":  1,
            "autoFails":  [
                              "SU-01"
                          ],
            "checks":  {
                           "SU-01":  {
                                         "status":  "Fail",
                                         "frameworks":  [
                                                            "CE v3.3",
                                                            "CE+ TC2"
                                                        ],
                                         "scope":  "Machine",
                                         "autoFail":  true
                                     }
                       },
            "frameworks":  {
                               "ce-v3.3":  {
                                               "label":  "Cyber Essentials v3.3",
                                               "applicable":  1,
                                               "met":  0,
                                               "attention":  1,
                                               "confirm":  0,
                                               "notApplicable":  0,
                                               "metPct":  0
                                           },
                               "ce-plus":  {
                                               "label":  "Cyber Essentials Plus",
                                               "tcs":  {
                                                           "TC1":  "Not assessed",
                                                           "TC2":  "Likely fail",
                                                           "TC3":  "Not assessed",
                                                           "TC4":  "Not assessed",
                                                           "TC5":  "Not assessed"
                                                       },
                                               "onTrack":  0,
                                               "total":  5
                                           }
                           },
            "hardware":  {
                             "manufacturer":  "Contoso",
                             "model":  "Laptop 14 G5",
                             "systemSku":  "CT14G5",
                             "serialNumber":  "SN-TEST-001",
                             "isVirtualMachine":  false,
                             "firmwareVersion":  "1.17.0",
                             "firmwareDate":  "2026-08-03",
                             "firmwareType":  "UEFI",
                             "tpmManufacturer":  "IFX",
                             "tpmFirmware":  "7.40.2098.0",
                             "tpmSpec":  "2.0",
                             "cpu":  "Contoso CPU \u003e 3 GHz",
                             "disks":  [
                                           {
                                               "model":  "Contoso NVMe 1TB",
                                               "firmware":  "4B2QJXD7"
                                           }
                                       ]
                         },
            "packs":  [
                          {
                              "id":  "good-pack",
                              "version":  "1.2.3",
                              "status":  "Loaded"
                          }
                      ],
            "reportFolder":  "C:\\ProgramData\\EngramicBaseline\\reports\\DEVICE01-20260929-150349"
        }
        """;
}
