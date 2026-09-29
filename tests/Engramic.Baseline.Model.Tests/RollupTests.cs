using System.Globalization;

namespace Engramic.Baseline.Model.Tests;

public sealed class RollupTests
{
    /// <summary>
    /// Every met/applicable pair up to 200 applicable checks whose share lands on a half, or a hair either
    /// side of one in floating point, with the metPct Windows PowerShell 5.1 gives for it:
    /// [int][math]::Round(([double]$met / $applicable) * 100). Generated with the PowerShell tool's formula.
    /// </summary>
    private const string PowerShellMidpoints =
        "1,8,12 3,8,38 5,8,62 7,8,88 2,16,12 6,16,38 10,16,62 14,16,88 3,24,12 9,24,38 15,24,62 21,24,88 4,32,12 12,32,38 20,32,62 28,32,88 " +
        "1,40,2 3,40,8 5,40,12 7,40,18 9,40,22 11,40,28 13,40,32 15,40,38 17,40,42 19,40,48 21,40,52 23,40,57 25,40,62 27,40,68 29,40,72 31,40,78 " +
        "33,40,82 35,40,88 37,40,92 39,40,98 6,48,12 18,48,38 30,48,62 42,48,88 7,56,12 21,56,38 35,56,62 49,56,88 8,64,12 24,64,38 40,64,62 56,64,88 " +
        "9,72,12 27,72,38 45,72,62 63,72,88 2,80,2 6,80,8 10,80,12 14,80,18 18,80,22 22,80,28 26,80,32 30,80,38 34,80,42 38,80,48 42,80,52 46,80,57 " +
        "50,80,62 54,80,68 58,80,72 62,80,78 66,80,82 70,80,88 74,80,92 78,80,98 11,88,12 33,88,38 55,88,62 77,88,88 12,96,12 36,96,38 60,96,62 84,96,88 " +
        "13,104,12 39,104,38 65,104,62 91,104,88 14,112,12 42,112,38 70,112,62 98,112,88 3,120,2 9,120,8 15,120,12 21,120,18 27,120,22 33,120,28 " +
        "39,120,32 45,120,38 51,120,42 57,120,48 63,120,52 69,120,57 75,120,62 81,120,68 87,120,72 93,120,78 99,120,82 105,120,88 111,120,92 117,120,98 " +
        "16,128,12 48,128,38 80,128,62 112,128,88 17,136,12 51,136,38 85,136,62 119,136,88 18,144,12 54,144,38 90,144,62 126,144,88 19,152,12 57,152,38 " +
        "95,152,62 133,152,88 4,160,2 12,160,8 20,160,12 28,160,18 36,160,22 44,160,28 52,160,32 60,160,38 68,160,42 76,160,48 84,160,52 92,160,57 " +
        "100,160,62 108,160,68 116,160,72 124,160,78 132,160,82 140,160,88 148,160,92 156,160,98 21,168,12 63,168,38 105,168,62 147,168,88 22,176,12 " +
        "66,176,38 110,176,62 154,176,88 23,184,12 69,184,38 115,184,62 161,184,88 24,192,12 72,192,38 120,192,62 168,192,88 1,200,0 3,200,2 5,200,2 " +
        "7,200,4 9,200,4 11,200,6 13,200,6 15,200,8 17,200,8 19,200,10 21,200,10 23,200,12 25,200,12 27,200,14 29,200,14 31,200,16 33,200,16 35,200,18 " +
        "37,200,18 39,200,20 41,200,20 43,200,22 45,200,22 47,200,24 49,200,24 51,200,26 53,200,26 55,200,28 57,200,28 59,200,30 61,200,30 63,200,32 " +
        "65,200,32 67,200,34 69,200,34 71,200,36 73,200,36 75,200,38 77,200,38 79,200,40 81,200,40 83,200,42 85,200,42 87,200,44 89,200,44 91,200,46 " +
        "93,200,46 95,200,48 97,200,48 99,200,50 101,200,50 103,200,52 105,200,52 107,200,54 109,200,55 111,200,56 113,200,56 115,200,57 117,200,58 " +
        "119,200,60 121,200,60 123,200,62 125,200,62 127,200,64 129,200,64 131,200,66 133,200,66 135,200,68 137,200,68 139,200,70 141,200,70 143,200,72 " +
        "145,200,72 147,200,74 149,200,74 151,200,76 153,200,76 155,200,78 157,200,78 159,200,80 161,200,80 163,200,82 165,200,82 167,200,84 169,200,84 " +
        "171,200,86 173,200,86 175,200,88 177,200,88 179,200,90 181,200,90 183,200,92 185,200,92 187,200,94 189,200,94 191,200,96 193,200,96 195,200,98 " +
        "197,200,98 199,200,100";

    [Fact]
    public void MetPct_rounds_as_Windows_PowerShell_does_at_every_midpoint()
    {
        var cases = PowerShellMidpoints.Split(' ').Select(c => c.Split(',').Select(n => int.Parse(n, CultureInfo.InvariantCulture)).ToArray()).ToList();
        Assert.Equal(260, cases.Count);

        var wrong = cases
            .Where(c => Rollup(met: c[0], attention: c[1] - c[0]).MetPct != c[2])
            .Select(c => $"{c[0]}/{c[1]}: expected {c[2]}, got {Rollup(met: c[0], attention: c[1] - c[0]).MetPct}")
            .ToList();

        Assert.True(wrong.Count == 0, string.Join('\n', wrong));
    }

    [Theory]
    // Half to even, not away from zero: 12.5 is 12 and 37.5 is 38.
    [InlineData(1, 7, 0, 12)]
    [InlineData(3, 5, 0, 38)]
    // 23/40 is 57.49999999999999 in floating point, so 57, as PowerShell has it.
    [InlineData(23, 17, 0, 57)]
    [InlineData(1, 1, 1, 33)]
    [InlineData(2, 1, 0, 67)]
    [InlineData(0, 3, 0, 0)]
    [InlineData(4, 0, 0, 100)]
    public void MetPct_is_the_share_of_applicable_checks_that_pass(int met, int attention, int confirm, int expected)
    {
        Assert.Equal(expected, Rollup(met, attention, confirm).MetPct);
    }

    [Fact]
    public void MetPct_is_0_when_nothing_applies_and_not_applicable_checks_do_not_count()
    {
        var rollup = Rollup(met: 0, attention: 0, confirm: 0, notApplicable: 4);

        Assert.Equal(0, rollup.Applicable);
        Assert.Equal(0, rollup.MetPct);
    }

    [Fact]
    public void Applicable_is_met_attention_and_confirm()
    {
        Assert.Equal(9, Rollup(met: 3, attention: 5, confirm: 1, notApplicable: 7).Applicable);
    }

    [Fact]
    public void On_track_counts_the_test_cases_likely_to_pass_out_of_five()
    {
        var rollup = new CePlusRollup
        {
            TestCases = new CePlusTestCaseStates
            {
                TC1 = CePlusState.LikelyPass,
                TC2 = CePlusState.LikelyFail,
                TC3 = CePlusState.Check,
                TC4 = CePlusState.NotAssessed,
                TC5 = CePlusState.LikelyPass,
            },
        };

        Assert.Equal(2, rollup.OnTrack);
        Assert.Equal(5, rollup.Total);
        Assert.Equal("Cyber Essentials Plus", rollup.Label);
    }

    [Fact]
    public void Counts_findings_by_status()
    {
        var counts = StatusCounts.Of([FindingStatus.Pass, FindingStatus.Pass, FindingStatus.Error, FindingStatus.NotApplicable, FindingStatus.Warn]);

        Assert.Equal(new StatusCounts { Pass = 2, Error = 1, NotApplicable = 1, Warn = 1 }, counts);
    }

    private static FrameworkRollup Rollup(int met, int attention, int confirm = 0, int notApplicable = 0)
    {
        return new FrameworkRollup { Label = "x", Met = met, Attention = attention, Confirm = confirm, NotApplicable = notApplicable };
    }
}
