using Engramic.Baseline.Engine;
using Engramic.Baseline.Model;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Windows;

// One call into each AOT-clean library, compiled with Native AOT. Exits 1 if any gives a wrong answer.
var failures = 0;

Check("Model", Utf8Bom.GetBytes("{}") is [0xEF, 0xBB, 0xBF, (byte)'{', (byte)'}']);
Check("Platform", Sid.TryParse("s-1-5-18", out var sid) && sid == Sid.LocalSystem);
Check("Engine", CheckIds.IsWellFormed("SU-01") && !CheckIds.IsWellFormed("SU-1"));
Check("Windows", ConsoleSession.GetActiveSessionId() is null or > 0);

Console.WriteLine(failures == 0 ? "AOT canary: all libraries ran." : $"AOT canary: {failures} failed.");
return failures == 0 ? 0 : 1;

void Check(string library, bool passed)
{
    Console.WriteLine($"{library}: {(passed ? "ok" : "FAILED")}");
    if (!passed)
    {
        failures++;
    }
}
