using System.CommandLine;
using System.CommandLine.Help;

namespace Engramic.Baseline.Cli;

/// <summary>The entry point of baseline.exe.</summary>
internal static class Program
{
    /// <summary>Runs the command line.</summary>
    /// <param name="args">The arguments.</param>
    /// <returns>The exit code: 0 on success.</returns>
    private static int Main(string[] args)
    {
        var root = new RootCommand("Engramic Baseline: audits this Windows device against Cyber Essentials v3.3 and NCSC device guidance.");

        // The commands arrive as they are ported. Until then, run on its own it shows the help.
        root.SetAction(parseResult => new HelpAction().Invoke(parseResult));

        return root.Parse(args).Invoke();
    }
}
