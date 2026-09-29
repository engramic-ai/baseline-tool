namespace Engramic.Baseline.Invariants.Tests;

/// <summary>Finds files in the source tree that the tests read.</summary>
internal static class Repository
{
    private static readonly Lazy<string> RootPath = new(FindRoot);

    /// <summary>Gets the repository root: the nearest folder above the tests that holds Baseline.slnx.</summary>
    public static string Root => RootPath.Value;

    /// <summary>Gets a full path from a path relative to the root, with forward slashes.</summary>
    public static string PathOf(string relative) => Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar));

    /// <summary>Gets a path relative to the root, with forward slashes.</summary>
    public static string RelativePathOf(string fullPath) => Path.GetRelativePath(Root, fullPath).Replace('\\', '/');

    /// <summary>Lists the files under a folder of the repository, leaving out build output.</summary>
    public static IEnumerable<string> FilesUnder(string relativeFolder, string searchPattern)
    {
        return Directory.EnumerateFiles(PathOf(relativeFolder), searchPattern, SearchOption.AllDirectories)
            .Where(f => !RelativePathOf(f).Split('/').Any(part => part is "bin" or "obj" or "artifacts" or ".git" or ".vs"))
            .Order(StringComparer.Ordinal);
    }

    private static string FindRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Baseline.slnx")))
            {
                return dir.FullName;
            }
        }

        throw new InvalidOperationException("Baseline.slnx was not found above " + AppContext.BaseDirectory);
    }
}
