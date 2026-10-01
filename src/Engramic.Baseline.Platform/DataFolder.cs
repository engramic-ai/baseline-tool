namespace Engramic.Baseline.Platform;

/// <summary>
/// A folder of the machine data folder that holds the tool's files: the data folder itself, or one of the
/// folders made in it, each locked from birth (<see cref="DataFolderLayout"/>).
/// </summary>
public enum DataFolder
{
    /// <summary>The data folder itself: status.json and last-error.json.</summary>
    Root,

    /// <summary>The logs of the scheduled audit and the install (logs).</summary>
    Logs,

    /// <summary>The report folders of each audit (reports).</summary>
    Reports,

    /// <summary>Administrators' config overrides (config), which standard users may read.</summary>
    Config,

    /// <summary>Answers the tool keeps between runs, such as the firmware catalog's (cache).</summary>
    Cache,

    /// <summary>The undo journals of fixes applied elevated or as SYSTEM (undo).</summary>
    Undo,
}
