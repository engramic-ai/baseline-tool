namespace Engramic.Baseline.Platform;

/// <summary>
/// Which registry view a read uses. Every read names one, so no read depends on whether the process is
/// 32-bit or 64-bit: a 32-bit process would otherwise be sent to the WOW6432Node copies of some keys.
/// </summary>
public enum RegistryView
{
    /// <summary>The 64-bit view, which holds the operating system's own settings. On 32-bit Windows, the only view.</summary>
    Registry64,

    /// <summary>The 32-bit view that 32-bit programs see on 64-bit Windows, such as their uninstall entries.</summary>
    Registry32,
}
