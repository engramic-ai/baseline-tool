namespace Engramic.Baseline.Platform;

/// <summary>
/// The type of a registry value.
/// </summary>
public enum RegistryValueKind
{
    /// <summary>REG_SZ: text.</summary>
    Text,

    /// <summary>REG_EXPAND_SZ: text that may name environment variables, kept as written, never expanded.</summary>
    ExpandText,

    /// <summary>REG_MULTI_SZ: a list of text.</summary>
    MultiText,

    /// <summary>REG_DWORD: a 32-bit number.</summary>
    DWord,

    /// <summary>REG_QWORD: a 64-bit number.</summary>
    QWord,

    /// <summary>REG_BINARY: bytes.</summary>
    Binary,

    /// <summary>REG_NONE or any other type: bytes, as stored.</summary>
    Other,
}
