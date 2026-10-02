using System.Security;
using Engramic.Baseline.Platform;
using Win32 = Microsoft.Win32;

namespace Engramic.Baseline.Windows;

/// <summary>
/// The registry primitive on Windows: reads a value, or lists a key's subkeys, in the hive and view the caller names.
/// </summary>
/// <remarks>
/// The one file that may use Microsoft.Win32.RegistryKey (src/BannedApiExemptions.txt). Every key is opened
/// from its hive's base key in the named view, read-only, and values are returned as stored: text of type
/// REG_EXPAND_SZ is not expanded from this process's environment.
/// </remarks>
public sealed class WindowsRegistry : IRegistry
{
    /// <inheritdoc/>
    public RegistryValue? GetValue(RegistryHive hive, RegistryView view, string keyPath, string valueName)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyPath);
        ArgumentNullException.ThrowIfNull(valueName);
        var baseHive = ToBaseHive(hive);
        var baseView = ToBaseView(view);

        object? data;
        Win32.RegistryValueKind kind;
        try
        {
#pragma warning disable RS0030 // The registry primitive: opens the named view read-only and reads one value, unexpanded
            using var root = Win32.RegistryKey.OpenBaseKey(baseHive, baseView);
            using var key = root.OpenSubKey(keyPath, writable: false);
            if (key is null)
            {
                return null;
            }

            data = key.GetValue(valueName, null, Win32.RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (data is null)
            {
                return null;
            }

            kind = key.GetValueKind(valueName);
#pragma warning restore RS0030
        }
        catch (SecurityException e)
        {
            throw new UnauthorizedAccessException($"The registry key {keyPath} cannot be read by this account.", e);
        }

        return ToRegistryValue(kind, data);
    }

    /// <inheritdoc/>
    public IReadOnlyList<string>? GetSubKeyNames(RegistryHive hive, RegistryView view, string keyPath)
    {
        ArgumentNullException.ThrowIfNull(keyPath);
        var baseHive = ToBaseHive(hive);
        var baseView = ToBaseView(view);
        try
        {
#pragma warning disable RS0030 // The registry primitive: opens the named view read-only and lists a key's subkeys
            using var root = Win32.RegistryKey.OpenBaseKey(baseHive, baseView);
            if (keyPath.Length == 0)
            {
                return root.GetSubKeyNames();
            }

            using var key = root.OpenSubKey(keyPath, writable: false);
            return key?.GetSubKeyNames();
#pragma warning restore RS0030
        }
        catch (SecurityException e)
        {
            throw new UnauthorizedAccessException($"The registry key {keyPath} cannot be listed by this account.", e);
        }
    }

    /// <summary>
    /// A value from its registry type and the object RegistryKey.GetValue returned for it.
    /// </summary>
    /// <remarks>
    /// The object is not always of the type the registry type suggests: a REG_DWORD whose data is longer
    /// than 4 bytes comes back as a long, or as bytes when longer than 8, a REG_QWORD longer than 8 bytes
    /// comes back as bytes, and the value can change between reading it and asking its type. A value whose
    /// object does not match its type is an Other value, with the bytes of the number when it is one, rather
    /// than an exception.
    /// </remarks>
    internal static RegistryValue ToRegistryValue(Win32.RegistryValueKind kind, object data)
    {
        return (kind, data) switch
        {
            (Win32.RegistryValueKind.String, string text) => RegistryValue.FromText(text),
            (Win32.RegistryValueKind.ExpandString, string text) => RegistryValue.FromExpandText(text),
            (Win32.RegistryValueKind.MultiString, string[] lines) => RegistryValue.FromMultiText(lines),
            (Win32.RegistryValueKind.DWord, int number) => RegistryValue.FromDWord(unchecked((uint)number)),
            (Win32.RegistryValueKind.QWord, long number) => RegistryValue.FromQWord(unchecked((ulong)number)),
            (Win32.RegistryValueKind.Binary, byte[] bytes) => RegistryValue.FromBinary(bytes),
            (_, byte[] bytes) => RegistryValue.FromOther(bytes),
            (_, int number) => RegistryValue.FromOther(BitConverter.GetBytes(number)),
            (_, long number) => RegistryValue.FromOther(BitConverter.GetBytes(number)),
            _ => RegistryValue.FromOther([]),
        };
    }

    private static Win32.RegistryHive ToBaseHive(RegistryHive hive) => hive switch
    {
        RegistryHive.LocalMachine => Win32.RegistryHive.LocalMachine,
        RegistryHive.Users => Win32.RegistryHive.Users,
        _ => throw new ArgumentOutOfRangeException(nameof(hive), hive, "Not a hive the registry primitive reads."),
    };

    private static Win32.RegistryView ToBaseView(RegistryView view) => view switch
    {
        RegistryView.Registry64 => Win32.RegistryView.Registry64,
        RegistryView.Registry32 => Win32.RegistryView.Registry32,
        _ => throw new ArgumentOutOfRangeException(nameof(view), view, "Not a registry view."),
    };
}
