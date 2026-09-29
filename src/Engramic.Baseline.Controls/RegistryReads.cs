using System.Globalization;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Controls;

/// <summary>
/// Reads registry values the way the PowerShell tool's checks see them: Get-CERegistryValue, which gives a
/// default for a key or value that is missing or cannot be read, then an [int] or [string] cast.
/// </summary>
/// <remarks>
/// Values that Windows writes convert exactly as in PowerShell. Two cases differ on purpose. A value that
/// is not a number where one is expected (text [int] cannot read, a list, bytes, or a number too big for
/// an int) counts as missing here, where the cast would throw and stop the PowerShell audit. REG_EXPAND_SZ
/// text is used as written, where Get-ItemProperty expands it from the environment of whoever started
/// the process.
/// </remarks>
internal static class RegistryReads
{
    /// <summary>Reads a value from HKEY_LOCAL_MACHINE in the 64-bit view, or null when missing or unreadable.</summary>
    public static RegistryValue? LocalMachine(IRegistry registry, string keyPath, string valueName)
    {
        try
        {
            return registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, keyPath, valueName);
        }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    /// <summary>A value as PowerShell's [int] cast makes it, or the default when missing or not a number.</summary>
    public static int ToInt32(RegistryValue? value, int fallback)
    {
        return value?.Kind switch
        {
            // REG_DWORD reaches PowerShell as a signed Int32, so 0xFFFFFFFF is -1.
            RegistryValueKind.DWord => unchecked((int)(uint)value.Number!.Value),
            // REG_QWORD reaches PowerShell as a signed Int64, which [int] takes only when it fits.
            RegistryValueKind.QWord => unchecked((long)value.Number!.Value) is var n and >= int.MinValue and <= int.MaxValue ? (int)n : fallback,
            RegistryValueKind.Text or RegistryValueKind.ExpandText => ParseInt32(value.Text!, fallback),
            _ => fallback,
        };
    }

    /// <summary>A value as PowerShell's [string] cast makes it, or the default when missing.</summary>
    public static string ToText(RegistryValue? value, string fallback)
    {
        return value?.Kind switch
        {
            null => fallback,
            RegistryValueKind.Text or RegistryValueKind.ExpandText => value.Text!,
            // An array joins with $OFS, a space.
            RegistryValueKind.MultiText => string.Join(' ', value.Lines),
            RegistryValueKind.DWord => unchecked((int)(uint)value.Number!.Value).ToString(CultureInfo.InvariantCulture),
            RegistryValueKind.QWord => unchecked((long)value.Number!.Value).ToString(CultureInfo.InvariantCulture),
            _ => string.Join(' ', value.Bytes.ToArray().Select(b => b.ToString(CultureInfo.InvariantCulture))),
        };
    }

    /// <summary>
    /// Text as a number, as [int] reads it: empty text is 0; white space around the number, a sign,
    /// thousands separators and an exponent are allowed; a fraction rounds half to even. Anything else,
    /// including white space alone and a number too big for an int, is not a number here, where [int]
    /// throws. Hexadecimal text such as 0x10, which [int] also reads, is not a number here either.
    /// </summary>
    private static int ParseInt32(string text, int fallback)
    {
        if (text.Length == 0)
        {
            return 0;
        }

        const NumberStyles style = NumberStyles.Float | NumberStyles.AllowThousands;
        if (int.TryParse(text, NumberStyles.Integer | NumberStyles.AllowThousands, CultureInfo.InvariantCulture, out var whole))
        {
            return whole;
        }

        if (double.TryParse(text, style, CultureInfo.InvariantCulture, out var number))
        {
            var rounded = Math.Round(number, MidpointRounding.ToEven);
            if (rounded is >= int.MinValue and <= int.MaxValue)
            {
                return (int)rounded;
            }
        }

        return fallback;
    }
}
