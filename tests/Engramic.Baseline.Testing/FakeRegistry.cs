using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Testing;

/// <summary>
/// A registry in memory. Keys and value names match without regard to case, as in Windows, and each view
/// holds its own values, so a test can show which view a reader used.
/// </summary>
public sealed class FakeRegistry : IRegistry
{
    private readonly Dictionary<(RegistryHive Hive, RegistryView View, string Key), Dictionary<string, RegistryValue>> _keys = new(new KeyComparer());
    private readonly HashSet<(RegistryHive Hive, RegistryView View, string Key)> _denied = new(new KeyComparer());
    private readonly List<(RegistryHive Hive, RegistryView View, string Key, string Name)> _reads = [];

    /// <summary>Gets every read, in order, so a test can check the hive and view a reader named.</summary>
    public IReadOnlyList<(RegistryHive Hive, RegistryView View, string Key, string Name)> Reads => _reads;

    /// <summary>Sets a value, creating its key. The 64-bit view unless another is named.</summary>
    public FakeRegistry Set(RegistryHive hive, string key, string name, RegistryValue value, RegistryView view = RegistryView.Registry64)
    {
        if (!_keys.TryGetValue((hive, view, key), out var values))
        {
            values = new Dictionary<string, RegistryValue>(StringComparer.OrdinalIgnoreCase);
            _keys[(hive, view, key)] = values;
        }

        values[name] = value;
        return this;
    }

    /// <summary>Creates a key with no values.</summary>
    public FakeRegistry CreateKey(RegistryHive hive, string key, RegistryView view = RegistryView.Registry64)
    {
        _keys.TryAdd((hive, view, key), new Dictionary<string, RegistryValue>(StringComparer.OrdinalIgnoreCase));
        return this;
    }

    /// <summary>Makes every read of a key fail as access denied.</summary>
    public FakeRegistry Deny(RegistryHive hive, string key, RegistryView view = RegistryView.Registry64)
    {
        _denied.Add((hive, view, key));
        return this;
    }

    /// <inheritdoc/>
    public RegistryValue? GetValue(RegistryHive hive, RegistryView view, string keyPath, string valueName)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyPath);
        ArgumentNullException.ThrowIfNull(valueName);
        _reads.Add((hive, view, keyPath, valueName));
        if (_denied.Contains((hive, view, keyPath)))
        {
            throw new UnauthorizedAccessException($"Access to the registry key {keyPath} is denied.");
        }

        return _keys.TryGetValue((hive, view, keyPath), out var values) && values.TryGetValue(valueName, out var value) ? value : null;
    }

    private sealed class KeyComparer : IEqualityComparer<(RegistryHive Hive, RegistryView View, string Key)>
    {
        public bool Equals((RegistryHive Hive, RegistryView View, string Key) x, (RegistryHive Hive, RegistryView View, string Key) y)
        {
            return x.Hive == y.Hive && x.View == y.View && string.Equals(x.Key.TrimEnd('\\'), y.Key.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }

        public int GetHashCode((RegistryHive Hive, RegistryView View, string Key) obj)
        {
            return HashCode.Combine(obj.Hive, obj.View, StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Key.TrimEnd('\\')));
        }
    }
}
