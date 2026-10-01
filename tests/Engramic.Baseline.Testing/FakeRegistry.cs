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
    private readonly List<(RegistryHive Hive, string Key, Action<FakeRegistry> Then)> _afterListing = [];

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

    /// <summary>Deletes a key and every key below it, as when a hive is unloaded.</summary>
    public FakeRegistry RemoveTree(RegistryHive hive, string key, RegistryView view = RegistryView.Registry64)
    {
        var trimmed = key.TrimEnd('\\');
        foreach (var path in _keys.Keys.Where(k => k.Hive == hive && k.View == view
            && (string.Equals(k.Key.TrimEnd('\\'), trimmed, StringComparison.OrdinalIgnoreCase) || k.Key.StartsWith(trimmed + "\\", StringComparison.OrdinalIgnoreCase))).ToList())
        {
            _keys.Remove(path);
        }

        return this;
    }

    /// <summary>
    /// Changes the registry once, right after the first time a key's subkeys are listed, as when a hive is unloaded
    /// while a reader goes through what it listed.
    /// </summary>
    public FakeRegistry AfterListing(RegistryHive hive, string key, Action<FakeRegistry> then)
    {
        _afterListing.Add((hive, key.TrimEnd('\\'), then));
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

    /// <inheritdoc/>
    /// <remarks>A key exists when it was created or has values, or a key below it does; its subkeys are the next names down.</remarks>
    public IReadOnlyList<string>? GetSubKeyNames(RegistryHive hive, RegistryView view, string keyPath)
    {
        ArgumentNullException.ThrowIfNull(keyPath);
        var key = keyPath.TrimEnd('\\');
        if (_denied.Contains((hive, view, key)))
        {
            throw new UnauthorizedAccessException($"Access to the registry key {keyPath} is denied.");
        }

        var prefix = key.Length == 0 ? string.Empty : key + "\\";
        var exists = key.Length == 0;
        var names = new List<string>();
        foreach (var (h, v, path) in _keys.Keys)
        {
            var trimmed = path.TrimEnd('\\');
            if (h != hive || v != view)
            {
                continue;
            }

            if (string.Equals(trimmed, key, StringComparison.OrdinalIgnoreCase))
            {
                exists = true;
            }
            else if (trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                exists = true;
                var child = trimmed[prefix.Length..].Split('\\')[0];
                if (!names.Contains(child, StringComparer.OrdinalIgnoreCase))
                {
                    names.Add(child);
                }
            }
        }

        var after = _afterListing.FindIndex(a => a.Hive == hive && string.Equals(a.Key, key, StringComparison.OrdinalIgnoreCase));
        if (after >= 0)
        {
            var then = _afterListing[after].Then;
            _afterListing.RemoveAt(after);
            then(this);
        }

        return exists ? names : null;
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
