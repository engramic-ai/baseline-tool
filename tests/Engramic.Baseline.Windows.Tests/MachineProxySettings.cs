using System.Diagnostics;
using System.Net.NetworkInformation;
using Microsoft.Win32;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// Changes to the machine's proxy settings for the SYSTEM tests, each put back exactly when disposed: the WinHTTP
/// proxy, set with netsh as an administrator sets it, and names for WPAD in the hosts file. Only the explicit
/// SYSTEM tests use these, on a throwaway CI runner.
/// </summary>
internal static class MachineProxySettings
{
    private const string ConnectionsKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";
    private const string WinHttpSettings = "WinHttpSettings";

    private static string HostsFile => Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");

    /// <summary>Sets the machine's WinHTTP proxy with netsh, and puts the setting back as it was, byte for byte, when disposed.</summary>
    public static IDisposable SetWinHttpProxy(string proxy, string bypass)
    {
        byte[]? saved;
        using (var key = OpenConnections(writable: false))
        {
            saved = key?.GetValue(WinHttpSettings) as byte[];
        }

        var restore = new Restore(() =>
        {
            using var key = OpenConnections(writable: true);
            if (key is null)
            {
                return;
            }

            if (saved is null)
            {
                key.DeleteValue(WinHttpSettings, throwOnMissingValue: false);
            }
            else
            {
                key.SetValue(WinHttpSettings, saved, RegistryValueKind.Binary);
            }
        });
        try
        {
            Run("netsh.exe", "winhttp", "set", "proxy", "proxy-server=" + proxy, "bypass-list=" + bypass);
            return restore;
        }
        catch
        {
            restore.Dispose();
            throw;
        }
    }

    /// <summary>Points names at 127.0.0.1 in the hosts file, and puts the file back as it was when disposed.</summary>
    public static IDisposable AddHostNames(IEnumerable<string> names)
    {
        var saved = File.Exists(HostsFile) ? File.ReadAllBytes(HostsFile) : null;
        var restore = new Restore(() =>
        {
            Retry(() =>
            {
                if (saved is null)
                {
                    File.Delete(HostsFile);
                }
                else
                {
                    File.WriteAllBytes(HostsFile, saved);
                }
            });
            Run("ipconfig.exe", "/flushdns");
        });
        try
        {
            var lines = names.Select(n => "127.0.0.1 " + n);
            Retry(() => File.AppendAllText(HostsFile, "\r\n# Engramic Baseline service client test\r\n" + string.Join("\r\n", lines) + "\r\n"));
            Run("ipconfig.exe", "/flushdns");
            return restore;
        }
        catch
        {
            restore.Dispose();
            throw;
        }
    }

    /// <summary>
    /// The names WPAD may look up by DNS on this machine: wpad under the primary DNS suffix, each connection's
    /// suffix and the search list, each shortened a label at a time down to two, and wpad alone.
    /// </summary>
    public static IReadOnlyList<string> WpadNames()
    {
        var suffixes = new List<string> { IPGlobalProperties.GetIPGlobalProperties().DomainName };
        suffixes.AddRange(NetworkInterface.GetAllNetworkInterfaces().Select(n => n.GetIPProperties().DnsSuffix));
        using (var parameters = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"))
        {
            if (parameters?.GetValue("SearchList") is string searchList)
            {
                suffixes.AddRange(searchList.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries));
            }
        }

        var names = new SortedSet<string>(StringComparer.OrdinalIgnoreCase) { "wpad" };
        foreach (var suffix in suffixes.Select(s => (s ?? string.Empty).Trim().Trim('.')).Where(s => s.Length > 0))
        {
            var labels = suffix.Split('.');
            for (var i = 0; i == 0 || i <= labels.Length - 2; i++)
            {
                names.Add("wpad." + string.Join('.', labels[i..]));
            }
        }

        return [.. names];
    }

    /// <summary>Clears WinHTTP's record of what WPAD found, so that a lookup looks again.</summary>
    public static void ResetAutoProxy() => Run("netsh.exe", "winhttp", "reset", "autoproxy");

    /// <summary>Runs a tool from System32, hidden, and returns what it printed; throws if it fails.</summary>
    public static string Run(string tool, params string[] arguments)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, tool))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException($"{tool} did not start.");
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(TimeSpan.FromSeconds(60)))
        {
            process.Kill();
            throw new TimeoutException($"{tool} {string.Join(' ', arguments)} did not finish within 60 seconds.");
        }

        var printed = output.Result + errors.Result;
        return process.ExitCode == 0 ? printed : throw new InvalidOperationException($"{tool} {string.Join(' ', arguments)} exited with {process.ExitCode}: {printed}");
    }

    /// <summary>Writes the hosts file, trying again for a few seconds while another process, such as a scan, holds it.</summary>
    private static void Retry(Action write)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                write();
                return;
            }
            catch (IOException) when (attempt < 10)
            {
                Thread.Sleep(200 * attempt);
            }
        }
    }

    private static RegistryKey? OpenConnections(bool writable)
    {
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        return machine.OpenSubKey(ConnectionsKey, writable);
    }

    private sealed class Restore(Action undo) : IDisposable
    {
        private Action? _undo = undo;

        public void Dispose()
        {
            Interlocked.Exchange(ref _undo, null)?.Invoke();
        }
    }
}
