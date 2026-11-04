using System.Diagnostics;
using System.Security.Principal;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>Reads the real process list, and finds this test process in it as Windows describes it.</summary>
public sealed class WindowsProcessListTests
{
    private readonly IReadOnlyList<RunningProcess> _processes = new WindowsProcessList().Read();

    [Fact]
    public void Lists_this_process_with_its_image_command_line_and_session()
    {
        using var current = Process.GetCurrentProcess();

        var self = Assert.Single(_processes, p => p.Id == (uint)Environment.ProcessId);

        Assert.Equal(Environment.ProcessPath, self.ImagePath, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(Path.GetFileName(Environment.ProcessPath), self.ImageName, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(Path.GetFileNameWithoutExtension(Environment.ProcessPath!), self.CommandLine!, StringComparison.OrdinalIgnoreCase);
        Assert.Equal((uint)current.SessionId, self.SessionId);
        Assert.Contains(_processes, p => p.Id == self.ParentId);
    }

    [Fact]
    public void Reads_the_owner_and_elevation_of_this_process_from_its_token()
    {
        using var identity = WindowsIdentity.GetCurrent();

        var self = Assert.Single(_processes, p => p.Id == (uint)Environment.ProcessId);

        Assert.Equal(identity.User!.Value, self.Owner?.Value);
        Assert.Equal(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator), self.IsElevated);
    }

    [Fact]
    public void Lists_the_system_process_and_leaves_out_the_idle_process()
    {
        Assert.Contains(_processes, p => p.Id == 4 && p.ParentId == 0 && p.ImageName == "System");
        Assert.DoesNotContain(_processes, p => p.Id == 0);
    }

    [Fact]
    public void Lists_each_process_once()
    {
        Assert.Equal(_processes.Count, _processes.Select(p => p.Id).Distinct().Count());
    }

    [Fact]
    public void Leaves_unknown_what_this_account_may_not_read()
    {
        Assert.SkipWhen(Elevation.IsElevated, "An elevated administrator may read the System process's token.");

        // A standard user may not open SYSTEM's token: the entry is still listed, by its name.
        var system = Assert.Single(_processes, p => p.Id == 4);

        Assert.Null(system.Owner);
        Assert.Null(system.IsElevated);
        Assert.All(_processes, p => Assert.False(string.IsNullOrEmpty(p.ImageName)));
    }

    [Fact]
    public void Reads_SYSTEM_as_the_owner_of_its_services_when_elevated()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);

        Assert.Contains(_processes, p => p.Owner == Sid.LocalSystem && p.IsElevated == true && p.SessionId == 0);
    }
}
