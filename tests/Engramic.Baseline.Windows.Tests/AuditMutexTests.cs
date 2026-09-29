using System.Security.AccessControl;
using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// The audit mutex, under names of the tests' own: never the product's Global\EngramicBaselineAudit, which a
/// real audit or install on this machine may hold.
/// </summary>
public sealed class AuditMutexTests
{
    private static readonly TimeSpan Short = TimeSpan.FromMilliseconds(200);

    [Fact]
    public void Is_named_as_the_PowerShell_tool_names_it()
    {
        Assert.Equal(@"Global\EngramicBaselineAudit", AuditMutex.MachineName);
    }

    [Fact]
    public void Is_created_with_an_access_list_for_SYSTEM_and_Administrators_alone()
    {
        Assert.Equal("D:P(A;;0x1f0001;;;SY)(A;;0x1f0001;;;BA)", AuditMutex.Security().GetSecurityDescriptorSddlForm(AccessControlSections.All));
    }

    [Fact]
    public void Takes_a_free_mutex_and_releases_it_when_disposed()
    {
        var name = TestMutexes.NewName();

        using (var held = AuditMutex.TryAcquire(name, Short))
        {
            Assert.NotNull(held);
        }

        using var again = AuditMutex.TryAcquire(name, Short);
        Assert.NotNull(again);
    }

    [Fact]
    public void Keeps_out_an_account_its_access_list_does_not_name()
    {
        // The creator's own handle has every right; anyone else is judged by the access list.
        Assert.SkipWhen(Elevation.IsElevated, "An elevated administrator is in the access list.");
        var name = TestMutexes.NewName();
        using var held = AuditMutex.TryAcquire(name, Short);

        var e = Assert.Throws<UnauthorizedAccessException>(() => Mutex.OpenExisting(name).Dispose());

        Assert.Contains(name, e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Lets_an_administrator_open_the_mutex_it_created_and_read_its_access_list()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);
        var name = TestMutexes.NewName();
        using var held = AuditMutex.TryAcquire(name, Short);

        var sddl = TestMutexes.OnOtherThread(() =>
        {
            // Reading the access list needs READ_CONTROL, which Mutex.OpenExisting does not ask for.
            using var opened = MutexAcl.OpenExisting(name, MutexRights.ReadPermissions | MutexRights.Synchronize);
            return opened.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        });

        Assert.Equal("D:P(A;;0x1f0001;;;SY)(A;;0x1f0001;;;BA)", sddl);
    }

    [Fact]
    public void Gives_up_when_another_holder_keeps_it_for_the_whole_time()
    {
        var name = TestMutexes.NewName();
        using var release = new ManualResetEventSlim();
        using var taken = new ManualResetEventSlim();
        var holder = new Thread(() =>
        {
            using var mutex = TestMutexes.OpenableByTheTests(name);
            mutex.WaitOne();
            taken.Set();
            release.Wait();
            mutex.ReleaseMutex();
        });
        holder.Start();
        taken.Wait(TestContext.Current.CancellationToken);

        try
        {
            Assert.Null(AuditMutex.TryAcquire(name, Short));
        }
        finally
        {
            release.Set();
            holder.Join();
        }
    }

    [Fact]
    public void Takes_a_mutex_its_last_holder_abandoned()
    {
        var name = TestMutexes.NewName();
        using var creator = TestMutexes.OpenableByTheTests(name);
        var holder = new Thread(() => TestMutexes.OpenableByTheTests(name).WaitOne());
        holder.Start();
        holder.Join();

        using var held = AuditMutex.TryAcquire(name, Short);

        Assert.NotNull(held);
    }

    [Fact]
    public void Refuses_a_mutex_whose_access_list_leaves_this_account_out_as_access_denied()
    {
        // As a standard user could make it first, to block audits: only SYSTEM may use it.
        Assert.SkipWhen(Elevation.IsSystem, "SYSTEM is in the access list.");
        var name = TestMutexes.NewName();
        using var planted = TestMutexes.Create(name, "D:P(A;;0x1f0001;;;SY)");

        Assert.Throws<UnauthorizedAccessException>(() => TestMutexes.OnOtherThread(() => AuditMutex.TryAcquire(name, Short)));
    }

    [Fact]
    public void Refuses_a_name_that_something_other_than_a_mutex_has()
    {
        var name = TestMutexes.NewName();
        using var planted = new EventWaitHandle(false, EventResetMode.ManualReset, name);

        Assert.Throws<WaitHandleCannotBeOpenedException>(() => AuditMutex.TryAcquire(name, Short));
    }

    [Fact]
    public void Disposing_twice_releases_once()
    {
        var held = AuditMutex.TryAcquire(TestMutexes.NewName(), Short)!;

        held.Dispose();
        held.Dispose();
    }
}
