using System.Security.Principal;

namespace Engramic.Baseline.Windows.Tests;

public sealed class CurrentProcessTests
{
    [Fact]
    public void Reads_the_account_as_Windows_names_it()
    {
        using var identity = WindowsIdentity.GetCurrent();

        var account = CurrentProcess.ReadAccount();

        Assert.Equal(identity.Name, account.Name);
        Assert.Contains('\\', account.Name);
        Assert.Equal(identity.IsSystem, account.IsLocalSystem);
        Assert.Equal(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator), account.IsAdministrator);
    }
}
