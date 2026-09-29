using System.Reflection;
using System.Runtime.Versioning;

namespace Engramic.Baseline.Windows.Tests;

public sealed class ConsoleSessionTests
{
    [Fact]
    public void The_console_session_is_never_the_services_session()
    {
        // Services have run alone in session 0 since Windows Vista; a signed-in console is session 1 or later.
        var id = ConsoleSession.GetActiveSessionId();

        Assert.True(id is null or > 0, $"The console session was {id}.");
    }

    [Fact]
    public void The_library_declares_Windows_10_1607_as_its_minimum()
    {
        // Directory.Build.targets writes this attribute; CA1416 reads it to flag calls to newer APIs.
        var platforms = typeof(ConsoleSession).Assembly.GetCustomAttributes<SupportedOSPlatformAttribute>();

        Assert.Equal("windows10.0.14393", Assert.Single(platforms).PlatformName);
    }
}
