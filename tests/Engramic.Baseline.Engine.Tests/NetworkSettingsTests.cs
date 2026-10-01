using System.Text;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;

namespace Engramic.Baseline.Engine.Tests;

/// <summary>
/// The service client's proxy settings, read from network.json through the config files: through the config trust
/// gate, which puts an administrator's override in front of the shipped copy.
/// </summary>
public sealed class NetworkSettingsTests
{
    private const string OverridePath = @"C:\ProgramData\EngramicBaseline\config\network.json";
    private const string Shipped = """{ "notes": "shipped", "proxyUrl": "", "proxyUseDefaultCredentials": false, "useWinHttpProxyWhenSystem": true, "proxyAutoConfigUrl": "", "proxyAutoDetect": true }""";

    private static readonly ProcessAccount LocalSystem = new(@"NT AUTHORITY\SYSTEM", IsAdministrator: true, IsLocalSystem: true);

    private readonly FakeSecureStore _store = new();

    [Fact]
    public void Reads_the_settings_of_network_json()
    {
        var files = new ConfigFiles(new()
        {
            ["network.json"] = """
                {
                  "proxyUrl": "http://proxy.contoso.com:8080",
                  "proxyUseDefaultCredentials": true,
                  "useWinHttpProxyWhenSystem": false,
                  "proxyAutoConfigUrl": "https://pac.contoso.com/proxy.pac",
                  "proxyAutoDetect": false
                }
                """,
        });

        var settings = NetworkSettings.Read(files);

        Assert.Equal("http://proxy.contoso.com:8080", settings.ProxyUrl);
        Assert.True(settings.ProxyUseDefaultCredentials);
        Assert.False(settings.UseWinHttpProxyWhenSystem);
        Assert.Equal("https://pac.contoso.com/proxy.pac", settings.ProxyAutoConfigUrl);
        Assert.False(settings.ProxyAutoDetect);
        Assert.Empty(settings.Problems);
    }

    [Fact]
    public void A_missing_file_gives_the_defaults_and_says_so()
    {
        var settings = NetworkSettings.Read(new ConfigFiles());

        Assert.Equal(string.Empty, settings.ProxyUrl);
        Assert.True(settings.UseWinHttpProxyWhenSystem);
        Assert.True(settings.ProxyAutoDetect);
        Assert.Equal(["config/network.json is missing, so the proxy settings are the defaults."], settings.Problems);
    }

    [Fact]
    public void A_file_that_is_not_valid_gives_the_defaults_and_says_why()
    {
        var settings = NetworkSettings.Read(new ConfigFiles(new() { ["network.json"] = """{ "proxyUrl": "http://proxy.contoso.com:8080", """ }));

        Assert.Equal(string.Empty, settings.ProxyUrl);
        Assert.False(settings.ProxyUseDefaultCredentials);
        Assert.StartsWith("config/network.json is not valid, so the proxy settings are the defaults: ", Assert.Single(settings.Problems), StringComparison.Ordinal);
    }

    [Fact]
    public void An_address_that_is_no_text_gives_the_defaults_and_says_why()
    {
        var settings = NetworkSettings.Read(new ConfigFiles(new() { ["network.json"] = """{ "proxyUrl": "\ud800", "proxyAutoDetect": false }""" }));

        Assert.True(settings.ProxyAutoDetect);
        Assert.StartsWith("config/network.json is not valid, so the proxy settings are the defaults: ", Assert.Single(settings.Problems), StringComparison.Ordinal);
    }

    [Fact]
    public void Through_the_trust_gate_an_administrator_s_override_replaces_the_shipped_settings_whole()
    {
        _store.WriteFile(DataFolder.Config, "network.json", Encoding.UTF8.GetBytes("""{ "proxyUrl": "http://proxy.contoso.com:8080", "proxyAutoDetect": false }"""));
        var gate = Gate();

        var settings = NetworkSettings.Read(gate);

        Assert.Equal("http://proxy.contoso.com:8080", settings.ProxyUrl);
        Assert.False(settings.ProxyAutoDetect);
        Assert.True(settings.UseWinHttpProxyWhenSystem);
        Assert.Empty(settings.Problems);
        Assert.Equal([OverridePath], gate.Overrides);
        Assert.Empty(gate.Notices);
    }

    [Fact]
    public void Through_the_trust_gate_an_override_that_does_not_meet_its_schema_leaves_the_shipped_settings_and_the_gate_says_why()
    {
        // Not the defaults with a problem on every route: the gate refuses the override before it is read here, and
        // the run reports the gate's notice once.
        _store.WriteFile(DataFolder.Config, "network.json", Encoding.UTF8.GetBytes("""{ "proxyUrl": "http://proxy.contoso.com:8080", "proxyurl": "" }"""));
        var gate = Gate();

        var settings = NetworkSettings.Read(gate);

        Assert.Equal(string.Empty, settings.ProxyUrl);
        Assert.True(settings.ProxyAutoDetect);
        Assert.Empty(settings.Problems);
        Assert.Equal(
            [$"Ignoring the config override network.json and using the shipped copy: {OverridePath} names proxyurl more than once in one object (line 1), so which value counts is not clear."],
            gate.Notices);
        Assert.Empty(gate.Overrides);
    }

    [Fact]
    public void An_override_the_trust_gate_could_not_read_throws_rather_than_give_the_defaults()
    {
        // As a standard user can bring about by locking the override: the defaults would undo it unseen.
        const string Reason = OverridePath + " could not be read: The process cannot access the file because another process has locked a portion of the file (Win32 error 33).";
        _store.FailRead(DataFolder.Config, "network.json", new SecureStoreException(Reason, isUnavailable: true, null));
        var gate = Gate();

        var e = Assert.Throws<IOException>(() => NetworkSettings.Read(gate));

        Assert.Equal($"The config override {OverridePath} could not be read, so the shipped copy is not used in its place: {Reason}", e.Message);
        Assert.Single(gate.Notices);
    }

    private ConfigTrustGate Gate() => new(new ConfigFiles(new() { ["network.json"] = Shipped }), _store, LocalSystem);
}
