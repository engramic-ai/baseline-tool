namespace Engramic.Baseline.Platform.Tests;

/// <summary>A service request's limits: the PowerShell tool's 1 to 600 seconds, and 1 KB to 16 MB.</summary>
public sealed class ServiceRequestTests
{
    private static readonly Uri Catalog = new("https://baseline.engramic.ai/v1/firmware/dell/0CF1");

    [Fact]
    public void Defaults_to_20_seconds_and_64_KB_with_no_ETag()
    {
        var request = new ServiceRequest(Catalog);

        Assert.Equal(TimeSpan.FromSeconds(20), request.Timeout);
        Assert.Equal(65_536, request.MaxBytes);
        Assert.Null(request.ETag);
        Assert.Same(Catalog, request.Uri);
    }

    [Fact]
    public void Takes_limits_within_the_range()
    {
        var request = new ServiceRequest(Catalog) { Timeout = TimeSpan.FromSeconds(1), MaxBytes = 1_024, ETag = "\"abc\"" };
        var longest = request with { Timeout = TimeSpan.FromSeconds(600), MaxBytes = 16_777_216 };

        Assert.Equal(TimeSpan.FromSeconds(1), request.Timeout);
        Assert.Equal(1_024, request.MaxBytes);
        Assert.Equal("\"abc\"", request.ETag);
        Assert.Equal(TimeSpan.FromSeconds(600), longest.Timeout);
        Assert.Equal(16_777_216, longest.MaxBytes);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(999)]
    [InlineData(600_001)]
    public void Refuses_a_time_outside_1_to_600_seconds(int milliseconds)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ServiceRequest(Catalog) { Timeout = TimeSpan.FromMilliseconds(milliseconds) });
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1_023)]
    [InlineData(16_777_217)]
    public void Refuses_a_size_limit_outside_1_KB_to_16_MB(int bytes)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ServiceRequest(Catalog) { MaxBytes = bytes });
    }

    [Fact]
    public void Needs_an_absolute_address()
    {
        Assert.Throws<ArgumentException>(() => new ServiceRequest(new Uri("v1/firmware", UriKind.Relative)));
        Assert.Throws<ArgumentNullException>(() => new ServiceRequest(null!));
    }
}
