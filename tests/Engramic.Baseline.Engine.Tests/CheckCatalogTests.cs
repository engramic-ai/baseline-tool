using Engramic.Baseline.Model;

namespace Engramic.Baseline.Engine.Tests;

public sealed class CheckCatalogTests
{
    [Fact]
    public void Keeps_the_checks_in_the_order_they_were_added()
    {
        var catalog = Samples.Catalog(new FakeCheck(Samples.Info("SU-02")), new FakeCheck(Samples.Info("FW-01")));

        Assert.Equal(["SU-02", "FW-01"], catalog.Checks.Select(c => c.Info.Id));
    }

    [Fact]
    public void Finds_a_check_without_regard_to_case()
    {
        var check = new FakeCheck(Samples.Info("SU-01"));
        var catalog = Samples.Catalog(check);

        Assert.Same(check, catalog.Find("su-01"));
        Assert.Null(catalog.Find("SU-02"));
    }

    [Fact]
    public void Refuses_a_second_check_with_the_same_identifier()
    {
        var builder = new CheckCatalog.Builder().Add(new FakeCheck(Samples.Info("SU-01")));

        var error = Assert.Throws<ArgumentException>(() => builder.Add(new FakeCheck(Samples.Info("SU-01") with { Title = "Another" })));

        Assert.StartsWith("Duplicate check id", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SU-1")]
    [InlineData("su-01")]
    [InlineData("SU_01")]
    [InlineData("")]
    public void Refuses_an_identifier_that_is_not_well_formed(string id)
    {
        var info = Samples.Info("SU-01") with { Id = id };

        Assert.Throws<ArgumentException>(() => new CheckCatalog.Builder().Add(new FakeCheck(info)));
    }

    [Fact]
    public void Refuses_a_check_without_a_title_a_reference_or_a_framework()
    {
        var info = Samples.Info("SU-01");

        Assert.Throws<ArgumentException>(() => new CheckCatalog.Builder().Add(new FakeCheck(info with { Title = " " })));
        Assert.Throws<ArgumentException>(() => new CheckCatalog.Builder().Add(new FakeCheck(info with { Reference = string.Empty })));
        Assert.Throws<ArgumentException>(() => new CheckCatalog.Builder().Add(new FakeCheck(info with { Frameworks = [] })));
        Assert.Throws<ArgumentException>(() => new CheckCatalog.Builder().Add(new FakeCheck(info with { Frameworks = ["CE v3.3", ""] })));
        Assert.Throws<ArgumentException>(() => new CheckCatalog.Builder().Add(new FakeCheck(info with { Severity = (Severity)42 })));
    }

    [Fact]
    public void Selects_by_identifier_theme_framework_and_scope_and_leaves_out_excluded_checks()
    {
        var catalog = Samples.Catalog(
            new FakeCheck(Samples.Info("FW-01", CheckCategory.Firewalls, frameworks: [FrameworkTags.CeV33, FrameworkTags.Ncsc])),
            new FakeCheck(Samples.Info("SU-01", frameworks: [FrameworkTags.CeV33, FrameworkTags.CePlusTC2])),
            new FakeCheck(Samples.Info("NC-04", CheckCategory.NCSCHardening, frameworks: [FrameworkTags.Ncsc])),
            new FakeCheck(Samples.Info("UA-10", CheckCategory.UserAccessControl, frameworks: [FrameworkTags.Ncsc], scope: CheckScope.User)));

        List<string> Ids(CheckSelection selection) => [.. catalog.Select(selection).Select(c => c.Info.Id)];

        Assert.Equal(["FW-01", "SU-01", "NC-04", "UA-10"], Ids(CheckSelection.All));
        Assert.Equal(["SU-01"], Ids(new CheckSelection { Ids = ["su-01", "XX-99"] }));
        Assert.Equal(["FW-01", "NC-04"], Ids(new CheckSelection { Categories = [CheckCategory.Firewalls, CheckCategory.NCSCHardening] }));
        // A framework matches the start of a tag, without regard to case: CE matches CE v3.3 and CE+ TC2.
        Assert.Equal(["FW-01", "SU-01"], Ids(new CheckSelection { Frameworks = ["ce"] }));
        Assert.Equal(["SU-01"], Ids(new CheckSelection { Frameworks = ["CE+"] }));
        Assert.Equal(["UA-10"], Ids(new CheckSelection { Scopes = [CheckScope.User] }));
        Assert.Equal(["FW-01", "UA-10"], Ids(new CheckSelection { Frameworks = ["NCSC"], ExcludeIds = ["nc-04"] }));
        Assert.Empty(Ids(new CheckSelection { Ids = ["SU-01"], Categories = [CheckCategory.Firewalls] }));
    }
}
