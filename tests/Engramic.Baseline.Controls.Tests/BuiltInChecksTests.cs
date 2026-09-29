using Engramic.Baseline.Engine;
using Engramic.Baseline.Model;

namespace Engramic.Baseline.Controls.Tests;

/// <summary>
/// The catalog is written by hand, so these tests prove it is complete: every check in this library is
/// listed once, and every identifier and framework tag is one the file formats accept.
/// </summary>
public sealed class BuiltInChecksTests
{
    private static readonly CheckCatalog Catalog = BuiltInChecks.CreateCatalog();

    [Fact]
    public void Every_check_in_the_library_is_in_the_catalog_once()
    {
        var types = typeof(BuiltInChecks).Assembly.GetTypes()
            .Where(t => t.IsSubclassOf(typeof(Check)) && !t.IsAbstract)
            .OrderBy(t => t.FullName, StringComparer.Ordinal)
            .ToList();
        var listed = Catalog.Checks.Select(c => c.GetType()).OrderBy(t => t.FullName, StringComparer.Ordinal).ToList();

        Assert.NotEmpty(types);
        Assert.Equal(types, listed);
    }

    [Fact]
    public void Identifiers_are_well_formed_and_unique()
    {
        var ids = Catalog.Checks.Select(c => c.Info.Id).ToList();

        Assert.All(ids, id => Assert.True(CheckIds.IsWellFormed(id), id));
        Assert.Equal(ids.Count, ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void Every_framework_tag_is_a_known_one()
    {
        Assert.All(Catalog.Checks, c => Assert.All(c.Info.Frameworks, tag => Assert.Contains(tag, FrameworkTags.All)));
    }

    [Fact]
    public void Checks_are_in_report_order_by_theme_then_identifier()
    {
        var order = Catalog.Checks.Select(c => (c.Info.Category, c.Info.Id)).ToList();

        Assert.Equal(order.OrderBy(o => o.Category).ThenBy(o => o.Id, StringComparer.Ordinal), order);
    }

    [Fact]
    public void Each_check_s_details_are_a_fixed_instance()
    {
        Assert.All(Catalog.Checks, c => Assert.Same(c.Info, c.Info));
    }

    [Fact]
    public void SU_01_has_the_PowerShell_tool_s_details()
    {
        var info = Catalog.Find("SU-01")!.Info;

        Assert.Equal("Operating system is licensed and supported by Microsoft", info.Title);
        Assert.Equal(CheckCategory.SecurityUpdateManagement, info.Category);
        Assert.Equal(Severity.Critical, info.Severity);
        Assert.Equal(["CE v3.3", "CE+ TC2"], info.Frameworks);
        Assert.Equal("CE v3.3 Security update management: all software must be licensed and supported, and removed when it becomes unsupported.", info.Reference);
        Assert.Equal(CheckScope.Machine, info.Scope);
        Assert.True(info.AutoFail);
        Assert.False(info.RequiresAdmin);
    }

    [Fact]
    public void Checks_are_not_public()
    {
        // Other code reaches a check only through the catalog.
        Assert.All(Catalog.Checks, c => Assert.False(c.GetType().IsPublic, c.GetType().Name));
        Assert.DoesNotContain(typeof(BuiltInChecks).Assembly.GetExportedTypes(), t => t.IsSubclassOf(typeof(Check)));
    }
}
