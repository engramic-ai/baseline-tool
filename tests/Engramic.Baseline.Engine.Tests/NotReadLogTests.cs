namespace Engramic.Baseline.Engine.Tests;

public sealed class NotReadLogTests
{
    [Fact]
    public void Records_the_same_location_kind_reason_and_topic_once_with_a_count()
    {
        var log = new NotReadLog();

        log.Add(@"%USERPROFILE%\.vscode\extensions", NotReadKind.FolderListing, "a link", "vscode", needsUserSession: true);
        log.Add(@"%USERPROFILE%\.vscode\extensions", NotReadKind.FolderListing, "a link", "vscode", needsUserSession: true);
        log.Add(@"%USERPROFILE%\.vscode\extensions", NotReadKind.FolderListing, "a link", "paths");
        log.Add(@"%USERPROFILE%\.claude.json", NotReadKind.FileContent, "too large", "mcp", "Shrink it.");

        Assert.Equal(
            [
                new NotReadRecord(@"%USERPROFILE%\.vscode\extensions", NotReadKind.FolderListing, "a link", string.Empty, "vscode", true, 2),
                new NotReadRecord(@"%USERPROFILE%\.vscode\extensions", NotReadKind.FolderListing, "a link", string.Empty, "paths", false, 1),
                new NotReadRecord(@"%USERPROFILE%\.claude.json", NotReadKind.FileContent, "too large", "Shrink it.", "mcp", false, 1),
            ],
            log.Records);
    }

    [Fact]
    public void A_new_log_is_empty()
    {
        Assert.Empty(new NotReadLog().Records);
    }
}
