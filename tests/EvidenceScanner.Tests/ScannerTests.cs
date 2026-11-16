using EvidenceScanner.Core;

namespace EvidenceScanner.Tests;

public class ScannerTests
{
    [Fact]
    public void Demo_FindsAllFourPlantedItems()
    {
        using var dir = new TempFolder();
        var knownBad = DemoEvidence.Create(dir.Path);

        var result = Scanner.CreateDefault(knownBad, DemoEvidence.Keywords).Scan(dir.Path, "tester");
        var flagged = result.Flagged.Select(i => i.RelativePath).ToList();

        Assert.Equal(8, result.Items.Count);
        Assert.Equal(4, flagged.Count);
        Assert.Contains("Downloads/invoice_october.pdf", flagged);
        Assert.Contains("Downloads/setup_tool.exe", flagged);
        Assert.Contains("Pictures/beach.jpg", flagged);
        Assert.Contains("Documents/.plans.txt", flagged);
    }

    [Fact]
    public void Demo_NormalFilesAreNotFlagged()
    {
        using var dir = new TempFolder();
        var result = Scanner.CreateDefault(DemoEvidence.Create(dir.Path), DemoEvidence.Keywords).Scan(dir.Path);
        var flagged = result.Flagged.Select(i => i.RelativePath).ToHashSet();

        Assert.DoesNotContain("Documents/report.pdf", flagged);
        Assert.DoesNotContain("Pictures/holiday.jpg", flagged);
        Assert.DoesNotContain("Documents/meeting_notes.txt", flagged);
    }

    [Fact]
    public void Flagged_AreOrderedMostSevereFirst()
    {
        using var dir = new TempFolder();
        var result = Scanner.CreateDefault(DemoEvidence.Create(dir.Path), DemoEvidence.Keywords).Scan(dir.Path);
        var severities = result.Flagged.Select(i => (int)i.HighestSeverity).ToList();

        Assert.Equal(severities.OrderByDescending(s => s).ToList(), severities);
    }

    [Fact]
    public void Scan_IncludesSubfoldersAndUsesForwardSlashes()
    {
        using var dir = new TempFolder();
        dir.Text("a/b/c/deep.txt", "x");

        var result = Scanner.CreateDefault().Scan(dir.Path);

        Assert.Equal("a/b/c/deep.txt", Assert.Single(result.Items).RelativePath);
    }

    [Fact]
    public void Scan_MissingFolder_Throws()
    {
        Assert.Throws<DirectoryNotFoundException>(() => Scanner.CreateDefault().Scan("/no/such/folder/xyz"));
    }

    [Fact]
    public void Scanner_RequiresHashAnalyzerFirst()
    {
        Assert.Throws<ArgumentException>(() => new Scanner(new IFileAnalyzer[] { new SignatureAnalyzer() }));
    }

    [Fact]
    public void Timeline_IsInTimeOrder_WithTwoEventsPerFile()
    {
        using var dir = new TempFolder();
        var result = Scanner.CreateDefault(DemoEvidence.Create(dir.Path)).Scan(dir.Path);

        var timeline = Scanner.BuildTimeline(result);

        Assert.Equal(result.Items.Count * 2, timeline.Count);
        Assert.Equal(timeline.OrderBy(e => e.TimestampUtc).Select(e => e.TimestampUtc).ToList(),
                     timeline.Select(e => e.TimestampUtc).ToList());
        Assert.Equal("Documents/report.pdf", timeline[0].RelativePath);
    }
}
