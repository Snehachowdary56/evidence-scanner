using EvidenceScanner.Core;

namespace EvidenceScanner.Tests;

public class IntegrityAndReportTests
{
    private static (TempFolder Dir, ScanResult Result) ScanDemo()
    {
        var dir = new TempFolder();
        var evidence = Path.Combine(dir.Path, "evidence");
        var result = Scanner.CreateDefault(DemoEvidence.Create(evidence), DemoEvidence.Keywords).Scan(evidence, "tester");
        return (dir, result);
    }

    [Fact]
    public void Verify_UntouchedEvidence_IsIntact()
    {
        var (dir, result) = ScanDemo();
        using (dir)
        {
            var verify = Integrity.Verify(Integrity.CreateManifest(result), result.EvidenceRoot);

            Assert.True(verify.IsIntact);
            Assert.Equal(8, verify.Unchanged.Count);
        }
    }

    [Fact]
    public void Verify_DetectsModifiedMissingAndAddedFiles()
    {
        var (dir, result) = ScanDemo();
        using (dir)
        {
            var manifest = Integrity.CreateManifest(result);
            var root = result.EvidenceRoot;
            File.AppendAllText(Path.Combine(root, "Documents", "meeting_notes.txt"), "tampered");
            File.Delete(Path.Combine(root, "Pictures", "logo.png"));
            File.WriteAllText(Path.Combine(root, "Downloads", "new.txt"), "planted later");

            var verify = Integrity.Verify(manifest, root);

            Assert.False(verify.IsIntact);
            Assert.Equal(new[] { "Documents/meeting_notes.txt" }, verify.Modified);
            Assert.Equal(new[] { "Pictures/logo.png" }, verify.Missing);
            Assert.Equal(new[] { "Downloads/new.txt" }, verify.Added);
        }
    }

    [Fact]
    public void Manifest_SavesAndLoadsRoundTrip()
    {
        var (dir, result) = ScanDemo();
        using (dir)
        {
            var path = Path.Combine(dir.Path, "manifest.json");
            Integrity.Save(Integrity.CreateManifest(result), path);

            var loaded = Integrity.Load(path);

            Assert.Equal("tester", loaded.Examiner);
            Assert.Equal(8, loaded.Files.Count);
            Assert.True(Integrity.Verify(loaded, result.EvidenceRoot).IsIntact);
        }
    }

    [Fact]
    public void Reports_AreWrittenWithEveryFile()
    {
        var (dir, result) = ScanDemo();
        using (dir)
        {
            IReportWriter[] writers = { new CsvReportWriter(), new JsonReportWriter(), new MarkdownReportWriter() };
            foreach (var w in writers)
            {
                w.Write(result, dir.Path);
            }

            var csv = File.ReadAllLines(Path.Combine(dir.Path, "evidence.csv"));
            Assert.Equal(9, csv.Length); // header + 8 files
            Assert.Contains("\"sha256\"", File.ReadAllText(Path.Combine(dir.Path, "evidence.json")).ToLowerInvariant());
            Assert.Contains("invoice_october.pdf", File.ReadAllText(Path.Combine(dir.Path, "case_report.md")));
        }
    }

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    public void Csv_EscapesCommasAndQuotes(string input, string expected)
    {
        Assert.Equal(expected, CsvReportWriter.Csv(input));
    }
}
