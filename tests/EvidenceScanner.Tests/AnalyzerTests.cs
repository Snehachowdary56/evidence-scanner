using EvidenceScanner.Core;

namespace EvidenceScanner.Tests;

public class AnalyzerTests
{
    private static EvidenceItem ItemFor(string fullPath, string relative)
    {
        var info = new FileInfo(fullPath);
        return new EvidenceItem(relative, info.Length, info.CreationTimeUtc, info.LastWriteTimeUtc, info.LastAccessTimeUtc);
    }

    [Fact]
    public void Hash_MatchesKnownSha256AndMd5()
    {
        using var dir = new TempFolder();
        var path = dir.Text("abc.txt", "abc");
        var item = ItemFor(path, "abc.txt");

        new HashAnalyzer().Analyze(item, path);

        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", item.Sha256);
        Assert.Equal("900150983cd24fb0d6963f7d28e17f72", item.Md5);
    }

    [Fact]
    public void Hash_DoesNotModifyTheEvidenceFile()
    {
        using var dir = new TempFolder();
        var path = dir.Text("a.txt", "evidence");
        var before = File.GetLastWriteTimeUtc(path);

        new HashAnalyzer().Analyze(ItemFor(path, "a.txt"), path);

        Assert.Equal(before, File.GetLastWriteTimeUtc(path));
        Assert.Equal("evidence", File.ReadAllText(path));
    }

    [Theory]
    [InlineData("doc.pdf", new byte[] { 0x25, 0x50, 0x44, 0x46, 0x2D }, "PDF")]
    [InlineData("pic.png", new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D }, "PNG image")]
    [InlineData("pic.jpeg", new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 }, "JPEG image")]
    [InlineData("report.docx", new byte[] { 0x50, 0x4B, 0x03, 0x04 }, "ZIP archive (or Office file)")]
    public void Signature_CorrectExtension_HasNoFinding(string name, byte[] header, string expectedType)
    {
        using var dir = new TempFolder();
        var path = dir.File(name, header.Concat(new byte[64]).ToArray());
        var item = ItemFor(path, name);

        new SignatureAnalyzer().Analyze(item, path);

        Assert.Equal(expectedType, item.DetectedType);
        Assert.Empty(item.Findings);
    }

    [Fact]
    public void Signature_ProgramDisguisedAsPdf_IsHigh()
    {
        using var dir = new TempFolder();
        var path = dir.File("invoice.pdf", new byte[] { 0x4D, 0x5A, 0x90, 0x00 });
        var item = ItemFor(path, "invoice.pdf");

        new SignatureAnalyzer().Analyze(item, path);

        var finding = Assert.Single(item.Findings);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Contains("Windows executable", finding.Message);
    }

    [Fact]
    public void Signature_ArchiveDisguisedAsPhoto_IsMedium()
    {
        using var dir = new TempFolder();
        var path = dir.File("beach.jpg", new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x00 });
        var item = ItemFor(path, "beach.jpg");

        new SignatureAnalyzer().Analyze(item, path);

        Assert.Equal(Severity.Medium, Assert.Single(item.Findings).Severity);
    }

    [Fact]
    public void Signature_PlainText_IsDetectedAsText()
    {
        using var dir = new TempFolder();
        var path = dir.Text("notes.txt", "hello world\n");
        var item = ItemFor(path, "notes.txt");

        new SignatureAnalyzer().Analyze(item, path);

        Assert.Equal("Text", item.DetectedType);
        Assert.Empty(item.Findings);
    }

    [Fact]
    public void Signature_EmptyFile_IsUnknownAndDoesNotCrash()
    {
        using var dir = new TempFolder();
        var path = dir.File("empty.bin", Array.Empty<byte>());
        var item = ItemFor(path, "empty.bin");

        new SignatureAnalyzer().Analyze(item, path);

        Assert.Equal("Unknown", item.DetectedType);
    }

    [Fact]
    public void KnownHash_MatchIsHigh_AndCaseInsensitive()
    {
        using var dir = new TempFolder();
        var path = dir.Text("abc.txt", "abc");
        var item = ItemFor(path, "abc.txt");
        new HashAnalyzer().Analyze(item, path);
        var list = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"] = "test sample",
        };

        new KnownHashAnalyzer(list).Analyze(item, path);

        Assert.Equal(Severity.High, Assert.Single(item.Findings).Severity);
    }

    [Fact]
    public void KnownHash_LoadHashList_SkipsCommentsAndBlankLines()
    {
        using var dir = new TempFolder();
        var path = dir.Text("bad.txt", "# known bad\n\naaa111, malware A\nbbb222\n");

        var map = KnownHashAnalyzer.LoadHashList(path);

        Assert.Equal(2, map.Count);
        Assert.Equal("malware A", map["AAA111"]);
        Assert.Equal("known bad", map["bbb222"]);
    }

    [Fact]
    public void Keyword_FindsCaseInsensitiveMatchesWithLineNumbers()
    {
        using var dir = new TempFolder();
        var path = dir.Text("note.txt", "first line\nsend the WIRE TRANSFER today\nnothing here\n");
        var item = ItemFor(path, "note.txt");
        item.DetectedType = "Text";

        new KeywordAnalyzer(new[] { "wire transfer", "bitcoin" }).Analyze(item, path);

        var finding = Assert.Single(item.Findings);
        Assert.Contains("line(s) 2", finding.Message);
    }

    [Fact]
    public void Keyword_SkipsBinaryFiles()
    {
        using var dir = new TempFolder();
        var path = dir.Text("x.bin", "bitcoin");
        var item = ItemFor(path, "x.bin");
        item.DetectedType = "Windows executable";

        new KeywordAnalyzer(new[] { "bitcoin" }).Analyze(item, path);

        Assert.Empty(item.Findings);
    }
}
