using EvidenceScanner.Core;

// Commands:
//   demo   [--out output]                         create sample evidence and scan it
//   scan   <folder> [--out output] [--hashes bad.txt] [--keywords a,b] [--examiner name]
//   verify <folder> <manifest.json>                check nothing changed since the scan
return Cli.Run(args);

internal static class Cli
{
    public static int Run(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help")
        {
            PrintHelp();
            return 0;
        }

        try
        {
            return args[0] switch
            {
                "demo" => Demo(Option(args, "--out") ?? "output"),
                "scan" when args.Length >= 2 => Scan(args[1], Option(args, "--out") ?? "output",
                    Option(args, "--hashes"), Option(args, "--keywords"), Option(args, "--examiner") ?? Environment.UserName),
                "verify" when args.Length >= 3 => Verify(args[1], args[2]),
                _ => Fail("Unknown command or missing arguments. Run with --help."),
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return Fail(ex.Message);
        }
    }

    private static int Demo(string outDir)
    {
        var evidence = Path.Combine(outDir, "sample_evidence");
        if (Directory.Exists(evidence))
        {
            Directory.Delete(evidence, recursive: true);
        }

        var knownBad = DemoEvidence.Create(evidence);
        Console.WriteLine($"Created SAMPLE evidence folder: {evidence}");
        return ScanAndReport(evidence, outDir, knownBad, DemoEvidence.Keywords, "demo examiner");
    }

    private static int Scan(string folder, string outDir, string? hashFile, string? keywords, string examiner)
    {
        var knownBad = hashFile is null ? new Dictionary<string, string>() : KnownHashAnalyzer.LoadHashList(hashFile);
        var words = keywords?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    ?? Array.Empty<string>();
        return ScanAndReport(folder, outDir, knownBad, words, examiner);
    }

    private static int ScanAndReport(string folder, string outDir, IReadOnlyDictionary<string, string> knownBad,
                                     IEnumerable<string> keywords, string examiner)
    {
        Directory.CreateDirectory(outDir);
        var result = Scanner.CreateDefault(knownBad, keywords).Scan(folder, examiner);

        IReportWriter[] writers = { new CsvReportWriter(), new JsonReportWriter(), new MarkdownReportWriter() };
        foreach (var w in writers)
        {
            w.Write(result, outDir);
        }

        var manifestPath = Path.Combine(outDir, "manifest.json");
        Integrity.Save(Integrity.CreateManifest(result), manifestPath);

        Console.WriteLine();
        Console.WriteLine($"Files scanned: {result.Items.Count}   Flagged: {result.Flagged.Count()}   Unreadable: {result.Errors.Count}");
        Console.WriteLine();
        Console.WriteLine("Flagged files:");
        foreach (var item in result.Flagged)
        {
            Console.WriteLine($"  [{item.HighestSeverity,-6}] {item.RelativePath}");
            foreach (var f in item.Findings.Where(f => f.Severity >= Severity.Low))
            {
                Console.WriteLine($"           - {f.Message}");
            }
        }

        Console.WriteLine();
        foreach (var w in writers)
        {
            Console.WriteLine($"Saved: {Path.Combine(outDir, w.FileName)}");
        }

        Console.WriteLine($"Saved: {manifestPath}  (use 'verify' later to prove nothing changed)");
        return 0;
    }

    private static int Verify(string folder, string manifestPath)
    {
        var result = Integrity.Verify(Integrity.Load(manifestPath), folder);
        Console.WriteLine($"Unchanged: {result.Unchanged.Count}  Modified: {result.Modified.Count}  " +
                          $"Missing: {result.Missing.Count}  Added: {result.Added.Count}");
        foreach (var p in result.Modified) Console.WriteLine($"  MODIFIED  {p}");
        foreach (var p in result.Missing) Console.WriteLine($"  MISSING   {p}");
        foreach (var p in result.Added) Console.WriteLine($"  ADDED     {p}");
        Console.WriteLine(result.IsIntact ? "Evidence is intact." : "WARNING: evidence has changed since the scan.");
        return result.IsIntact ? 0 : 2;
    }

    private static string? Option(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"Error: {message}");
        return 1;
    }

    private static void PrintHelp() => Console.WriteLine("""
        Evidence Scanner - read-only triage of a folder of digital evidence

          demo   [--out output]
          scan   <folder> [--out output] [--hashes known_bad.txt] [--keywords word1,word2] [--examiner name]
          verify <folder> <manifest.json>
        """);
}
