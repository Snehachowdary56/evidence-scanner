namespace EvidenceScanner.Core;

/// <summary>Walks an evidence folder (read-only) and runs every analyzer on every file.</summary>
public sealed class Scanner
{
    private readonly IReadOnlyList<IFileAnalyzer> _analyzers;

    public Scanner(IEnumerable<IFileAnalyzer> analyzers)
    {
        _analyzers = analyzers.ToList();
        if (_analyzers.Count == 0 || _analyzers[0] is not HashAnalyzer)
        {
            throw new ArgumentException("HashAnalyzer must run first, because other analyzers use the hash.");
        }
    }

    /// <summary>The standard set of checks.</summary>
    public static Scanner CreateDefault(IReadOnlyDictionary<string, string>? knownBad = null,
                                        IEnumerable<string>? keywords = null) =>
        new(new IFileAnalyzer[]
        {
            new HashAnalyzer(),
            new SignatureAnalyzer(),
            new KnownHashAnalyzer(knownBad ?? new Dictionary<string, string>()),
            new KeywordAnalyzer(keywords ?? Array.Empty<string>()),
        });

    public ScanResult Scan(string evidenceRoot, string examiner = "unknown")
    {
        if (!Directory.Exists(evidenceRoot))
        {
            throw new DirectoryNotFoundException($"Evidence folder not found: {evidenceRoot}");
        }

        var root = Path.GetFullPath(evidenceRoot);
        var items = new List<EvidenceItem>();
        var errors = new List<string>();
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = 0 };

        foreach (var path in Directory.EnumerateFiles(root, "*", options).OrderBy(p => p, StringComparer.Ordinal))
        {
            var relative = Path.GetRelativePath(root, path).Replace('\\', '/');
            try
            {
                var info = new FileInfo(path);
                var item = new EvidenceItem(relative, info.Length, info.CreationTimeUtc, info.LastWriteTimeUtc, info.LastAccessTimeUtc);
                if ((info.Attributes & FileAttributes.Hidden) != 0 || info.Name.StartsWith('.'))
                {
                    item.Findings.Add(new Finding("Attributes", Severity.Low, "Hidden file"));
                }

                foreach (var analyzer in _analyzers)
                {
                    analyzer.Analyze(item, path);
                }

                items.Add(item);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                errors.Add($"{relative}: {ex.Message}"); // one unreadable file never stops the scan
            }
        }

        return new ScanResult
        {
            EvidenceRoot = root,
            Examiner = examiner,
            ScannedAtUtc = DateTime.UtcNow,
            Items = items,
            Errors = errors,
        };
    }

    /// <summary>All created/modified events in time order, for the case timeline.</summary>
    public static IReadOnlyList<TimelineEvent> BuildTimeline(ScanResult result) =>
        result.Items
              .SelectMany(i => new[]
              {
                  new TimelineEvent(i.CreatedUtc, "created", i.RelativePath),
                  new TimelineEvent(i.ModifiedUtc, "modified", i.RelativePath),
              })
              .OrderBy(e => e.TimestampUtc)
              .ThenBy(e => e.RelativePath, StringComparer.Ordinal)
              .ToList();
}
