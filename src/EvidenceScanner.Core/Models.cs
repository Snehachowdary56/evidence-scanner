namespace EvidenceScanner.Core;

/// <summary>How serious a finding is.</summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

/// <summary>Something an analyzer noticed about a file, with the reason in plain words.</summary>
public sealed record Finding(string Analyzer, Severity Severity, string Message);

/// <summary>One file in the evidence folder and everything we learned about it.</summary>
public sealed class EvidenceItem
{
    public EvidenceItem(string relativePath, long sizeBytes, DateTime createdUtc, DateTime modifiedUtc, DateTime accessedUtc)
    {
        RelativePath = relativePath;
        SizeBytes = sizeBytes;
        CreatedUtc = createdUtc;
        ModifiedUtc = modifiedUtc;
        AccessedUtc = accessedUtc;
    }

    public string RelativePath { get; }
    public long SizeBytes { get; }
    public DateTime CreatedUtc { get; }
    public DateTime ModifiedUtc { get; }
    public DateTime AccessedUtc { get; }

    public string Extension => Path.GetExtension(RelativePath).TrimStart('.').ToLowerInvariant();

    public string? Sha256 { get; set; }
    public string? Md5 { get; set; }

    /// <summary>File type detected from the file's first bytes, e.g. "PDF" or "Windows executable".</summary>
    public string? DetectedType { get; set; }

    public List<Finding> Findings { get; } = new();

    public Severity HighestSeverity => Findings.Count == 0 ? Severity.Info : Findings.Max(f => f.Severity);
}

/// <summary>A single dated event for the case timeline.</summary>
public sealed record TimelineEvent(DateTime TimestampUtc, string Event, string RelativePath);

/// <summary>The result of one scan.</summary>
public sealed class ScanResult
{
    public required string EvidenceRoot { get; init; }
    public required string Examiner { get; init; }
    public required DateTime ScannedAtUtc { get; init; }
    public required IReadOnlyList<EvidenceItem> Items { get; init; }
    public required IReadOnlyList<string> Errors { get; init; }

    public IEnumerable<EvidenceItem> Flagged => Items.Where(i => i.HighestSeverity >= Severity.Medium)
                                                     .OrderByDescending(i => i.HighestSeverity)
                                                     .ThenBy(i => i.RelativePath, StringComparer.Ordinal);
}
