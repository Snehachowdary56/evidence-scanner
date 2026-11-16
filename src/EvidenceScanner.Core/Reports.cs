using System.Globalization;
using System.Text;
using System.Text.Json;

namespace EvidenceScanner.Core;

/// <summary>Writes the scan in a format an investigator or another tool can use.</summary>
public interface IReportWriter
{
    string FileName { get; }
    void Write(ScanResult result, string outputDirectory);
}

/// <summary>One row per file, for Excel.</summary>
public sealed class CsvReportWriter : IReportWriter
{
    public string FileName => "evidence.csv";

    public void Write(ScanResult result, string outputDirectory)
    {
        var sb = new StringBuilder();
        sb.AppendLine("path,size_bytes,detected_type,severity,sha256,md5,created_utc,modified_utc,findings");
        foreach (var i in result.Items)
        {
            sb.AppendLine(string.Join(',', new[]
            {
                Csv(i.RelativePath), i.SizeBytes.ToString(CultureInfo.InvariantCulture), Csv(i.DetectedType ?? ""),
                i.HighestSeverity.ToString(), i.Sha256 ?? "", i.Md5 ?? "", Iso(i.CreatedUtc), Iso(i.ModifiedUtc),
                Csv(string.Join(" | ", i.Findings.Select(f => f.Message))),
            }));
        }

        File.WriteAllText(Path.Combine(outputDirectory, FileName), sb.ToString());
    }

    internal static string Csv(string value) =>
        value.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;

    internal static string Iso(DateTime utc) => utc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}

/// <summary>Machine-readable report for other tools.</summary>
public sealed class JsonReportWriter : IReportWriter
{
    public string FileName => "evidence.json";

    public void Write(ScanResult result, string outputDirectory)
    {
        var payload = new
        {
            result.Examiner,
            result.EvidenceRoot,
            result.ScannedAtUtc,
            FileCount = result.Items.Count,
            Items = result.Items.Select(i => new
            {
                i.RelativePath, i.SizeBytes, i.DetectedType, Severity = i.HighestSeverity.ToString(),
                i.Sha256, i.Md5, i.CreatedUtc, i.ModifiedUtc,
                Findings = i.Findings.Select(f => new { f.Analyzer, Severity = f.Severity.ToString(), f.Message }),
            }),
            result.Errors,
        };
        File.WriteAllText(Path.Combine(outputDirectory, FileName),
            JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
    }
}

/// <summary>A short, readable case summary with flagged files and the timeline.</summary>
public sealed class MarkdownReportWriter : IReportWriter
{
    public string FileName => "case_report.md";

    public void Write(ScanResult result, string outputDirectory)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Evidence scan report");
        sb.AppendLine();
        sb.AppendLine($"- Examiner: {result.Examiner}");
        sb.AppendLine($"- Scanned (UTC): {CsvReportWriter.Iso(result.ScannedAtUtc)}");
        sb.AppendLine($"- Files scanned: **{result.Items.Count}**, flagged: **{result.Flagged.Count()}**, unreadable: {result.Errors.Count}");
        sb.AppendLine();
        sb.AppendLine("## Flagged files");
        sb.AppendLine();
        sb.AppendLine("| Severity | File | Real type | Why |");
        sb.AppendLine("|---|---|---|---|");
        foreach (var i in result.Flagged)
        {
            sb.AppendLine($"| {i.HighestSeverity} | {i.RelativePath} | {i.DetectedType} | {string.Join("; ", i.Findings.Select(f => f.Message))} |");
        }

        sb.AppendLine();
        sb.AppendLine("## Timeline (UTC)");
        sb.AppendLine();
        foreach (var e in Scanner.BuildTimeline(result))
        {
            sb.AppendLine($"- {CsvReportWriter.Iso(e.TimestampUtc)}  {e.Event,-8}  {e.RelativePath}");
        }

        File.WriteAllText(Path.Combine(outputDirectory, FileName), sb.ToString());
    }
}
