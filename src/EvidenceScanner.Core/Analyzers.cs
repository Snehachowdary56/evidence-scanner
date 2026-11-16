using System.Security.Cryptography;
using System.Text;

namespace EvidenceScanner.Core;

/// <summary>
/// One check that runs on every file. New checks are added by writing a new class that
/// implements this interface, without changing the scanner (open/closed principle).
/// </summary>
public interface IFileAnalyzer
{
    string Name { get; }
    void Analyze(EvidenceItem item, string fullPath);
}

/// <summary>Computes SHA-256 and MD5 fingerprints. Any change to a file changes its hash.</summary>
public sealed class HashAnalyzer : IFileAnalyzer
{
    public string Name => "Hash";

    public void Analyze(EvidenceItem item, string fullPath)
    {
        using var stream = File.OpenRead(fullPath); // read-only: evidence is never modified
        item.Sha256 = Convert.ToHexStringLower(SHA256.HashData(stream));
        stream.Position = 0;
        item.Md5 = Convert.ToHexStringLower(MD5.HashData(stream));
    }

    public static string Sha256OfFile(string fullPath)
    {
        using var stream = File.OpenRead(fullPath);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }
}

/// <summary>
/// Detects the real file type from its first bytes ("magic numbers") and flags files whose
/// extension hides their real type, e.g. a program renamed to invoice.pdf.
/// </summary>
public sealed class SignatureAnalyzer : IFileAnalyzer
{
    private sealed record Signature(string Type, byte[] Magic, string[] Extensions, bool Executable = false);

    private static readonly Signature[] Signatures =
    {
        new("Windows executable", "MZ"u8.ToArray(), new[] { "exe", "dll", "sys", "scr" }, Executable: true),
        new("Linux executable", new byte[] { 0x7F, 0x45, 0x4C, 0x46 }, new[] { "elf", "so", "bin", "" }, Executable: true),
        new("PDF", "%PDF"u8.ToArray(), new[] { "pdf" }),
        new("PNG image", new byte[] { 0x89, 0x50, 0x4E, 0x47 }, new[] { "png" }),
        new("JPEG image", new byte[] { 0xFF, 0xD8, 0xFF }, new[] { "jpg", "jpeg" }),
        new("GIF image", "GIF8"u8.ToArray(), new[] { "gif" }),
        new("ZIP archive (or Office file)", new byte[] { 0x50, 0x4B, 0x03, 0x04 }, new[] { "zip", "docx", "xlsx", "pptx", "jar", "apk" }),
        new("SQLite database", "SQLite format 3"u8.ToArray(), new[] { "db", "sqlite", "sqlite3" }),
    };

    public string Name => "Signature";

    public void Analyze(EvidenceItem item, string fullPath)
    {
        var header = ReadHeader(fullPath, 16);
        var match = Signatures.FirstOrDefault(s => header.AsSpan().StartsWith(s.Magic));
        if (match is null)
        {
            item.DetectedType = LooksLikeText(header) ? "Text" : "Unknown";
            return;
        }

        item.DetectedType = match.Type;
        if (match.Extensions.Contains(item.Extension))
        {
            return;
        }

        var severity = match.Executable ? Severity.High : Severity.Medium;
        var shown = item.Extension.Length == 0 ? "(none)" : "." + item.Extension;
        item.Findings.Add(new Finding(Name, severity,
            $"Extension {shown} does not match real type: {match.Type}"));
    }

    private static byte[] ReadHeader(string path, int count)
    {
        using var stream = File.OpenRead(path);
        var buffer = new byte[count];
        var read = stream.Read(buffer, 0, count);
        return buffer[..read];
    }

    private static bool LooksLikeText(byte[] header) =>
        header.Length > 0 && header.All(b => b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127) || b >= 128);
}

/// <summary>Flags files whose SHA-256 is on a known-bad list (e.g. known malware or contraband).</summary>
public sealed class KnownHashAnalyzer : IFileAnalyzer
{
    private readonly IReadOnlyDictionary<string, string> _knownBad;

    public KnownHashAnalyzer(IReadOnlyDictionary<string, string> knownBad) => _knownBad = knownBad;

    public string Name => "KnownHash";

    public void Analyze(EvidenceItem item, string fullPath)
    {
        if (item.Sha256 is not null && _knownBad.TryGetValue(item.Sha256, out var label))
        {
            item.Findings.Add(new Finding(Name, Severity.High, $"Matches known-bad hash list: {label}"));
        }
    }

    /// <summary>Reads lines of "sha256,label". Lines starting with # are comments.</summary>
    public static Dictionary<string, string> LoadHashList(string path)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in File.ReadLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var parts = line.Split(',', 2);
            map[parts[0].Trim()] = parts.Length > 1 ? parts[1].Trim() : "known bad";
        }

        return map;
    }
}

/// <summary>Searches text files for case keywords (case-insensitive) and records where they appear.</summary>
public sealed class KeywordAnalyzer : IFileAnalyzer
{
    private const long MaxBytes = 5 * 1024 * 1024;
    private readonly string[] _keywords;

    public KeywordAnalyzer(IEnumerable<string> keywords) =>
        _keywords = keywords.Where(k => !string.IsNullOrWhiteSpace(k)).Select(k => k.Trim()).ToArray();

    public string Name => "Keyword";

    public void Analyze(EvidenceItem item, string fullPath)
    {
        if (_keywords.Length == 0 || item.DetectedType != "Text" || item.SizeBytes > MaxBytes)
        {
            return;
        }

        var lines = File.ReadAllLines(fullPath, Encoding.UTF8);
        foreach (var keyword in _keywords)
        {
            var hits = lines.Select((text, index) => (text, line: index + 1))
                            .Where(x => x.text.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            .Select(x => x.line)
                            .ToList();
            if (hits.Count > 0)
            {
                item.Findings.Add(new Finding(Name, Severity.Medium,
                    $"Keyword \"{keyword}\" found on line(s) {string.Join(", ", hits.Take(5))}"));
            }
        }
    }
}
