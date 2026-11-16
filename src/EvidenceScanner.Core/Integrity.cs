using System.Text.Json;

namespace EvidenceScanner.Core;

/// <summary>
/// Chain of custody: the manifest records every file's SHA-256 at scan time. Verifying later
/// proves the evidence was not changed, added to or deleted since then.
/// </summary>
public sealed record ManifestEntry(string Path, long SizeBytes, string Sha256);

public sealed record Manifest(string Examiner, DateTime CreatedUtc, string EvidenceRoot, List<ManifestEntry> Files);

public sealed record VerifyResult(List<string> Unchanged, List<string> Modified, List<string> Missing, List<string> Added)
{
    public bool IsIntact => Modified.Count == 0 && Missing.Count == 0 && Added.Count == 0;
}

public static class Integrity
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static Manifest CreateManifest(ScanResult result) =>
        new(result.Examiner, result.ScannedAtUtc, result.EvidenceRoot,
            result.Items.Select(i => new ManifestEntry(i.RelativePath, i.SizeBytes, i.Sha256!)).ToList());

    public static void Save(Manifest manifest, string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(manifest, Json));

    public static Manifest Load(string path) =>
        JsonSerializer.Deserialize<Manifest>(File.ReadAllText(path))
        ?? throw new InvalidDataException("Manifest file is empty or invalid.");

    public static VerifyResult Verify(Manifest manifest, string evidenceRoot)
    {
        var root = Path.GetFullPath(evidenceRoot);
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = 0 };
        var current = Directory.EnumerateFiles(root, "*", options)
                               .ToDictionary(p => Path.GetRelativePath(root, p).Replace('\\', '/'), p => p);

        var result = new VerifyResult(new(), new(), new(), new());
        foreach (var entry in manifest.Files)
        {
            if (!current.TryGetValue(entry.Path, out var full))
            {
                result.Missing.Add(entry.Path);
            }
            else if (!string.Equals(HashAnalyzer.Sha256OfFile(full), entry.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                result.Modified.Add(entry.Path);
            }
            else
            {
                result.Unchanged.Add(entry.Path);
            }
        }

        var known = manifest.Files.Select(f => f.Path).ToHashSet();
        result.Added.AddRange(current.Keys.Where(k => !known.Contains(k)).OrderBy(k => k, StringComparer.Ordinal));
        return result;
    }
}
