using System.Security.Cryptography;
using System.Text;

namespace EvidenceScanner.Core;

/// <summary>
/// Creates a small SAMPLE evidence folder (all made-up files) with planted items to find:
/// a program disguised as a PDF, an archive disguised as a photo, a known-bad file,
/// a hidden file and a note containing case keywords.
/// </summary>
public static class DemoEvidence
{
    public static readonly string[] Keywords = { "bitcoin", "wire transfer" };

    /// <summary>Creates the folder and returns the known-bad hash list for it (sha256 -> label).</summary>
    public static Dictionary<string, string> Create(string root)
    {
        Directory.CreateDirectory(root);
        var docs = Directory.CreateDirectory(Path.Combine(root, "Documents")).FullName;
        var pics = Directory.CreateDirectory(Path.Combine(root, "Pictures")).FullName;
        var downloads = Directory.CreateDirectory(Path.Combine(root, "Downloads")).FullName;

        var start = new DateTime(2026, 10, 1, 9, 0, 0, DateTimeKind.Utc);
        void Put(string path, byte[] bytes, int hoursAfterStart)
        {
            File.WriteAllBytes(path, bytes);
            var t = start.AddHours(hoursAfterStart);
            File.SetCreationTimeUtc(path, t);
            File.SetLastWriteTimeUtc(path, t.AddMinutes(30));
        }

        // Normal files
        Put(Path.Combine(docs, "report.pdf"), Concat("%PDF-1.7\n"u8.ToArray(), Filler(400, 1)), 1);
        Put(Path.Combine(docs, "meeting_notes.txt"), "Team meeting: quarterly planning and budget review.\n"u8.ToArray(), 5);
        Put(Path.Combine(pics, "holiday.jpg"), Concat(new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 }, Filler(800, 2)), 10);
        Put(Path.Combine(pics, "logo.png"), Concat(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, Filler(300, 3)), 12);

        // Planted: a Windows program renamed to look like a PDF invoice
        Put(Path.Combine(downloads, "invoice_october.pdf"), Concat("MZ"u8.ToArray(), Filler(1200, 4)), 30);

        // Planted: a ZIP archive renamed to look like a photo
        Put(Path.Combine(pics, "beach.jpg"), Concat(new byte[] { 0x50, 0x4B, 0x03, 0x04 }, Filler(600, 5)), 31);

        // Planted: a file whose hash is on the known-bad list
        var badBytes = Concat("MZ"u8.ToArray(), Filler(900, 6));
        Put(Path.Combine(downloads, "setup_tool.exe"), badBytes, 32);

        // Planted: a hidden note with case keywords
        Put(Path.Combine(docs, ".plans.txt"),
            Encoding.UTF8.GetBytes("Move funds by wire transfer on Friday.\nConvert the rest to Bitcoin.\n"), 33);

        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [Convert.ToHexStringLower(SHA256.HashData(badBytes))] = "sample known-bad tool (demo)",
        };
    }

    private static byte[] Filler(int length, int seed)
    {
        var rng = new Random(seed);
        var bytes = new byte[length];
        rng.NextBytes(bytes);
        return bytes;
    }

    private static byte[] Concat(byte[] a, byte[] b) => a.Concat(b).ToArray();
}
