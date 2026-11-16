# Evidence Scanner (C# / .NET)

A small, read-only digital forensics triage tool. Point it at a folder of evidence files and it:

- **fingerprints every file** with SHA-256 and MD5 hashes
- **detects the real file type** from the file's first bytes ("magic numbers") and flags files whose
  extension is a disguise, e.g. a program renamed to `invoice_october.pdf`
- **flags known-bad files** by comparing hashes against a hash list
- **searches text files for case keywords** and reports the line numbers
- **flags hidden files**
- **builds a timeline** of when files were created and modified
- **proves the evidence was not changed** later: it saves a hash manifest, and `verify` reports any
  modified, missing or added file (chain of custody)
- writes **CSV** (for Excel), **JSON** (for other tools) and a **Markdown case report**

> **Data note:** the `demo` command creates a folder of made-up sample files. Nothing is real.

## Run it (Windows Command Prompt)

Needs the .NET 10 SDK (`dotnet --version` should show 10.x).

```
dotnet test
dotnet run --project src/EvidenceScanner.Cli -- demo
```

Expected result of the demo: **8 files scanned, 4 flagged**:

| Severity | File | Why |
|---|---|---|
| High | Downloads/invoice_october.pdf | really a Windows program disguised as a PDF |
| High | Downloads/setup_tool.exe | its hash is on the known-bad list |
| Medium | Documents/.plans.txt | hidden file containing the keywords "wire transfer" and "bitcoin" |
| Medium | Pictures/beach.jpg | really a ZIP archive disguised as a photo |

Check that the evidence has not changed since the scan:

```
dotnet run --project src/EvidenceScanner.Cli -- verify output/sample_evidence output/manifest.json
```

Scan any folder of your own (the files are only read, never changed):

```
dotnet run --project src/EvidenceScanner.Cli -- scan C:\path\to\folder --keywords password,invoice --hashes known_bad.txt
```

## Design (object-oriented)

| Piece | Role |
|---|---|
| `IFileAnalyzer` | One check per class: `HashAnalyzer`, `SignatureAnalyzer`, `KnownHashAnalyzer`, `KeywordAnalyzer`. New checks are added as new classes without changing the scanner (strategy pattern, open/closed principle). |
| `Scanner` | Walks the folder read-only, runs every analyzer, keeps going if one file cannot be read, and builds the timeline. |
| `Integrity` | Creates, saves and verifies the hash manifest. |
| `IReportWriter` | `CsvReportWriter`, `JsonReportWriter`, `MarkdownReportWriter`. |
| `EvidenceItem`, `Finding`, `ScanResult` | Data model; each finding carries a severity and a plain-language reason. |

## Terms in plain language

- **Hash**: a fingerprint of a file. Change one byte and the hash changes completely.
- **Magic number / file signature**: the first bytes of a file that show its real type (PDFs start with `%PDF`, Windows programs with `MZ`).
- **Known-bad hash list**: hashes of files already known to be malicious or illegal.
- **Chain of custody**: proof that evidence was not altered after it was collected.

## Project layout

```
src/EvidenceScanner.Core/    library: models, analyzers, scanner, integrity, reports, demo evidence
src/EvidenceScanner.Cli/     command-line app: demo, scan, verify
tests/EvidenceScanner.Tests/ 28 xUnit tests
```
