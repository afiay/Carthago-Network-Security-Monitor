// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Validates the frozen synthetic evaluation set's provenance, labels and
/// separation from the development replay folder. This does not tune rules
/// against the holdout or equate synthetic samples with field validation.
/// </summary>
public sealed class SyntheticHoldoutContractTests
{
    [Fact]
    public void Holdout_Contains_Pinned_Balanced_Paired_Labels_For_Three_Rules()
    {
        var root = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", ".."));
        var manifestFile = Path.Combine(root, "docs", "holdout-evaluation-manifest.json");
        Assert.True(File.Exists(manifestFile));
        using var manifestDoc = JsonDocument.Parse(File.ReadAllText(manifestFile));
        var entries = manifestDoc.RootElement.GetProperty("samples").EnumerateArray().ToArray();
        Assert.Equal(12, entries.Length);
        Assert.Equal(1, manifestDoc.RootElement.GetProperty("schemaVersion").GetInt32());

        var filenames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var counts = new Dictionary<string, (int Benign, int Malicious)>(
            StringComparer.OrdinalIgnoreCase);
        var trainingRoot = Path.Combine(root, "Tests", "RuleReplaySamples");
        var holdoutRoot = Path.Combine(root, "Tests", "RuleReplayHoldout");
        var rawObserved = new HashSet<string>(StringComparer.Ordinal);

        foreach (var entry in entries)
        {
            var path = entry.GetProperty("file").GetString()!;
            Assert.StartsWith("Tests/RuleReplayHoldout/", path, StringComparison.Ordinal);
            Assert.True(filenames.Add(path));
            Assert.Matches("^[a-f0-9]{40}$", entry.GetProperty("gitBlobSha").GetString()!);
            Assert.False(path.Contains("..", StringComparison.Ordinal));
            var fullPath = Path.GetFullPath(Path.Combine(root, path.Replace('/', Path.DirectorySeparatorChar)));
            Assert.True(fullPath.StartsWith(holdoutRoot + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase));
            Assert.True(File.Exists(fullPath));

            var group = entry.GetProperty("classification").GetString()!;
            var rule = entry.GetProperty("primaryRule").GetString()!;
            Assert.Contains(rule, new[] { "R102", "R118", "R163" });
            Assert.Contains(group, new[] { "Benign", "Malicious" });
            Assert.Contains("/" + group.ToLowerInvariant() + "/", path, StringComparison.Ordinal);
            Assert.False(File.Exists(Path.Combine(trainingRoot,
                group.ToLowerInvariant(), Path.GetFileName(fullPath))));

            using var fixture = JsonDocument.Parse(File.ReadAllText(fullPath));
            var json = fixture.RootElement;
            Assert.Equal(group, json.GetProperty("classification").GetString());
            Assert.Equal(Path.GetFileNameWithoutExtension(fullPath),
                json.GetProperty("name").GetString());
            Assert.True(json.GetProperty("records").GetArrayLength() > 0);
            var expected = group == "Malicious" ? "expectedMatches" : "expectedNonMatches";
            var ids = json.GetProperty(expected).EnumerateArray()
                .Select(item => item.GetString()).ToArray();
            Assert.Contains(rule, ids);

            // A byte-identical raw records block should not be treated as an
            // additional independent scenario with a new file name.
            Assert.True(rawObserved.Add(json.GetProperty("records").GetRawText()),
                "Duplicate holdout record sequence: " + path);

            counts.TryGetValue(rule, out var totals);
            counts[rule] = group == "Benign"
                ? (totals.Benign + 1, totals.Malicious)
                : (totals.Benign, totals.Malicious + 1);
        }

        Assert.Equal(12, filenames.Count);
        Assert.Equal(12, Directory.GetFiles(holdoutRoot, "*.json",
            SearchOption.AllDirectories).Length);
        foreach (var rule in new[] { "R102", "R118", "R163" })
        {
            Assert.True(counts.TryGetValue(rule, out var count));
            Assert.Equal(2, count.Benign);
            Assert.Equal(2, count.Malicious);
        }
    }
}
