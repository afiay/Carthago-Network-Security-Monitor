// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Manifest-level isolation contract for candidate v2. These assertions
/// cannot confer accuracy or external-label legitimacy on synthetic data.
/// No holdout evaluation is executed by these tests.
/// </summary>
public sealed class SyntheticHoldoutV2ContractTests
{
    private static string Root => Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", ".."));

    private static JsonDocument Read(string relative)
        => JsonDocument.Parse(File.ReadAllText(Path.Combine(Root,
            relative.Replace('/', Path.DirectorySeparatorChar))));

    [Fact]
    public void V2_is_separate_from_the_existing_frozen_v1_manifest()
    {
        using var v1 = Read("docs/holdout-evaluation-manifest.json");
        using var v2 = Read("docs/holdout-evaluation-v2-manifest.json");
        Assert.Equal(1, v1.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(2, v2.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("docs/holdout-evaluation-manifest.json",
            v2.RootElement.GetProperty("predecessorManifest").GetString());
        Assert.Equal(12, v1.RootElement.GetProperty("samples").GetArrayLength());
        Assert.Equal(12, v2.RootElement.GetProperty("samples").GetArrayLength());
    }

    [Fact]
    public void V2_reuses_exactly_eight_non_R102_v1_frozen_blob_hashes()
    {
        using var v1 = Read("docs/holdout-evaluation-manifest.json");
        using var v2 = Read("docs/holdout-evaluation-v2-manifest.json");
        var originals = v1.RootElement.GetProperty("samples").EnumerateArray()
            .ToDictionary(e => e.GetProperty("file").GetString()!,
                e => e.GetProperty("gitBlobSha").GetString()!,
                StringComparer.Ordinal);
        var reused = v2.RootElement.GetProperty("samples").EnumerateArray()
            .Where(e => e.GetProperty("sourceKind").GetString() == "pinned-v1-synthetic")
            .ToArray();
        Assert.Equal(8, reused.Length);
        foreach (var item in reused)
        {
            var path = item.GetProperty("file").GetString()!;
            Assert.StartsWith("Tests/RuleReplayHoldout/", path, StringComparison.Ordinal);
            Assert.NotEqual("R102", item.GetProperty("primaryRule").GetString());
            Assert.True(originals.TryGetValue(path, out var originalHash));
            Assert.Equal(originalHash, item.GetProperty("gitBlobSha").GetString());
        }
    }

    [Fact]
    public void Four_new_R102_slots_have_strictly_separate_fixture_and_provenance_paths()
    {
        using var v2 = Read("docs/holdout-evaluation-v2-manifest.json");
        var entries = v2.RootElement.GetProperty("samples").EnumerateArray()
            .Where(e => e.GetProperty("sourceKind").GetString() == "external-pcap-reviewed")
            .ToArray();
        Assert.Equal(4, entries.Length);
        Assert.Equal(4, entries.Select(e => e.GetProperty("file").GetString())
            .Distinct(StringComparer.Ordinal).Count());
        foreach (var item in entries)
        {
            Assert.Equal("R102", item.GetProperty("primaryRule").GetString());
            Assert.StartsWith("Tests/RuleReplayHoldoutV2/",
                item.GetProperty("file").GetString()!, StringComparison.Ordinal);
            Assert.StartsWith("docs/holdout-v2-provenance/",
                item.GetProperty("provenanceFile").GetString()!, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Every_rule_retains_two_benign_and_two_malicious_scenarios()
    {
        using var v2 = Read("docs/holdout-evaluation-v2-manifest.json");
        var cases = v2.RootElement.GetProperty("samples").EnumerateArray().ToArray();
        foreach (var rule in new[] { "R102", "R118", "R163" })
        {
            Assert.Equal(2, cases.Count(item =>
                item.GetProperty("primaryRule").GetString() == rule
                && item.GetProperty("classification").GetString() == "Benign"));
            Assert.Equal(2, cases.Count(item =>
                item.GetProperty("primaryRule").GetString() == rule
                && item.GetProperty("classification").GetString() == "Malicious"));
        }
    }

    [Fact]
    public void A_pending_v2_must_not_contain_pretend_frozen_hashes()
    {
        using var v2 = Read("docs/holdout-evaluation-v2-manifest.json");
        var state = v2.RootElement.GetProperty("approvalState").GetString();
        Assert.Contains(state, new[] {
            "PENDING_EXTERNAL_CAPTURE_AND_REVIEW", "FROZEN_V2_SYNTHETIC"
        });
        var external = v2.RootElement.GetProperty("samples").EnumerateArray()
            .Where(e => e.GetProperty("sourceKind").GetString() == "external-pcap-reviewed");
        foreach (var item in external)
        {
            foreach (var key in new[] { "gitBlobSha", "provenanceBlobSha" })
            {
                var hash = item.GetProperty(key).ValueKind == JsonValueKind.Null
                    ? null : item.GetProperty(key).GetString();
                if (state == "PENDING_EXTERNAL_CAPTURE_AND_REVIEW")
                    Assert.Null(hash);
                else
                    Assert.Matches("^[a-f0-9]{40}$", hash!);
            }
            if (state == "FROZEN_V2_SYNTHETIC")
            {
                foreach (var key in new[] { "file", "provenanceFile" })
                {
                    var file = Path.Combine(Root, item.GetProperty(key).GetString()!
                        .Replace('/', Path.DirectorySeparatorChar));
                    Assert.True(File.Exists(file), "Missing frozen v2 evidence: " + file);
                }
            }
        }
    }

    [Fact]
    public void Source_inspection_reports_exclusive_rejection_reasons_and_private_length_histograms()
    {
        // Prevent future source triage from collapsing missing transport,
        // bad DNS names and frame duplication into an opaque skip count.
        // This is a structural assertion; the true capture must still
        // be decoded on CARTHAGE, and no detector thresholds are changed.
        var inspector = File.ReadAllText(Path.Combine(Root, "scripts",
            "inspect-holdout-v2-pcap.ps1"));
        Assert.Contains("skippedFrameReasonCounts=$skipReasons", inspector);
        Assert.Contains("excludedByOptionalRootFilter=$excludedByOptionalRootFilter", inspector);
        Assert.Contains("distinctTxtNamesByLongestLabelLength=$distinctLengthHistogram", inspector);
        Assert.Contains("txtLongestLabelLengthHistogram=$lengthHistogram", inspector);
        Assert.Contains("repeatedFrameNumber", inspector);
        Assert.Contains("missingOrConflictingTransport", inspector);
        Assert.Contains("invalidQuestionName", inspector);
        Assert.Contains("invalidLabelLength", inspector);
        Assert.Contains("if ($reasonCount -ne $skipped)", inspector);
        Assert.Contains("'46-49'", inspector);
        Assert.Contains("'50-53'", inspector);
        Assert.Contains("'54-57'", inspector);
        Assert.Contains("Raw QNAMEs are not exported", inspector);
        Assert.DoesNotContain("ShowSourceAddresses=$true", inspector);
        Assert.DoesNotContain("ShowDnsRoots=$true", inspector);
    }

    [Fact]
    public void V2_packet_audit_rejects_unattributed_or_injected_fixture_fields()
    {
        // Structural safety assertion only; original PCAPs are separately
        // required for an actual TShark-backed source audit.
        var audit = File.ReadAllText(Path.Combine(Root, "scripts",
            "audit-holdout-v2-candidates.ps1"));
        Assert.Contains("Get-FileHash -LiteralPath $pcap -Algorithm SHA256", audit);
        Assert.Contains("'frame.number'", audit);
        Assert.Contains("'udp.srcport'", audit);
        Assert.Contains("'tcp.srcport'", audit);
        Assert.Contains("Compare-Object -ReferenceObject ($allowedRecordFields", audit);
        Assert.Contains("Compare-Object -ReferenceObject ($allowedSampleFields", audit);
        Assert.Contains("ambiguous transport", audit, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("same original PCAP packet frame reused", audit);
        Assert.Contains("$record.isUdp -ne $udp", audit);
        Assert.Contains("$record.isTcp -ne $tcp", audit);
        Assert.Contains("$maliciousSources.Add", audit);
    }

    [Fact]
    public void V2_readiness_reports_pending_sources_without_automatically_freezing()
    {
        var readiness = File.ReadAllText(Path.Combine(Root, "scripts",
            "inspect-holdout-v2-readiness.ps1"));
        Assert.Contains("PENDING CAPTURE/PROVENANCE", readiness);
        Assert.Contains("PACKET FIELDS AUDITED - MANUAL LABEL/RIGHTS/PRIVACY REVIEW", readiness);
        Assert.Contains("audit-holdout-v2-candidates.ps1", readiness);
        Assert.DoesNotContain("freeze-holdout-v2.ps1", readiness);

        var evaluator = File.ReadAllText(Path.Combine(Root, "scripts",
            "evaluate-holdout-v2.ps1"));
        Assert.Contains("PENDING_EXTERNAL_CAPTURE_AND_REVIEW", readiness);
        Assert.Contains("FROZEN_V2_SYNTHETIC", evaluator);
        Assert.Contains("inspect-replay-input-telemetry.ps1", evaluator);
    }

    [Fact]
    public void Full_verification_defaults_to_v1_and_requires_explicit_v2_opt_in()
    {
        var script = File.ReadAllText(Path.Combine(Root,
            "scripts", "verify-all-rule-batches.ps1"));
        Assert.Contains("[string]$HoldoutVersion='v1'", script, StringComparison.Ordinal);
        Assert.Contains("if ($HoldoutVersion -eq 'v2')", script, StringComparison.Ordinal);
        Assert.Contains("scripts/evaluate-holdout-v2.ps1", script, StringComparison.Ordinal);
        Assert.Contains("scripts/evaluate-holdout.ps1", script, StringComparison.Ordinal);
    }
}
