// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Engine.Rules.IotOt;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Offline paired fixtures exercise the distinction between an observed
/// credential request and independently corroborated attacker-controlled SSRF.
/// No fixture is sufficient to authorize automatic promotion to Alert.
/// </summary>
public sealed class R118R163PairedReplayQualityTests
{
    [Fact]
    public async Task New_Labeled_Replays_Preserve_R118_R163_Confidence_Gates_And_Alert_Precision()
    {
        var replayDirectory = Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(
            new TuningBenchmarkOptions { ReplayDirectory = replayDirectory });

        var r118Benign = report.SampleResults.Single(sample =>
            sample.Name == "r118-bearer-token-looks-like-default-basic");
        var r118Malicious = report.SampleResults.Single(sample =>
            sample.Name == "r118-ubiquiti-default-basic-observed");
        var r163Benign = report.SampleResults.Single(sample =>
            sample.Name == "r163-paired-unrelated-gcp-agent");
        var r163Malicious = report.SampleResults.Single(sample =>
            sample.Name == "r163-paired-gcp-unattributed-fetch-candidate");

        Assert.Equal(ReplaySampleClassification.Benign, r118Benign.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, r163Benign.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, r118Malicious.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, r163Malicious.Classification);

        Assert.DoesNotContain("R118", r118Benign.ActualMatches);
        // This authorized Bearer request is TLS-protected, so it is neither
        // a Basic default-credential attempt nor a cleartext Bearer exposure.
        Assert.DoesNotContain("R135", r118Benign.ActualMatches);
        Assert.DoesNotContain("R163", r163Benign.ActualMatches);
        Assert.Contains("R118", r118Malicious.ActualMatches);
        Assert.Contains("R163", r163Malicious.ActualMatches);
        Assert.Empty(r118Benign.Errors);
        Assert.Empty(r118Malicious.Errors);
        Assert.Empty(r163Benign.Errors);
        Assert.Empty(r163Malicious.Errors);

        Assert.Equal(86, new R118_DefaultCredentialIoTAttemptRule().PrecisionProfile.MinimumConfidence);
        Assert.Equal(84, new R163_SsrfMetadataServiceProbeRule().PrecisionProfile.MinimumConfidence);

        foreach (var profile in report.ProfileResults.Keys)
        {
            Assert.DoesNotContain("R118", r118Malicious.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R163", r163Malicious.Profiles[profile].AlertRuleIds);

            var r118 = Assert.Single(r118Malicious.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R118");
            var r163 = Assert.Single(r163Malicious.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R163");
            Assert.True(r118.Confidence < 0.86, $"{profile}: R118 unexpectedly reached its 86% floor.");
            Assert.True(r163.Confidence < 0.84, $"{profile}: R163 unexpectedly reached its 84% floor.");
        }

        // Second paired batch: an ambiguous duplicate Authorization header is
        // not proof of a device login; a single origin Basic header still is.
        // Likewise, normalized-away metadata paths are not credential reads,
        // while the provider-documented GCP IPv6 token path is a raw candidate.
        var duplicateAuth = report.SampleResults.Single(sample =>
            sample.Name == "r118-duplicate-authorization-ambiguous");
        var singleAuth = report.SampleResults.Single(sample =>
            sample.Name == "r118-unauthorized-router-root-basic");
        var normalizedPath = report.SampleResults.Single(sample =>
            sample.Name == "r163-encoded-dot-segment-metadata-decoy");
        var ipv6CredentialPath = report.SampleResults.Single(sample =>
            sample.Name == "r163-gcp-ipv6-credential-fetch-unattributed");

        Assert.Equal(ReplaySampleClassification.Benign, duplicateAuth.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, singleAuth.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, normalizedPath.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, ipv6CredentialPath.Classification);
        Assert.DoesNotContain("R118", duplicateAuth.ActualMatches);
        Assert.DoesNotContain("R135", duplicateAuth.ActualMatches);
        Assert.Contains("R118", singleAuth.ActualMatches);
        Assert.DoesNotContain("R163", normalizedPath.ActualMatches);
        Assert.Contains("R163", ipv6CredentialPath.ActualMatches);
        Assert.Empty(duplicateAuth.Errors);
        Assert.Empty(singleAuth.Errors);
        Assert.Empty(normalizedPath.Errors);
        Assert.Empty(ipv6CredentialPath.Errors);

        foreach (var profile in report.ProfileResults.Keys)
        {
            Assert.DoesNotContain("R118", singleAuth.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R163", ipv6CredentialPath.Profiles[profile].AlertRuleIds);

            var r118 = Assert.Single(singleAuth.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R118");
            var r163 = Assert.Single(ipv6CredentialPath.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R163");
            Assert.True(r118.Confidence < 0.86, $"{profile}: duplicate-auth batch unexpectedly promotes R118.");
            Assert.True(r163.Confidence < 0.84, $"{profile}: GCP IPv6 batch unexpectedly promotes R163.");
        }

        // Sample-level metrics count actual alerts, not raw detector matches.
        // A benign alert in any profile is a regression requiring investigation.
        Assert.All(report.Summary.SampleLevelQualityByProfile.Values,
            quality => Assert.Equal(0, quality.FalsePositives));
    }
}
