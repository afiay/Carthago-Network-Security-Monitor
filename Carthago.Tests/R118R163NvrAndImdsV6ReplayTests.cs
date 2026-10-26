// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Dns;
using Carthago.Engine.Rules.Expansion;
using Carthago.Engine.Rules.IotOt;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Paired NVR Basic and EC2 IMDSv6 replays distinguish capture-derived
/// authentication evidence and approved metadata agents from unauthorized
/// candidates. No replay proves authentication success or SSRF causality.
/// </summary>
public sealed class R118R163NvrAndImdsV6ReplayTests
{
    [Fact]
    public async Task Paired_Replays_Respect_Redaction_And_Confidence_Gates()
    {
        var directory = Path.Combine(AppContext.BaseDirectory,
            "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(
            new TuningBenchmarkOptions { ReplayDirectory = directory });

        var nvrNormal = Assert.Single(report.SampleResults,
            sample => sample.Name == "r118-nvr-nondefault-redacted-basic");
        var nvrDefault = Assert.Single(report.SampleResults,
            sample => sample.Name == "r118-nvr-default-redacted-basic");
        var agent = Assert.Single(report.SampleResults,
            sample => sample.Name == "r163-imdsv6-approved-ssm-credential-read");
        var unapproved = Assert.Single(report.SampleResults,
            sample => sample.Name == "r163-imdsv6-unapproved-credential-read");

        Assert.True(report.SampleResults.Count >= 100);
        Assert.Equal(ReplaySampleClassification.Benign, nvrNormal.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, nvrDefault.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, agent.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, unapproved.Classification);

        Assert.DoesNotContain("R118", nvrNormal.ActualMatches);
        Assert.Contains("R118", nvrDefault.ActualMatches);
        Assert.DoesNotContain("R163", agent.ActualMatches);
        Assert.Contains("R163", unapproved.ActualMatches);
        Assert.All(new[] { nvrNormal, nvrDefault, agent, unapproved },
            sample => Assert.Empty(sample.Errors));

        // The fixture's synthetic wire credentials must never be copied
        // into a serialized benchmark report.
        var exported = JsonSerializer.Serialize(report);
        Assert.DoesNotContain("Z3Vlc3Q6", exported, StringComparison.Ordinal);
        Assert.DoesNotContain("Authorization: Basic", exported, StringComparison.OrdinalIgnoreCase);

        Assert.Equal(86, new R118_DefaultCredentialIoTAttemptRule().PrecisionProfile.MinimumConfidence);
        Assert.Equal(84, new R163_SsrfMetadataServiceProbeRule().PrecisionProfile.MinimumConfidence);
        Assert.Equal(80, new R102_DNSTunnelingViaLongLabelsRule().PrecisionProfile.MinimumConfidence);

        foreach (var profile in report.ProfileResults.Keys)
        {
            Assert.Empty(nvrNormal.Profiles[profile].AlertRuleIds);
            Assert.Empty(agent.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R118", nvrDefault.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R163", unapproved.Profiles[profile].AlertRuleIds);
            Assert.True(Assert.Single(nvrDefault.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R118").Confidence < 0.86);
            Assert.True(Assert.Single(unapproved.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R163").Confidence < 0.84);
        }
    }
}
