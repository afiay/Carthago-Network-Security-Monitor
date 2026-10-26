// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Engine.Rules.IotOt;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// HTTP Digest versus Basic and ECS metadata versus task-role credentials:
/// detector recognition is not proof of login success or SSRF causality.
/// </summary>
public sealed class R118R163EcsDigestReplayTests
{
    [Fact]
    public async Task Paired_Replays_Preserve_Redaction_And_All_Profile_Confidence_Gates()
    {
        var directory = Path.Combine(AppContext.BaseDirectory,
            "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(
            new TuningBenchmarkOptions { ReplayDirectory = directory });

        var digest = Assert.Single(report.SampleResults,
            sample => sample.Name == "r118-digest-camera-auth-not-basic");
        var basic = Assert.Single(report.SampleResults,
            sample => sample.Name == "r118-ubiquiti-basic-https-wire-probe");
        var ecsMetadata = Assert.Single(report.SampleResults,
            sample => sample.Name == "r163-ecs-task-metadata-not-credentials");
        var ecsCredentials = Assert.Single(report.SampleResults,
            sample => sample.Name == "r163-ecs-unapproved-task-credential-probe");

        Assert.True(report.SampleResults.Count >= 92);
        Assert.Equal(ReplaySampleClassification.Benign, digest.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, basic.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, ecsMetadata.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, ecsCredentials.Classification);
        Assert.DoesNotContain("R118", digest.ActualMatches);
        Assert.Contains("R118", basic.ActualMatches);
        Assert.DoesNotContain("R163", ecsMetadata.ActualMatches);
        Assert.Contains("R163", ecsCredentials.ActualMatches);
        Assert.All(new[] { digest, basic, ecsMetadata, ecsCredentials },
            sample => Assert.Empty(sample.Errors));

        // Raw wire data is synthetic and confined to fixture inputs. The
        // exported benchmark must contain neither the default Basic token nor
        // a captured Digest Authorization value.
        var exported = JsonSerializer.Serialize(report);
        Assert.DoesNotContain("dWJudDp1Ym50", exported, StringComparison.Ordinal);
        Assert.DoesNotContain("nonce=\\\"synthetic\\\"", exported, StringComparison.Ordinal);

        Assert.Equal(86, new R118_DefaultCredentialIoTAttemptRule().PrecisionProfile.MinimumConfidence);
        Assert.Equal(84, new R163_SsrfMetadataServiceProbeRule().PrecisionProfile.MinimumConfidence);
        foreach (var profile in report.ProfileResults.Keys)
        {
            Assert.Empty(digest.Profiles[profile].AlertRuleIds);
            Assert.Empty(ecsMetadata.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R118", basic.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R163", ecsCredentials.Profiles[profile].AlertRuleIds);
            Assert.True(Assert.Single(basic.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R118").Confidence < 0.86);
            Assert.True(Assert.Single(ecsCredentials.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R163").Confidence < 0.84);
        }
    }
}
