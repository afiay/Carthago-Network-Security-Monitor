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
/// Paired authority-port and Azure IMDS scenarios verify that raw candidate
/// recognition is distinct from trusted authentication or SSRF causality.
/// The benchmark uses synthetic inputs and must never export credentials.
/// </summary>
public sealed class R118R163AuthorityAndAzureReplayTests
{
    [Fact]
    public async Task Authority_And_Azure_Pairs_Respect_Privacy_And_Confidence_Floors()
    {
        var directory = Path.Combine(AppContext.BaseDirectory,
            "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(
            new TuningBenchmarkOptions { ReplayDirectory = directory });

        var wrongPort = Assert.Single(report.SampleResults,
            sample => sample.Name == "r118-router-authority-port-mismatch");
        var correctPort = Assert.Single(report.SampleResults,
            sample => sample.Name == "r118-router-authority-port-match");
        var azureInstance = Assert.Single(report.SampleResults,
            sample => sample.Name == "r163-azure-instance-metadata-agent");
        var azureToken = Assert.Single(report.SampleResults,
            sample => sample.Name == "r163-azure-vault-token-unapproved");

        Assert.True(report.SampleResults.Count >= 96);
        Assert.Equal(ReplaySampleClassification.Benign, wrongPort.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, correctPort.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, azureInstance.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, azureToken.Classification);

        Assert.DoesNotContain("R118", wrongPort.ActualMatches);
        Assert.Contains("R118", correctPort.ActualMatches);
        Assert.DoesNotContain("R163", azureInstance.ActualMatches);
        Assert.Contains("R163", azureToken.ActualMatches);
        Assert.All(new[] { wrongPort, correctPort, azureInstance, azureToken },
            sample => Assert.Empty(sample.Errors));

        // The synthetic HTTP Basic value is confined to fixture input and
        // must be redacted before benchmark observations are serialized.
        var exported = JsonSerializer.Serialize(report);
        Assert.DoesNotContain("YWRtaW46cGFzc3dvcmQ=", exported, StringComparison.Ordinal);

        Assert.Equal(86, new R118_DefaultCredentialIoTAttemptRule().PrecisionProfile.MinimumConfidence);
        Assert.Equal(84, new R163_SsrfMetadataServiceProbeRule().PrecisionProfile.MinimumConfidence);
        Assert.Equal(80, new R102_DNSTunnelingViaLongLabelsRule().PrecisionProfile.MinimumConfidence);

        foreach (var profile in report.ProfileResults.Keys)
        {
            Assert.Empty(wrongPort.Profiles[profile].AlertRuleIds);
            Assert.Empty(azureInstance.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R118", correctPort.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R163", azureToken.Profiles[profile].AlertRuleIds);
            Assert.True(Assert.Single(correctPort.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R118").Confidence < 0.86);
            Assert.True(Assert.Single(azureToken.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R163").Confidence < 0.84);
        }
    }
}
