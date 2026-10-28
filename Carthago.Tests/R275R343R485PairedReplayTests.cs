// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Paired benign and malicious replay controls for three previously
/// positive-only rule families. Recognition is assessed separately from
/// replay alert eligibility; no thresholds or policy modes are adjusted.
/// </summary>
public sealed class R275R343R485PairedReplayTests
{
    [Fact]
    public async Task Paired_Replays_Reject_Routine_Device_And_Remoting_And_Bacnet_Read_Behavior()
    {
        var replayDirectory = Path.Combine(AppContext.BaseDirectory,
            "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions
        {
            ReplayDirectory = replayDirectory
        });

        var cases = new[]
        {
            (Rule: "R275", Malicious: "oauth-device-code-phishing",
                Benign: "r275-routine-device-code-initiation"),
            (Rule: "R343", Malicious: "ad-psremoting-encoded-command",
                Benign: "r343-powershell-remoting-without-encoded-payload"),
            (Rule: "R485", Malicious: "bacnet-write-property",
                Benign: "r485-bacnet-readproperty-no-write")
        };

        foreach (var scenario in cases)
        {
            var positive = Assert.Single(report.SampleResults,
                sample => sample.Name == scenario.Malicious);
            var negative = Assert.Single(report.SampleResults,
                sample => sample.Name == scenario.Benign);

            Assert.Equal(ReplaySampleClassification.Malicious, positive.Classification);
            Assert.Equal(ReplaySampleClassification.Benign, negative.Classification);
            Assert.Contains(scenario.Rule, positive.ExpectedMatches);
            Assert.Contains(scenario.Rule, negative.ExpectedNonMatches);
            Assert.DoesNotContain(scenario.Rule, negative.ActualMatches);
            Assert.Empty(negative.Errors);

            foreach (var profile in report.ProfileResults.Keys)
                Assert.Empty(negative.Profiles[profile].AlertRuleIds);

            var coverage = Assert.Single(report.RuleEvidenceCoverage,
                item => item.RuleId == scenario.Rule);
            Assert.True(coverage.HasPairedControls,
                scenario.Rule + " must retain both positive and explicit negative labels.");
            Assert.True(coverage.ExplicitNegativePassed >= 1);
            Assert.Equal(0, coverage.ExplicitNegativeFailed);

            if (scenario.Rule is "R275" or "R343")
            {
                // These maliciously labeled scenarios lack a trusted identity
                // provider / WinRM audit producer. Keep the missing positive
                // visible instead of manufacturing a result from packet Info.
                Assert.DoesNotContain(scenario.Rule, positive.ActualMatches);
                Assert.Contains(scenario.Rule, positive.MissingExpectedMatches);
                Assert.Contains(positive.ExpectedRuleDiagnostics,
                    item => item.RuleId == scenario.Rule && (item.Outcome is "NoMatch" or "MissingTelemetry"));
                Assert.True(coverage.PositiveMissed >= 1);
            }
            else
            {
                Assert.Contains(scenario.Rule, positive.ActualMatches);
                Assert.Empty(positive.Errors);
                Assert.True(coverage.PositiveRecognized >= 1);
            }
        }

        Assert.All(report.DetectionFunnelByProfile.Values, funnel =>
            Assert.Equal(0, funnel.BenignSimulatedAlerts));
    }
}
