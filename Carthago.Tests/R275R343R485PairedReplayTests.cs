// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Paired controls preserve fail-closed unsupported producer gaps for R275/R343
/// while R485 now uses parser-backed BACnet capture evidence as a supported
/// malicious positive. No thresholds or policy modes are adjusted.
/// </summary>
public sealed class R275R343R485PairedReplayTests
{
    [Fact]
    public async Task Paired_Replays_Separate_Unsupported_Producers_From_ParserBacked_Bacnet()
    {
        var replayDirectory = Path.Combine(AppContext.BaseDirectory,
            "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions
        {
            ReplayDirectory = replayDirectory
        });

        foreach (var scenario in new[]
        {
            (Rule: "R275", Sample: "oauth-device-code-phishing",
                Benign: "r275-routine-device-code-initiation",
                Reason: "TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE"),
            (Rule: "R343", Sample: "ad-psremoting-encoded-command",
                Benign: "r343-powershell-remoting-without-encoded-payload",
                Reason: "WINRM_COMMAND_AUDIT_UNAVAILABLE")
        })
        {
            var unsupported = Assert.Single(report.SampleResults,
                sample => sample.Name == scenario.Sample);
            var negative = Assert.Single(report.SampleResults,
                sample => sample.Name == scenario.Benign);

            Assert.Equal(ReplaySampleClassification.UnsupportedMalicious, unsupported.Classification);
            Assert.Contains(scenario.Rule, unsupported.UnsupportedRuleIds);
            Assert.Equal(scenario.Reason, unsupported.UnsupportedReasonCodesByRuleId[scenario.Rule]);
            Assert.DoesNotContain(scenario.Rule, unsupported.ActualMatches);
            Assert.Empty(unsupported.Errors);

            Assert.Equal(ReplaySampleClassification.Benign, negative.Classification);
            Assert.Contains(scenario.Rule, negative.ExpectedNonMatches);
            Assert.DoesNotContain(scenario.Rule, negative.ActualMatches);
            Assert.Empty(negative.Errors);
        }

        var bacnet = Assert.Single(report.SampleResults,
            sample => sample.Name == "bacnet-write-property");
        var bacnetNegative = Assert.Single(report.SampleResults,
            sample => sample.Name == "r485-bacnet-readproperty-no-write");
        Assert.Equal(ReplaySampleClassification.Malicious, bacnet.Classification);
        Assert.Contains("R485", bacnet.ExpectedMatches);
        Assert.Contains("R485", bacnet.ActualMatches);
        Assert.Empty(bacnet.MissingExpectedMatches);
        Assert.Empty(bacnet.Errors);
        Assert.Contains("R485", bacnetNegative.ExpectedNonMatches);
        Assert.DoesNotContain("R485", bacnetNegative.ActualMatches);

        var coverage = Assert.Single(report.RuleEvidenceCoverage,
            item => item.RuleId == "R485");
        Assert.True(coverage.HasPairedControls);
        Assert.True(coverage.PositiveRecognized >= 1);
        Assert.True(coverage.ExplicitNegativePassed >= 1);
        Assert.Equal(0, coverage.ExplicitNegativeFailed);

        Assert.All(report.DetectionFunnelByProfile.Values, funnel =>
            Assert.Equal(0, funnel.BenignSimulatedAlerts));
    }
}
