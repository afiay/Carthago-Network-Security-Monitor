// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Dns;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.EnvironmentTuning;
using Xunit;

namespace Carthago.Tests;

[Collection("R102 distinct TXT correlation")]
public sealed class Ga09DnsCaptureBoundaryTests
{
    [Fact]
    public async Task Capture_Parsed_A_Question_Does_Not_Establish_Baseline_Readiness()
    {
        var handler = new PacketHandler();
        var rule = new R102_DNSTunnelingViaLongLabelsRule();
        var root = "ga09-" + Guid.NewGuid().ToString("N")[..8] + ".example";
        const string label = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz";
        var now = new DateTime(2026, 11, 13, 0, 0, 0, DateTimeKind.Utc);
        var benign = DnsCaptureQualificationTests.Parse(handler,
            DnsCaptureQualificationTests.Message(100, false, name: "status." + root), false);
        Assert.True(benign.DnsValidatedAQuestion);
        Assert.False((await rule.EvaluateAsync(new RuleEvaluationContext(
            benign, Sensitivity.Balanced, now))).Matched);

        var query = DnsCaptureQualificationTests.Parse(handler,
            DnsCaptureQualificationTests.Message(101, false, name: label + "." + root), false);
        Assert.True(query.DnsValidatedAQuestion);
        Assert.Equal("A", query.DnsQtype);
        Assert.Equal(label + "." + root, query.DnsQname);
        var result = await rule.EvaluateAsync(new RuleEvaluationContext(
            query, Sensitivity.Balanced, now.AddSeconds(1)));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal(80, rule.PrecisionProfile.MinimumConfidence);
        var assets = new ApprovedAssetRegistry(new EnvironmentTuningOptions());
        var decision = RuleTuningCatalog.Resolve("SmallBusiness", rule.Descriptor,
            evt, query, assets, baselineReady: false);
        Assert.Equal(RuleMode.Shadow, decision.EffectiveMode);
    }
}
