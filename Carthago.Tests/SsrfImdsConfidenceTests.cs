// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class SsrfImdsConfidenceTests
{
    [Fact]
    public async Task IMDSv2_Token_And_Metadata_Headers_Do_Not_Increase_Ssrf_Confidence()
    {
        // These headers are normal provider protocol requirements, not independent
        // evidence of an attacker-controlled inbound request or an SSRF exploit.
        var baseline = MetadataRequest(null);
        var withHeaders = MetadataRequest(
            "X-aws-ec2-metadata-token: [REDACTED]\r\nMetadata: true\r\nMetadata-Flavor: Google");

        var rule = new R163_SsrfMetadataServiceProbeRule();
        var baselineResult = await rule.EvaluateAsync(Context(baseline));
        var headersResult = await rule.EvaluateAsync(Context(withHeaders));

        Assert.True(baselineResult.Matched);
        Assert.True(headersResult.Matched);
        Assert.Equal(Assert.Single(baselineResult.Events).ConfidenceScore,
            Assert.Single(headersResult.Events).ConfidenceScore, 6);
        Assert.Equal(84, rule.PrecisionProfile.MinimumConfidence);
    }

    [Fact]
    public async Task Metadata_Credential_Access_Without_Independent_Causality_Stays_Shadow()
    {
        var record = MetadataRequest("X-aws-ec2-metadata-token: [REDACTED]");
        var rule = new R163_SsrfMetadataServiceProbeRule();
        var result = await rule.EvaluateAsync(Context(record));

        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        var decision = RulePrecisionRuntimeEvaluator.Evaluate(
            rule.Descriptor, evt, record, RuleMode.Alert, "Research");

        Assert.Equal(RuleMode.Shadow, decision.EffectiveMode);
        Assert.False(decision.ConfidenceSatisfied);
    }

    private static TrafficRecord MetadataRequest(string? headers) => new()
    {
        Source = "10.0.0.20",
        Destination = "169.254.169.254",
        Protocol = "HTTP",
        DestinationPort = 80,
        ProcessName = "webapp.exe",
        HttpMethod = "GET",
        HttpHost = "169.254.169.254",
        HttpUri = "/latest/meta-data/iam/security-credentials",
        HttpRequestHeaders = headers
    };

    private static RuleEvaluationContext Context(TrafficRecord record)
        => new(record, Sensitivity.Balanced, DateTime.UtcNow);
}
