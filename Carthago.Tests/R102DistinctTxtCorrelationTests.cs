// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Dns;
using Carthago.Engine.Rules.Tuning;
using Carthago.Services.EnvironmentTuning;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

// Replay benchmarks reset the DNS rule's shared windows. Keep the correlation
// test collection separate from parallel benchmark executions.
[CollectionDefinition("R102 distinct TXT correlation", DisableParallelization = true)]
public sealed class R102DistinctTxtCorrelationCollection { }

[Collection("R102 distinct TXT correlation")]
public sealed class R102DistinctTxtCorrelationTests
{
    private static readonly DateTime BaseTime =
        new(2026, 10, 26, 11, 0, 0, DateTimeKind.Utc);

    // Distinct synthetic high-entropy names; no live credentials or domains.
    private static readonly string[] Labels =
    {
        "x9q8v7m6n5p4t3k2rz0h1w2c3v4b5n6m7l8k9j0i1u2y3t4r5s6",
        "v6n1z7m3q9w4t0p5k8c2r6b1s7x3j9d4h0f5l8y2g6a1e7o3u9",
        "q4n8v2x6k0s5p9h3t7w1r4m8y2c6j0d5f9g3b7l1z4a8e2u6i0"
    };

    [Fact]
    public async Task R102_Uses_Three_Distinct_HighEntropy_Txt_Names_As_Corroboration()
    {
        var rule = new R102_DNSTunnelingViaLongLabelsRule();
        var root = "exfil-" + Guid.NewGuid().ToString("N")[..8] + ".example";
        var source = "10.248.10.10";
        DetectionEvent? first = null;
        DetectionEvent? last = null;
        for (var index = 0; index < Labels.Length; index++)
        {
            var record = Record(source, Labels[index] + "." + root, "TXT");
            var evaluated = await rule.EvaluateAsync(new RuleEvaluationContext(
                record, Sensitivity.Balanced, BaseTime.AddSeconds(index * 20)));
            Assert.True(evaluated.Matched);
            var evt = Assert.Single(evaluated.Events);
            first ??= evt;
            last = evt;
            Assert.Equal((index + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), EvidenceValue(evt, "dns.distinctSuspiciousTxtNames"));
            Assert.Equal(index == 2,
                EvidenceValue(evt, "matched_conditions").Contains(
                    "multiple_distinct_suspicious_txt_names", StringComparison.OrdinalIgnoreCase));
        }

        Assert.NotNull(first);
        Assert.NotNull(last);
        Assert.True(last!.ConfidenceScore > first!.ConfidenceScore);
        Assert.True(last.ConfidenceScore >= 0.80);
        Assert.Equal(80, rule.PrecisionProfile.MinimumConfidence);

        // Behavioral corroboration alone is not mature-baseline evidence.
        // Do not change the existing 80% floor or baseline promotion contract.
        var policy = RuleTuningCatalog.Resolve(
            "SmallBusiness", rule.Descriptor, last,
            Record(source, Labels[2] + "." + root, "TXT"),
            new ApprovedAssetRegistry(new EnvironmentTuningOptions()),
            baselineReady: false);
        Assert.Equal(RuleMode.Shadow, policy.EffectiveMode);
    }

    [Fact]
    public async Task R102_Identical_Retries_Never_Count_As_Distinct_Corroboration()
    {
        var rule = new R102_DNSTunnelingViaLongLabelsRule();
        var root = "retry-" + Guid.NewGuid().ToString("N")[..8] + ".example";
        var record = Record("10.248.10.20", Labels[0] + "." + root, "TXT");
        for (var index = 0; index < 4; index++)
        {
            var evaluated = await rule.EvaluateAsync(new RuleEvaluationContext(
                record, Sensitivity.Balanced, BaseTime.AddSeconds(index * 20)));
            Assert.True(evaluated.Matched);
            var evt = Assert.Single(evaluated.Events);
            Assert.Equal("1", EvidenceValue(evt, "dns.distinctSuspiciousTxtNames"));
            Assert.False(EvidenceValue(evt, "matched_conditions").Contains(
                "multiple_distinct_suspicious_txt_names", StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public async Task R102_Normal_Dns_Browsing_Cannot_Prime_A_Suspicious_Query_Burst()
    {
        var rule = new R102_DNSTunnelingViaLongLabelsRule();
        var root = "short-noise-" + Guid.NewGuid().ToString("N")[..8] + ".example";
        var source = "10.248.11.90";
        var start = BaseTime.AddHours(1);

        // Ten ordinary lookups under the same registrable root are not
        // independent tunneling evidence, even with a shared client IP.
        for (var i = 0; i < 10; i++)
        {
            var ordinary = await rule.EvaluateAsync(new RuleEvaluationContext(
                Record(source, $"status{i}." + root, "A"),
                Sensitivity.Balanced, start.AddSeconds(i * 10)));
            Assert.False(ordinary.Matched);
        }

        // This is high entropy and close to the length threshold, but one
        // subthreshold A query alone must not inherit the ten ordinary
        // DNS observations as a suspicious burst.
        var label = Labels[0][..48];
        var first = await rule.EvaluateAsync(new RuleEvaluationContext(
            Record(source, label + "." + root, "A"),
            Sensitivity.Balanced, start.AddSeconds(110)));
        Assert.False(first.Matched);

        // A second independently observed candidate with the same shape is
        // legitimate repeated-shape evidence (still subject to precision
        // and baseline controls, not automatic alert promotion).
        var second = await rule.EvaluateAsync(new RuleEvaluationContext(
            Record(source, Labels[1][..48] + "." + root, "A"),
            Sensitivity.Balanced, start.AddSeconds(130)));
        Assert.True(second.Matched);
        var evt = Assert.Single(second.Events);
        Assert.Equal("2", EvidenceValue(evt, "count"));
        Assert.Contains("repeated_long_query_shape",
            EvidenceValue(evt, "matched_conditions"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task R102_Null_Dns_Query_Type_Does_Not_Claim_Txt_Corroboration()
    {
        var rule = new R102_DNSTunnelingViaLongLabelsRule();
        var root = "nulltype-" + Guid.NewGuid().ToString("N")[..8] + ".example";
        for (var index = 0; index < Labels.Length; index++)
        {
            var result = await rule.EvaluateAsync(new RuleEvaluationContext(
                Record("10.248.10.50", Labels[index] + "." + root, "NULL"),
                Sensitivity.Balanced, BaseTime.AddSeconds(index * 20)));
            Assert.True(result.Matched);
            var evt = Assert.Single(result.Events);
            Assert.Equal("0", EvidenceValue(evt, "dns.distinctSuspiciousTxtNames"));
            Assert.False(EvidenceValue(evt, "matched_conditions").Contains(
                "multiple_distinct_suspicious_txt_names", StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public async Task R102_Does_Not_Combine_Different_Sources_Or_Expired_Windows()
    {
        var rule = new R102_DNSTunnelingViaLongLabelsRule();
        var root = "window-" + Guid.NewGuid().ToString("N")[..8] + ".example";

        async Task<DetectionEvent> Evaluate(string source, string label, DateTime timestamp)
        {
            var result = await rule.EvaluateAsync(new RuleEvaluationContext(
                Record(source, label + "." + root, "TXT"), Sensitivity.Balanced, timestamp));
            Assert.True(result.Matched);
            return Assert.Single(result.Events);
        }

        await Evaluate("10.248.10.40", Labels[0], BaseTime);
        await Evaluate("10.248.10.40", Labels[1], BaseTime.AddSeconds(20));

        var differentSource = await Evaluate(
            "10.248.10.41", Labels[2], BaseTime.AddSeconds(40));
        Assert.Equal("1", EvidenceValue(differentSource, "dns.distinctSuspiciousTxtNames"));
        Assert.False(EvidenceValue(differentSource, "matched_conditions").Contains(
                "multiple_distinct_suspicious_txt_names", StringComparison.OrdinalIgnoreCase));

        // A third distinct query for the original source arrives outside the
        // five-minute observation window and must not complete the old burst.
        var expired = await Evaluate(
            "10.248.10.40", Labels[2], BaseTime.AddMinutes(6));
        Assert.Equal("1", EvidenceValue(expired, "dns.distinctSuspiciousTxtNames"));
        Assert.False(EvidenceValue(expired, "matched_conditions").Contains(
                "multiple_distinct_suspicious_txt_names", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task R102_Does_Not_Boost_Validation_Or_Known_Telemetry_Txt_Queries()
    {
        var rule = new R102_DNSTunnelingViaLongLabelsRule();
        var source = "10.248.10.30";
        for (var index = 0; index < 3; index++)
        {
            var validation = await rule.EvaluateAsync(new RuleEvaluationContext(
                Record(source, "_acme-challenge." + Labels[index] + ".example", "TXT"),
                Sensitivity.Balanced, BaseTime.AddSeconds(index * 20)));
            Assert.False(validation.Matched);

            var known = await rule.EvaluateAsync(new RuleEvaluationContext(
                Record(source, Labels[index] + ".microsoft.com", "TXT"),
                Sensitivity.Balanced, BaseTime.AddSeconds(index * 20)));
            if (known.Matched)
            {
                var evt = Assert.Single(known.Events);
                Assert.Equal("0", EvidenceValue(evt, "dns.distinctSuspiciousTxtNames"));
                Assert.False(EvidenceValue(evt, "matched_conditions").Contains(
                "multiple_distinct_suspicious_txt_names", StringComparison.OrdinalIgnoreCase));
            }
        }
    }

    private static TrafficRecord Record(string source, string query, string qtype)
        => new()
        {
            Source = source,
            Destination = "8.8.8.8",
            DestinationPort = 53,
            Protocol = "DNS",
            ApplicationProtocol = "DNS",
            ApplicationService = "DNS",
            IsUdp = true,
            DnsQname = query,
            DnsQtype = qtype
        };

    private static string EvidenceValue(DetectionEvent evt, string key)
        => evt.StructuredEvidence?.Items.FirstOrDefault(item =>
            string.Equals(item.Key, key, StringComparison.OrdinalIgnoreCase))?.Value
            ?? throw new InvalidOperationException("Missing structured evidence: " + key);
}
