using System.Linq;
using Carthago.Services.Baseline;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Dns;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class DnsPrecisionRuleTests
{
    public static IEnumerable<object[]> PrecisionDnsRules()
    {
        yield return new object[] { new R094_DGALikeDomainQueryRule() };
        yield return new object[] { new R095_NewlyObservedDomainWithHighEntropyRule() };
        yield return new object[] { new R096_FastFluxDNSPatternRule() };
        yield return new object[] { new R097_ExcessiveUniqueSubdomainsRule() };
        yield return new object[] { new R098_SuspiciousDynamicDNSProviderRule() };
        yield return new object[] { new R099_DNSQueryToNewlyRegisteredDomainRule() };
        yield return new object[] { new R100_DNSQueryForInternalNameToExternalResolverRule() };
        yield return new object[] { new R101_DNSCNAMEChainAbuseRule() };
        yield return new object[] { new R102_DNSTunnelingViaLongLabelsRule() };
        yield return new object[] { new R103_DNSBeaconingWithStableIntervalRule() };
    }

    [Theory]
    [MemberData(nameof(PrecisionDnsRules))]
    public async Task Precision_dns_rules_return_no_match_without_dns_telemetry(IDetectionRule rule)
    {
        var context = CreateContext(new TrafficRecord
        {
            Source = "10.0.0.10",
            Destination = "8.8.8.8",
            DestinationPort = 53,
            Protocol = "UDP",
            IsUdp = true
        });

        var result = await rule.EvaluateAsync(context);

        Assert.False(result.Matched);
        Assert.Empty(result.Events);
    }

    [Theory]
    [MemberData(nameof(PrecisionDnsRules))]
    public async Task Precision_dns_rules_return_no_match_for_anytext_only_input(IDetectionRule rule)
    {
        var context = CreateContext(new TrafficRecord
        {
            Source = "10.0.0.20",
            Destination = "198.51.100.10",
            DestinationPort = 443,
            Protocol = "TCP",
            Info = "averylongrandomlookinglabel12345.duckdns.org newly registered beacon every 30s",
            HttpHost = "not-dns.example",
            IsTcp = true
        });

        var result = await rule.EvaluateAsync(context);

        Assert.False(result.Matched);
    }

    [Theory]
    [MemberData(nameof(PrecisionDnsRules))]
    public async Task Precision_dns_rules_return_no_match_for_port_only_records(IDetectionRule rule)
    {
        var context = CreateContext(new TrafficRecord
        {
            Source = "10.0.0.30",
            Destination = "8.8.8.8",
            DestinationPort = 53,
            Protocol = "UDP",
            ApplicationProtocol = "UDP",
            ApplicationService = "UDP",
            IsUdp = true
        });

        var result = await rule.EvaluateAsync(context);

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R094_matches_dga_like_dns_query_with_structured_evidence()
    {
        // R094 suppresses an established source/domain baseline after three
        // observations. Reusing ProgramData made this test depend on previous
        // runs (and could collide with a live Carthago instance).
        var directory = Path.Combine(Path.GetTempPath(), "carthago-r094-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (BaselineStore.UseScoped(new BaselineStore(new BaselineOptions { DirectoryPath = directory })))
            {
                var rule = new R094_DGALikeDomainQueryRule();
                var context = CreateContext(CreateDnsRecord(
                    "x9q8v7m6n5p4t3k2rz.example",
                    qtype: "A",
                    source: "10.0.1.10"));

                var result = await rule.EvaluateAsync(context);
                var evt = AssertSingleEvent(result, "R094", SeverityLevel.High, 0.70);
                AssertEvidence(evt, "dns.qname", "analyst.whyMatched", "response.recommended.1");

                // A persistent known DGA-shaped domain should still be
                // suppressed: isolation fixes the test, not detector policy.
                await rule.EvaluateAsync(context);
                await rule.EvaluateAsync(context);
                Assert.False((await rule.EvaluateAsync(context)).Matched);
            }
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task R094_ignores_punycode_domains_to_avoid_idn_overlap()
    {
        var rule = new R094_DGALikeDomainQueryRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("xn--d1acpjx3f.example", qtype: "A", source: "10.0.1.101")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R095_matches_first_seen_high_entropy_domain()
    {
        var rule = new R095_NewlyObservedDomainWithHighEntropyRule();
        var query = "zx9q8v7m6n5p4t3k2r1s0u9v.h7k6j5m4n3.example";
        var context = CreateContext(CreateDnsRecord(query, qtype: "A", source: "10.0.1.11"));

        var result = await rule.EvaluateAsync(context);

        var evt = AssertSingleEvent(result, "R095", SeverityLevel.Medium, 0.55);
        AssertEvidence(evt, "dns.entropy", "baseline.reason", "analyst.whyMatched");
    }

    [Fact]
    public async Task R096_matches_fast_flux_answer_set()
    {
        var rule = new R096_FastFluxDNSPatternRule();
        var context = CreateContext(CreateDnsRecord(
            $"flux-{UniqueLabel(8)}.example",
            qtype: "A",
            answers: "198.51.100.10 198.51.100.11 198.51.100.12 198.51.100.13 198.51.100.14 198.51.100.15",
            ttl: 30,
            isResponse: true,
            source: "10.0.1.12"));

        var result = await rule.EvaluateAsync(context);

        var evt = AssertSingleEvent(result, "R096", SeverityLevel.High, 0.60);
        AssertEvidence(evt, "dns.answerCount", "dns.ttl", "analyst.severityReason");
    }

    [Fact]
    public async Task R097_requires_distinct_subdomain_threshold()
    {
        var rule = new R097_ExcessiveUniqueSubdomainsRule();
        var root = $"{UniqueLabel(6)}.example";
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 25; index++)
        {
            var query = $"{UniqueLabel(10)}{index}.{root}";
            last = await rule.EvaluateAsync(CreateContext(CreateDnsRecord(query, source: "10.0.1.13"), new DateTime(2026, 4, 29, 12, 0, index, DateTimeKind.Utc)));
        }

        var evt = AssertSingleEvent(last!, "R097", SeverityLevel.Medium, 0.50);
        AssertEvidence(evt, "dns.uniqueSubdomains", "window_seconds", "matched_conditions");
    }

    [Fact]
    public async Task R098_matches_dynamic_dns_provider_query()
    {
        var rule = new R098_SuspiciousDynamicDNSProviderRule();
        var context = CreateContext(CreateDnsRecord("x8q7v6m5n4p3.duckdns.org", qtype: "A", source: "10.0.1.14"));

        var result = await rule.EvaluateAsync(context);

        var evt = AssertSingleEvent(result, "R098", SeverityLevel.Medium, 0.45);
        AssertEvidence(evt, "dns.dynamicProvider", "baseline.reason", "response.recommended.1");
    }

    [Fact]
    public async Task R098_ignores_first_seen_human_readable_ddns_label()
    {
        var rule = new R098_SuspiciousDynamicDNSProviderRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("mynas.duckdns.org", qtype: "A", source: "10.0.1.141")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R099_requires_recent_reputation_timing()
    {
        var rule = new R099_DNSQueryToNewlyRegisteredDomainRule();
        var record = CreateDnsRecord($"{UniqueLabel(10)}.recent.example", qtype: "A", source: "10.0.1.15");
        record.ReputationLastSeen = new DateTime(2026, 4, 28, 10, 0, 0, DateTimeKind.Utc);
        record.ReputationScore = 82;

        var result = await rule.EvaluateAsync(CreateContext(record, new DateTime(2026, 4, 29, 12, 0, 0, DateTimeKind.Utc)));

        var evt = AssertSingleEvent(result, "R099", SeverityLevel.High, 0.55);
        AssertEvidence(evt, "reputation.lastSeenDays", "baseline.reason", "analyst.whyMatched");
    }

    [Fact]
    public async Task R100_requires_repeated_internal_name_leaks_to_external_resolver()
    {
        var rule = new R100_DNSQueryForInternalNameToExternalResolverRule();
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 3; index++)
        {
            var record = CreateDnsRecord("dc01.corp", qtype: "A", source: "10.0.1.16", destination: "8.8.8.8");
            last = await rule.EvaluateAsync(CreateContext(record, new DateTime(2026, 4, 29, 13, 0, index, DateTimeKind.Utc)));
        }

        var evt = AssertSingleEvent(last!, "R100", SeverityLevel.High, 0.50);
        AssertEvidence(evt, "resolver.destination", "count", "matched_conditions");
    }

    [Fact]
    public async Task R100_requires_more_volume_for_common_single_label_fallback_names()
    {
        var rule = new R100_DNSQueryForInternalNameToExternalResolverRule();
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 3; index++)
        {
            var record = CreateDnsRecord("wpad", qtype: "A", source: "10.0.1.161", destination: "8.8.8.8");
            last = await rule.EvaluateAsync(CreateContext(record, new DateTime(2026, 4, 29, 13, 30, index, DateTimeKind.Utc)));
        }

        Assert.NotNull(last);
        Assert.False(last!.Matched);
    }

    [Fact]
    public async Task R101_matches_deep_cname_chain_in_dns_response()
    {
        var rule = new R101_DNSCNAMEChainAbuseRule();
        var answers = "alias1.example CNAME alias2.example CNAME alias3.example CNAME alias4.example CNAME alias5.example CNAME alias6.example";
        var context = CreateContext(CreateDnsRecord($"cname-{UniqueLabel(6)}.example", qtype: "A", answers: answers, ttl: 60, isResponse: true, source: "10.0.1.17"));

        var result = await rule.EvaluateAsync(context);

        var evt = AssertSingleEvent(result, "R101", SeverityLevel.High, 0.45);
        AssertEvidence(evt, "dns.cnameCount", "dns.answers", "analyst.falsePositives");
    }

    [Fact]
    public async Task R101_ignores_shallow_cname_chain_into_known_provider()
    {
        var rule = new R101_DNSCNAMEChainAbuseRule();
        var answers = "edge1.example CNAME edge2.cloudfront.net CNAME edge3.akamaiedge.net CNAME edge4.cloudfront.net";
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord($"cdn-{UniqueLabel(6)}.example", qtype: "A", answers: answers, ttl: 60, isResponse: true, source: "10.0.1.171")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R102_matches_long_high_entropy_label_and_preserves_cooldown_suppression()
    {
        var rule = new R102_DNSTunnelingViaLongLabelsRule();
        var query = $"{UniqueLabel(56)}.example";
        var first = await rule.EvaluateAsync(CreateContext(CreateDnsRecord(query, qtype: "TXT", source: "10.0.1.18"), new DateTime(2026, 4, 29, 14, 0, 0, DateTimeKind.Utc)));
        var second = await rule.EvaluateAsync(CreateContext(CreateDnsRecord(query, qtype: "TXT", source: "10.0.1.18"), new DateTime(2026, 4, 29, 14, 1, 0, DateTimeKind.Utc)));

        var firstEvent = AssertSingleEvent(first, "R102", SeverityLevel.High, 0.70);
        var secondEvent = AssertSingleEvent(second, "R102", SeverityLevel.High, 0.70);
        Assert.Equal(DetectionSuppressionStatus.Suppressed, secondEvent.SuppressionStatus);
        AssertEvidence(firstEvent, "dns.maxLabelLength", "dns.entropy", "analyst.whyMatched");
    }

    [Fact]
    public async Task R102_matches_monolithic_txt_label_replay_sample()
    {
        var rule = new R102_DNSTunnelingViaLongLabelsRule();
        var query = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.exfil.example";
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord(query, qtype: "TXT", source: "10.0.0.26"), new DateTime(2026, 4, 29, 14, 5, 0, DateTimeKind.Utc)));

        var evt = AssertSingleEvent(result, "R102", SeverityLevel.High, 0.75);
        AssertEvidence(evt, "dns.uniqueCharactersInLongestLabel", "matched_conditions", "analyst.whyMatched");
    }

    [Fact]
    public async Task R102_requires_repeat_or_txt_context_for_single_long_label()
    {
        var rule = new R102_DNSTunnelingViaLongLabelsRule();
        var query = $"{UniqueLabel(56)}.example";
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord(query, qtype: "A", source: "10.0.1.181"), new DateTime(2026, 4, 29, 14, 10, 0, DateTimeKind.Utc)));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R103_requires_stable_dns_interval_window()
    {
        var rule = new R103_DNSBeaconingWithStableIntervalRule();
        var root = $"{UniqueLabel(6)}.example";
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 6; index++)
        {
            var record = CreateDnsRecord($"beacon.{root}", qtype: "A", source: "10.0.1.19");
            last = await rule.EvaluateAsync(CreateContext(record, new DateTime(2026, 4, 29, 15, 0, 0, DateTimeKind.Utc).AddSeconds(index * 30)));
        }

        var evt = AssertSingleEvent(last!, "R103", SeverityLevel.High, 0.60);
        AssertEvidence(evt, "dns.averageIntervalSeconds", "dns.intervalStdDev", "count");
    }

    [Fact]
    public async Task R103_ignores_stable_root_cadence_when_exact_queries_rotate()
    {
        var rule = new R103_DNSBeaconingWithStableIntervalRule();
        var root = $"{UniqueLabel(6)}.example";
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 6; index++)
        {
            var record = CreateDnsRecord($"beacon{index}.{root}", qtype: "A", source: "10.0.1.191");
            last = await rule.EvaluateAsync(CreateContext(record, new DateTime(2026, 4, 29, 15, 30, 0, DateTimeKind.Utc).AddSeconds(index * 30)));
        }

        Assert.NotNull(last);
        Assert.False(last!.Matched);
    }

    [Fact]
    public void Migrated_dns_rules_register_rule_owned_precision_profiles()
    {
        var r099 = RulePrecisionCatalog.GetProfile("R099", "Dns", SeverityLevel.High);
        var r100 = RulePrecisionCatalog.GetProfile("R100", "Dns", SeverityLevel.High);
        var r103 = RulePrecisionCatalog.GetProfile("R103", "Dns", SeverityLevel.High);

        Assert.Contains(RuleTelemetryKind.ThreatIntel, r099.RequiredTelemetry);
        Assert.Equal(3, r100.Threshold);
        Assert.Equal(TimeSpan.FromMinutes(15), r103.Window);
    }

    private static RuleEvaluationContext CreateContext(TrafficRecord record, DateTime? timestampUtc = null)
        => new(record, Sensitivity.Balanced, timestampUtc ?? new DateTime(2026, 4, 29, 12, 0, 0, DateTimeKind.Utc));

    private static TrafficRecord CreateDnsRecord(
        string query,
        string qtype = "A",
        string source = "10.0.0.10",
        string destination = "8.8.8.8",
        string? answers = null,
        int? ttl = null,
        bool isResponse = false)
        => new()
        {
            Source = source,
            Destination = destination,
            DestinationPort = 53,
            Protocol = "DNS",
            ApplicationProtocol = "DNS",
            ApplicationService = "DNS",
            DnsQname = query,
            DnsQtype = qtype,
            DnsRcode = "NOERROR",
            DnsAnswers = answers,
            DnsTtl = ttl,
            DnsIsResponse = isResponse,
            IsUdp = true
        };

    private static DetectionEvent AssertSingleEvent(RuleEvaluationResult result, string ruleId, SeverityLevel minimumSeverity, double minimumConfidence)
    {
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal(ruleId, evt.RuleId);
        Assert.True(evt.ConfidenceScore >= minimumConfidence, $"Expected confidence >= {minimumConfidence:F2} but got {evt.ConfidenceScore:F2}.");
        Assert.True(evt.Severity >= minimumSeverity);
        Assert.NotNull(evt.StructuredEvidence);
        return evt;
    }

    private static void AssertEvidence(DetectionEvent evt, params string[] expectedKeys)
    {
        var keys = evt.StructuredEvidence!.Items.Select(item => item.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var expected in expectedKeys)
            Assert.Contains(expected, keys);
    }

    private static string UniqueLabel(int length)
    {
        const string alphabet = "bcdfghjklmnpqrstvwxyz0123456789";
        var seed = Guid.NewGuid().ToString("N");
        var chars = new char[length];
        for (var index = 0; index < length; index++)
            chars[index] = alphabet[(seed[index % seed.Length] + index) % alphabet.Length];
        return new string(chars);
    }
}
