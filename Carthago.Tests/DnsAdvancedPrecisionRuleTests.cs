using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class DnsAdvancedPrecisionRuleTests
{
    public static IEnumerable<object[]> PrecisionDnsAdvancedRules()
    {
        yield return new object[] { new R178_DnsQueryForCryptoMiningPoolRule() };
        yield return new object[] { new R179_DnsQueryForTorOnionGatewayRule() };
        yield return new object[] { new R180_DnsQueryToHighRiskTldRule() };
        yield return new object[] { new R181_ExcessiveDnsAnyQueriesRule() };
        yield return new object[] { new R182_DnsZoneTransferAttemptRule() };
        yield return new object[] { new R183_DnssecRandomSubdomainSpikeRule() };
        yield return new object[] { new R184_ExternalReverseDnsEnumerationRule() };
        yield return new object[] { new R185_CanaryOrMetadataDomainProbeRule() };
        yield return new object[] { new R186_DnsCaaRecordProbingBurstRule() };
        yield return new object[] { new R187_DnsNullQueryUsageRule() };
        yield return new object[] { new R188_ActiveDirectorySrvEnumerationRule() };
        yield return new object[] { new R189_AdSrvQueryToExternalResolverRule() };
        yield return new object[] { new R190_DnsShortTtlBurstRule() };
        yield return new object[] { new R191_ConsonantHeavyDgaDomainRule() };
        yield return new object[] { new R192_PunycodeHomographDomainRule() };
        yield return new object[] { new R193_CloudBrandLookalikeDomainRule() };
        yield return new object[] { new R194_DohOverUncommonHostRule() };
        yield return new object[] { new R195_DnsOverTlsToUnapprovedResolverRule() };
        yield return new object[] { new R196_NxdomainUniqueRootSpikeRule() };
        yield return new object[] { new R197_DnsRebindingPrivateIpAnswerRule() };
    }

    [Theory]
    [MemberData(nameof(PrecisionDnsAdvancedRules))]
    public async Task Precision_dns_advanced_rules_return_no_match_without_required_context(IDetectionRule rule)
    {
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.30.0.10",
            Destination = "10.30.0.20",
            DestinationPort = 9000,
            Protocol = "TCP",
            IsTcp = true,
            Length = 512
        }));

        Assert.False(result.Matched);
        Assert.Empty(result.Events);
    }

    [Theory]
    [MemberData(nameof(PrecisionDnsAdvancedRules))]
    public async Task Precision_dns_advanced_rules_ignore_anytext_only_inputs(IDetectionRule rule)
    {
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.30.0.11",
            Destination = "198.51.100.11",
            DestinationPort = 443,
            Protocol = "TCP",
            IsTcp = true,
            Info = "mining pool tor2web zip ANY AXFR DNSKEY interact.sh CAA NULL _ldap._tcp low ttl punycode micros0ft dns-query dot NXDOMAIN rebinding",
            HttpHost = "docs.example.com",
            Length = 1024
        }));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R178_matches_known_mining_pool_query_with_pool_like_subdomain()
    {
        var rule = new R178_DnsQueryForCryptoMiningPoolRule();
        var query = $"stratum-{UniqueLabel(6)}.2miners.com";
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord(query, source: "10.30.1.10")));

        var evt = AssertSingleEvent(result, "R178", SeverityLevel.High, 0.50);
        AssertEvidence(evt, "matched_conditions", "dns.poolRoot");
    }

    [Fact]
    public async Task R178_ignores_generic_crypto_brand_domain_outside_known_pool_roots()
    {
        var rule = new R178_DnsQueryForCryptoMiningPoolRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("wallet.example.com", source: "10.30.1.11")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R179_matches_tor_onion_gateway_query()
    {
        var rule = new R179_DnsQueryForTorOnionGatewayRule();
        var query = $"{UniqueLabel(10)}.onion.to";
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord(query, source: "10.30.1.20")));

        var evt = AssertSingleEvent(result, "R179", SeverityLevel.Medium, 0.25);
        AssertEvidence(evt, "matched_conditions");
    }

    [Fact]
    public async Task R179_ignores_unrelated_domain_with_onion_word()
    {
        var rule = new R179_DnsQueryForTorOnionGatewayRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("onion-soup.example.com", source: "10.30.1.21")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R180_matches_first_seen_suspicious_high_risk_tld()
    {
        var rule = new R180_DnsQueryToHighRiskTldRule();
        var query = $"{UniqueLabel(11)}.zip";
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord(query, source: "10.30.1.30")));

        var evt = AssertSingleEvent(result, "R180", SeverityLevel.Low, 0.20);
        AssertEvidence(evt, "baseline.reason", "dns.entropy", "matched_conditions");
    }

    [Fact]
    public async Task R180_ignores_short_human_readable_high_risk_tld_domain()
    {
        var rule = new R180_DnsQueryToHighRiskTldRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("docs.zip", source: "10.30.1.31")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R181_matches_repeated_dns_any_queries()
    {
        var rule = new R181_ExcessiveDnsAnyQueriesRule();
        var baseTime = new DateTime(2026, 4, 30, 14, 0, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 5; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(
                CreateDnsRecord($"any-{index}.{UniqueLabel(6)}.example", qtype: "ANY", source: "10.30.1.40", destination: "8.8.8.8"),
                baseTime.AddSeconds(index * 20)));
        }

        var evt = AssertSingleEvent(last!, "R181", SeverityLevel.Medium, 0.35);
        AssertEvidence(evt, "count", "window_seconds", "matched_conditions");
    }

    [Fact]
    public async Task R181_ignores_single_dns_any_query()
    {
        var rule = new R181_ExcessiveDnsAnyQueriesRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("single-any.example", qtype: "ANY", source: "10.30.1.41", destination: "8.8.8.8")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R182_matches_boundary_crossing_zone_transfer_attempt()
    {
        var rule = new R182_DnsZoneTransferAttemptRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("corp.example.com", qtype: "AXFR", source: "10.30.1.50", destination: "198.51.100.50")));

        var evt = AssertSingleEvent(result, "R182", SeverityLevel.High, 0.50);
        AssertEvidence(evt, "matched_conditions");
    }

    [Fact]
    public async Task R182_ignores_internal_secondary_zone_transfer()
    {
        var rule = new R182_DnsZoneTransferAttemptRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("corp.example.com", qtype: "AXFR", source: "10.30.1.51", destination: "10.30.1.52")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R183_matches_random_dnssec_subdomain_burst()
    {
        var rule = new R183_DnssecRandomSubdomainSpikeRule();
        var root = $"{UniqueLabel(8)}.example";
        var baseTime = new DateTime(2026, 4, 30, 14, 10, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 8; index++)
        {
            var query = $"{UniqueLabel(18)}{index}.{root}";
            last = await rule.EvaluateAsync(CreateContext(
                CreateDnsRecord(query, qtype: "DNSKEY", source: "10.30.1.60"),
                baseTime.AddSeconds(index * 15)));
        }

        var evt = AssertSingleEvent(last!, "R183", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "count", "window_seconds", "matched_conditions");
    }

    [Fact]
    public async Task R183_ignores_apex_dnssec_lookup()
    {
        var rule = new R183_DnssecRandomSubdomainSpikeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("example.com", qtype: "DNSKEY", source: "10.30.1.61")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R184_matches_external_reverse_dns_enumeration_burst()
    {
        var rule = new R184_ExternalReverseDnsEnumerationRule();
        var baseTime = new DateTime(2026, 4, 30, 14, 20, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 10; index++)
        {
            var query = $"{index}.2.0.192.in-addr.arpa";
            last = await rule.EvaluateAsync(CreateContext(
                CreateDnsRecord(query, qtype: "PTR", source: "10.30.1.70", destination: "8.8.8.8"),
                baseTime.AddSeconds(index * 10)));
        }

        var evt = AssertSingleEvent(last!, "R184", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "count", "window_seconds", "matched_conditions");
    }

    [Fact]
    public async Task R184_ignores_isolated_ptr_lookup()
    {
        var rule = new R184_ExternalReverseDnsEnumerationRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("1.2.0.192.in-addr.arpa", qtype: "PTR", source: "10.30.1.71", destination: "8.8.8.8")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R185_matches_known_canary_domain_query()
    {
        var rule = new R185_CanaryOrMetadataDomainProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord($"{UniqueLabel(8)}.interact.sh", source: "10.30.1.80")));

        var evt = AssertSingleEvent(result, "R185", SeverityLevel.Low, 0.20);
        AssertEvidence(evt, "matched_conditions");
    }

    [Fact]
    public async Task R185_ignores_similar_looking_non_canary_domain()
    {
        var rule = new R185_CanaryOrMetadataDomainProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("interact-safe.example.com", source: "10.30.1.81")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R186_matches_caa_record_probing_burst()
    {
        var rule = new R186_DnsCaaRecordProbingBurstRule();
        var baseTime = new DateTime(2026, 4, 30, 14, 30, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 8; index++)
        {
            var query = $"{UniqueLabel(6)}{index}.example";
            last = await rule.EvaluateAsync(CreateContext(
                CreateDnsRecord(query, qtype: "CAA", source: "10.30.1.90"),
                baseTime.AddSeconds(index * 15)));
        }

        var evt = AssertSingleEvent(last!, "R186", SeverityLevel.Low, 0.20);
        AssertEvidence(evt, "count", "window_seconds", "matched_conditions");
    }

    [Fact]
    public async Task R186_ignores_single_caa_lookup()
    {
        var rule = new R186_DnsCaaRecordProbingBurstRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("example.com", qtype: "CAA", source: "10.30.1.91")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R187_matches_dns_null_query()
    {
        var rule = new R187_DnsNullQueryUsageRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord($"{UniqueLabel(8)}.example", qtype: "NULL", source: "10.30.1.100")));

        var evt = AssertSingleEvent(result, "R187", SeverityLevel.Medium, 0.25);
        AssertEvidence(evt, "matched_conditions");
    }

    [Fact]
    public async Task R187_ignores_txt_query()
    {
        var rule = new R187_DnsNullQueryUsageRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord($"{UniqueLabel(8)}.example", qtype: "TXT", source: "10.30.1.101")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R188_matches_ad_srv_enumeration_burst()
    {
        var rule = new R188_ActiveDirectorySrvEnumerationRule();
        var baseTime = new DateTime(2026, 4, 30, 14, 40, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        foreach (var (query, offset) in new[]
                 {
                     ("_ldap._tcp.dc._msdcs.corp.local", 0),
                     ("_kerberos._tcp.dc._msdcs.corp.local", 20),
                     ("_gc._tcp.corp.local", 40)
                 })
        {
            last = await rule.EvaluateAsync(CreateContext(
                CreateDnsRecord(query, qtype: "SRV", source: "10.30.1.110"),
                baseTime.AddSeconds(offset)));
        }

        var evt = AssertSingleEvent(last!, "R188", SeverityLevel.Medium, 0.35);
        AssertEvidence(evt, "count", "window_seconds", "matched_conditions");
    }

    [Fact]
    public async Task R188_ignores_single_ad_srv_lookup()
    {
        var rule = new R188_ActiveDirectorySrvEnumerationRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("_ldap._tcp.dc._msdcs.corp.local", qtype: "SRV", source: "10.30.1.111")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R189_matches_ad_srv_query_leaking_to_external_resolver()
    {
        var rule = new R189_AdSrvQueryToExternalResolverRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("_ldap._tcp.dc._msdcs.corp.local", qtype: "SRV", source: "10.30.1.120", destination: "8.8.8.8")));

        var evt = AssertSingleEvent(result, "R189", SeverityLevel.High, 0.50);
        AssertEvidence(evt, "resolver.destination", "matched_conditions");
    }

    [Fact]
    public async Task R189_ignores_public_srv_query_to_external_resolver()
    {
        var rule = new R189_AdSrvQueryToExternalResolverRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("_ldap._tcp.example.com", qtype: "SRV", source: "10.30.1.121", destination: "8.8.8.8")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R190_matches_repeated_short_ttl_dns_responses()
    {
        var rule = new R190_DnsShortTtlBurstRule();
        var root = $"{UniqueLabel(8)}.example";
        var baseTime = new DateTime(2026, 4, 30, 14, 50, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 6; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(
                CreateDnsRecord($"host{index}.{root}", qtype: "A", source: "10.30.1.130", ttl: 1, isResponse: true, answers: $"198.51.100.{index + 10}"),
                baseTime.AddSeconds(index * 10)));
        }

        var evt = AssertSingleEvent(last!, "R190", SeverityLevel.Medium, 0.35);
        AssertEvidence(evt, "count", "window_seconds", "matched_conditions");
    }

    [Fact]
    public async Task R190_ignores_higher_ttl_response()
    {
        var rule = new R190_DnsShortTtlBurstRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("stable.example", qtype: "A", source: "10.30.1.131", ttl: 30, isResponse: true, answers: "198.51.100.30")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R191_matches_consonant_heavy_dga_like_domain()
    {
        var rule = new R191_ConsonantHeavyDgaDomainRule();
        var query = "zxvbnmqwrtypsdf9.com";
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord(query, source: "10.30.1.140")));

        var evt = AssertSingleEvent(result, "R191", SeverityLevel.Medium, 0.35);
        AssertEvidence(evt, "dns.entropy", "matched_conditions");
    }

    [Fact]
    public async Task R191_ignores_human_readable_domain()
    {
        var rule = new R191_ConsonantHeavyDgaDomainRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("portalupdates.com", source: "10.30.1.141")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R192_matches_first_seen_punycode_homograph_candidate()
    {
        var rule = new R192_PunycodeHomographDomainRule();
        var query = "xn--pple-43d.com";
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord(query, source: "10.30.1.150")));

        var evt = AssertSingleEvent(result, "R192", SeverityLevel.Medium, 0.30);
        AssertEvidence(evt, "dns.punycodeLabel", "baseline.reason", "matched_conditions");
    }

    [Fact]
    public async Task R192_ignores_punycode_tld_usage()
    {
        var rule = new R192_PunycodeHomographDomainRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("brand.xn--p1ai", source: "10.30.1.151")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R193_matches_first_seen_cloud_brand_lookalike_label()
    {
        var rule = new R193_CloudBrandLookalikeDomainRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord($"login.micros0ft.{UniqueLabel(5)}", source: "10.30.1.160")));

        var evt = AssertSingleEvent(result, "R193", SeverityLevel.Medium, 0.30);
        AssertEvidence(evt, "dns.lookalikeBrand", "dns.lookalikeLabel", "baseline.reason", "matched_conditions");
    }

    [Fact]
    public async Task R193_ignores_legitimate_vendor_domain()
    {
        var rule = new R193_CloudBrandLookalikeDomainRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord("login.microsoft.com", source: "10.30.1.161")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R194_matches_doh_request_to_unapproved_external_host()
    {
        var rule = new R194_DohOverUncommonHostRule();
        // Use a complete base64url-encoded DNS wire question. A truncated
        // six-character query string is not an observed DoH operation.
        var observed = NetworkBatch186195Context.DohGet("resolver.evil.example");
        var result = await rule.EvaluateAsync(CreateContext(observed));

        var evt = AssertSingleEvent(result, "R194", SeverityLevel.Medium, 0.45);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R194_ignores_approved_public_doh_provider()
    {
        var rule = new R194_DohOverUncommonHostRule();
        // An approved host must stay excluded even with a valid DoH request.
        var observed = NetworkBatch186195Context.DohGet("dns.google");
        var result = await rule.EvaluateAsync(CreateContext(observed));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R195_matches_unapproved_external_dot_resolver()
    {
        var rule = new R195_DnsOverTlsToUnapprovedResolverRule();
        // Canonical parsed TCP/853 TLS metadata with an externally routable
        // resolver, rather than an incomplete TLS metadata stub.
        var observed = NetworkBatch186195Context.Dot("resolver.evil.example");
        var result = await rule.EvaluateAsync(CreateContext(observed));

        var evt = AssertSingleEvent(result, "R195", SeverityLevel.High, 0.50);
        AssertEvidence(evt, "matched_conditions");
    }

    [Fact]
    public async Task R195_ignores_approved_public_dot_resolver()
    {
        var rule = new R195_DnsOverTlsToUnapprovedResolverRule();
        var observed = NetworkBatch186195Context.Dot("dns.google");
        var result = await rule.EvaluateAsync(CreateContext(observed));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R195_ignores_port_853_record_without_real_tls_context()
    {
        var rule = new R195_DnsOverTlsToUnapprovedResolverRule();
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.30.1.182",
            Destination = "198.51.100.182",
            DestinationPort = 853,
            Protocol = "TCP",
            ApplicationProtocol = "TCP",
            ApplicationService = "TCP",
            IsTcp = true,
            Length = 1024
        }));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R196_matches_unique_root_nxdomain_spike()
    {
        var rule = new R196_NxdomainUniqueRootSpikeRule();
        var baseTime = new DateTime(2026, 4, 30, 15, 0, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 10; index++)
        {
            var query = $"{UniqueLabel(6)}.{UniqueLabel(5)}{index}.example";
            last = await rule.EvaluateAsync(CreateContext(
                CreateDnsRecord(query, qtype: "A", source: "10.30.1.190", rcode: "NXDOMAIN"),
                baseTime.AddSeconds(index * 10)));
        }

        var evt = AssertSingleEvent(last!, "R196", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "count", "window_seconds", "matched_conditions");
    }

    [Fact]
    public async Task R196_ignores_repeated_nxdomain_for_single_root()
    {
        var rule = new R196_NxdomainUniqueRootSpikeRule();
        var baseTime = new DateTime(2026, 4, 30, 15, 5, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 10; index++)
        {
            var query = $"{UniqueLabel(6)}{index}.same-root.example";
            last = await rule.EvaluateAsync(CreateContext(
                CreateDnsRecord(query, qtype: "A", source: "10.30.1.191", rcode: "NXDOMAIN"),
                baseTime.AddSeconds(index * 10)));
        }

        Assert.NotNull(last);
        Assert.False(last!.Matched);
    }

    [Fact]
    public async Task R197_matches_dns_rebinding_style_private_answer()
    {
        var rule = new R197_DnsRebindingPrivateIpAnswerRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord(
            "portal-login.example.com",
            qtype: "A",
            source: "10.30.1.200",
            answers: "192.168.1.10 198.51.100.10",
            ttl: 30,
            isResponse: true)));

        var evt = AssertSingleEvent(result, "R197", SeverityLevel.High, 0.50);
        AssertEvidence(evt, "dns.privateAnswer", "matched_conditions");
    }

    [Fact]
    public async Task R197_ignores_long_ttl_split_horizon_style_private_answer()
    {
        var rule = new R197_DnsRebindingPrivateIpAnswerRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateDnsRecord(
            "portal.example.com",
            qtype: "A",
            source: "10.30.1.201",
            answers: "10.0.0.5",
            ttl: 600,
            isResponse: true)));

        Assert.False(result.Matched);
    }

    [Fact]
    public void Migrated_dns_advanced_rules_register_rule_owned_precision_profiles()
    {
        _ = new R178_DnsQueryForCryptoMiningPoolRule();
        _ = new R181_ExcessiveDnsAnyQueriesRule();
        _ = new R189_AdSrvQueryToExternalResolverRule();
        _ = new R190_DnsShortTtlBurstRule();
        _ = new R194_DohOverUncommonHostRule();
        _ = new R195_DnsOverTlsToUnapprovedResolverRule();
        _ = new R196_NxdomainUniqueRootSpikeRule();
        _ = new R197_DnsRebindingPrivateIpAnswerRule();

        var r178 = RulePrecisionCatalog.GetProfile("R178", "DnsAdvanced", SeverityLevel.High);
        var r181 = RulePrecisionCatalog.GetProfile("R181", "DnsAdvanced", SeverityLevel.Medium);
        var r190 = RulePrecisionCatalog.GetProfile("R190", "DnsAdvanced", SeverityLevel.Medium);
        var r194 = RulePrecisionCatalog.GetProfile("R194", "DnsAdvanced", SeverityLevel.Medium);
        var r195 = RulePrecisionCatalog.GetProfile("R195", "DnsAdvanced", SeverityLevel.High);
        var r196 = RulePrecisionCatalog.GetProfile("R196", "DnsAdvanced", SeverityLevel.Medium);

        Assert.Equal(RuleRuntimeMode.Alert, r178.DefaultMode);
        Assert.Equal(5, r181.Threshold);
        Assert.Equal(TimeSpan.FromMinutes(5), r190.Window);
        Assert.Contains(RuleTelemetryKind.Http, r194.RequiredTelemetry);
        Assert.Contains(RuleTelemetryKind.Payload, r194.RequiredTelemetry);
        Assert.Equal(RuleRuntimeMode.Alert, r195.DefaultMode);
        Assert.Contains(RuleTelemetryKind.Tls, r195.RequiredTelemetry);
        Assert.Equal(10, r196.Threshold);
    }

    private static RuleEvaluationContext CreateContext(TrafficRecord record, DateTime? timestampUtc = null)
        => new(record, Sensitivity.Balanced, timestampUtc ?? new DateTime(2026, 4, 30, 13, 0, 0, DateTimeKind.Utc));

    private static TrafficRecord CreateDnsRecord(
        string query,
        string qtype = "A",
        string source = "10.30.0.10",
        string destination = "8.8.8.8",
        string? answers = null,
        int? ttl = null,
        bool isResponse = false,
        string rcode = "NOERROR")
        => new()
        {
            Id = Guid.NewGuid(),
            // The named source represents the client under observation.
            // DNS response packets reverse the wire endpoints and port roles.
            Source = isResponse || rcode.Equals("NXDOMAIN", StringComparison.OrdinalIgnoreCase) ? destination : source,
            Destination = isResponse || rcode.Equals("NXDOMAIN", StringComparison.OrdinalIgnoreCase) ? source : destination,
            SourcePort = isResponse || rcode.Equals("NXDOMAIN", StringComparison.OrdinalIgnoreCase) ? 53 : 53000,
            DestinationPort = isResponse || rcode.Equals("NXDOMAIN", StringComparison.OrdinalIgnoreCase) ? 53000 : 53,
            IpVersion = 4,
            Protocol = "DNS",
            ApplicationProtocol = "DNS",
            ApplicationService = "DNS",
            DnsQname = query,
            DnsQtype = qtype,
            DnsRcode = rcode,
            DnsAnswers = answers,
            DnsTtl = ttl,
            DnsIsResponse = isResponse || rcode.Equals("NXDOMAIN", StringComparison.OrdinalIgnoreCase),
            // AXFR/IXFR queries are TCP, not UDP transport observations.
            IsTcp = qtype is "AXFR" or "IXFR",
            IsUdp = qtype is not ("AXFR" or "IXFR")
        };

    private static TrafficRecord CreateWebRecord(
        string source,
        string destination,
        int destinationPort,
        string host,
        string method,
        string uri,
        string headers,
        string info,
        string service,
        string protocol,
        string? process = null)
        => new()
        {
            Source = source,
            Destination = destination,
            DestinationPort = destinationPort,
            Protocol = protocol,
            ApplicationProtocol = protocol,
            ApplicationService = service,
            HttpHost = host,
            HttpMethod = method,
            HttpUri = uri,
            HttpRequestHeaders = headers,
            Info = info,
            ProcessName = process,
            IsTcp = true,
            Length = 2048,
            L4Len = 2048
        };

    private static TrafficRecord CreateTlsRecord(
        string source,
        string destination,
        int destinationPort,
        string? sni = null,
        string? tlsVersion = null,
        string? process = null)
        => new()
        {
            Source = source,
            Destination = destination,
            DestinationPort = destinationPort,
            Protocol = "TLS",
            ApplicationProtocol = "TLS",
            ApplicationService = "HTTPS",
            Sni = sni,
            TlsVersion = tlsVersion,
            ProcessName = process,
            IsTcp = true,
            Length = 2048,
            L4Len = 2048
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
