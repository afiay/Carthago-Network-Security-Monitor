using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class TlsPkiPrecisionRuleTests
{
    public static IEnumerable<object[]> PrecisionTlsRules()
    {
        yield return new object[] { new R138_SelfSignedCertificateToExternalHostRule() };
        yield return new object[] { new R139_WeakTlsVersionObservedRule() };
        yield return new object[] { new R140_SuspiciousCertificateIssuerPatternRule() };
        yield return new object[] { new R141_NewSniWithRareTlsFingerprintRule() };
        yield return new object[] { new R142_TlsCertificateSubjectSniMismatchRule() };
        yield return new object[] { new R143_WildcardCertificateOnSensitiveServiceRule() };
        yield return new object[] { new R144_CertificateValidityPeriodTooLongRule() };
        yield return new object[] { new R145_ShortLivedCertificateWithNewSniRule() };
        yield return new object[] { new R146_TlsHandshakeFailureSpikeRule() };
        yield return new object[] { new R147_EncryptedClienthelloOrEchIndicatorRule() };
        yield return new object[] { new R148_TlsToDynamicDnsHostRule() };
        yield return new object[] { new R149_IpLiteralUsedAsTlsNameRule() };
        yield return new object[] { new R150_KnownMalwareLikeTlsFingerprintLabelRule() };
        yield return new object[] { new R151_Http2AlpnOnUncommonPortRule() };
        yield return new object[] { new R152_TlsFingerprintFanOutToManyAsnsRule() };
    }

    [Theory]
    [MemberData(nameof(PrecisionTlsRules))]
    public async Task Precision_tls_rules_return_no_match_without_tls_context(IDetectionRule rule)
    {
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.20.0.10",
            Destination = "10.20.0.20",
            DestinationPort = 9001,
            Protocol = "TCP",
            IsTcp = true,
            Length = 512
        }));

        Assert.False(result.Matched);
        Assert.Empty(result.Events);
    }

    [Theory]
    [MemberData(nameof(PrecisionTlsRules))]
    public async Task Precision_tls_rules_ignore_anytext_only_inputs(IDetectionRule rule)
    {
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.20.0.11",
            Destination = "198.51.100.11",
            DestinationPort = 9002,
            Protocol = "TCP",
            IsTcp = true,
            Info = "self-signed tls1.0 mitmproxy ja3 wildcard ech duckdns ip literal cobalt strike ja3 h2",
            Length = 1024
        }));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R138_matches_self_signed_external_tls()
    {
        var rule = new R138_SelfSignedCertificateToExternalHostRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.1.10",
            destination: "198.51.100.20",
            destinationPort: 443,
            sni: "stage.bad.example",
            tlsVersion: "TLS 1.2",
            certIssuer: "CN=stage.bad.example",
            certSubject: "CN=stage.bad.example")));

        var evt = AssertSingleEvent(result, "R138", SeverityLevel.Medium, 0.60);
        AssertEvidence(evt, "matched_conditions", "tls.certIssuer", "tls.certSubject");
    }

    [Fact]
    public async Task R138_ignores_non_self_signed_external_tls()
    {
        var rule = new R138_SelfSignedCertificateToExternalHostRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.1.11",
            destination: "198.51.100.21",
            destinationPort: 443,
            sni: "api.example.com",
            tlsVersion: "TLS 1.2",
            certIssuer: "CN=Let's Encrypt Authority X3",
            certSubject: "CN=api.example.com")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R139_matches_weak_tls_version()
    {
        var rule = new R139_WeakTlsVersionObservedRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.1.20",
            destination: "198.51.100.30",
            destinationPort: 443,
            sni: "legacy.example.com",
            tlsVersion: "TLS 1.0")));

        var evt = AssertSingleEvent(result, "R139", SeverityLevel.High, 0.70);
        AssertEvidence(evt, "matched_conditions", "tls.version");
    }

    [Fact]
    public async Task R139_ignores_modern_tls_version()
    {
        var rule = new R139_WeakTlsVersionObservedRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.1.21",
            destination: "198.51.100.31",
            destinationPort: 443,
            sni: "modern.example.com",
            tlsVersion: "TLS 1.3")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R140_matches_suspicious_issuer()
    {
        var rule = new R140_SuspiciousCertificateIssuerPatternRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.1.30",
            destination: "198.51.100.40",
            destinationPort: 443,
            sni: "proxy.example.com",
            tlsVersion: "TLS 1.2",
            certIssuer: "CN=mitmproxy",
            certSubject: "CN=proxy.example.com")));

        var evt = AssertSingleEvent(result, "R140", SeverityLevel.Medium, 0.50);
        AssertEvidence(evt, "matched_conditions", "tls.certIssuer");
    }

    [Fact]
    public async Task R140_ignores_public_ca_issuer()
    {
        var rule = new R140_SuspiciousCertificateIssuerPatternRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.1.31",
            destination: "198.51.100.41",
            destinationPort: 443,
            sni: "api.example.com",
            tlsVersion: "TLS 1.2",
            certIssuer: "CN=GlobalSign Atlas R3 DV TLS CA 2025 Q1",
            certSubject: "CN=api.example.com")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R141_matches_repeated_non_browser_fingerprint_to_same_sni()
    {
        var rule = new R141_NewSniWithRareTlsFingerprintRule();
        var baseTime = new DateTime(2026, 4, 30, 12, 0, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 3; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
                source: "10.20.1.40",
                destination: "198.51.100.50",
                destinationPort: 443,
                sni: "rare-beacon.example",
                tlsVersion: "TLS 1.2",
                ja4: "ja4-rare-141",
                process: "beacon.exe"), baseTime.AddSeconds(index * 20)));
        }

        var evt = AssertSingleEvent(last!, "R141", SeverityLevel.Medium, 0.50);
        AssertEvidence(evt, "matched_conditions", "count", "tls.sni");
    }

    [Fact]
    public async Task R141_ignores_browser_tls_repetition()
    {
        var rule = new R141_NewSniWithRareTlsFingerprintRule();
        var baseTime = new DateTime(2026, 4, 30, 12, 5, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 3; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
                source: "10.20.1.41",
                destination: "198.51.100.51",
                destinationPort: 443,
                sni: "browser.example",
                tlsVersion: "TLS 1.3",
                ja4: "ja4-browser-141",
                process: "chrome.exe"), baseTime.AddSeconds(index * 20)));
        }

        Assert.NotNull(last);
        Assert.False(last!.Matched);
    }

    [Fact]
    public async Task R142_matches_strong_sni_subject_mismatch()
    {
        var rule = new R142_TlsCertificateSubjectSniMismatchRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.1.50",
            destination: "198.51.100.60",
            destinationPort: 443,
            sni: "login.example.com",
            tlsVersion: "TLS 1.2",
            certIssuer: "CN=Test CA",
            certSubject: "CN=cdn-evil.net")));

        var evt = AssertSingleEvent(result, "R142", SeverityLevel.Medium, 0.55);
        AssertEvidence(evt, "matched_conditions", "tls.sni", "tls.certSubject");
    }

    [Fact]
    public async Task R142_ignores_same_root_name_difference()
    {
        var rule = new R142_TlsCertificateSubjectSniMismatchRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.1.51",
            destination: "198.51.100.61",
            destinationPort: 443,
            sni: "api.example.com",
            tlsVersion: "TLS 1.2",
            certIssuer: "CN=Let's Encrypt Authority X3",
            certSubject: "CN=www.example.com")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R143_matches_wildcard_certificate_on_sensitive_service()
    {
        var rule = new R143_WildcardCertificateOnSensitiveServiceRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.1.60",
            destination: "10.20.1.61",
            destinationPort: 5986,
            sni: "admin.example.com",
            tlsVersion: "TLS 1.2",
            certSubject: "CN=*.example.com")));

        var evt = AssertSingleEvent(result, "R143", SeverityLevel.Medium, 0.45);
        AssertEvidence(evt, "matched_conditions", "tls.certSubject", "network.destinationPort");
    }

    [Fact]
    public async Task R143_ignores_wildcard_certificate_on_standard_https()
    {
        var rule = new R143_WildcardCertificateOnSensitiveServiceRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.1.61",
            destination: "10.20.1.62",
            destinationPort: 443,
            sni: "www.example.com",
            tlsVersion: "TLS 1.2",
            certSubject: "CN=*.example.com")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R144_matches_long_validity_external_certificate()
    {
        var rule = new R144_CertificateValidityPeriodTooLongRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.1.70",
            destination: "198.51.100.70",
            destinationPort: 443,
            sni: "legacycert.example",
            tlsVersion: "TLS 1.2",
            certValidFrom: new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            certValidTo: new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc))));

        var evt = AssertSingleEvent(result, "R144", SeverityLevel.Medium, 0.45);
        AssertEvidence(evt, "matched_conditions", "tls.validityDays");
    }

    [Fact]
    public async Task R144_ignores_standard_validity_certificate()
    {
        var rule = new R144_CertificateValidityPeriodTooLongRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.1.71",
            destination: "198.51.100.71",
            destinationPort: 443,
            sni: "standard.example",
            tlsVersion: "TLS 1.3",
            certValidFrom: new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            certValidTo: new DateTime(2026, 12, 1, 0, 0, 0, DateTimeKind.Utc))));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R145_matches_short_lived_certificate_repetition()
    {
        var rule = new R145_ShortLivedCertificateWithNewSniRule();
        var baseTime = new DateTime(2026, 4, 30, 12, 10, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 3; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
                source: "10.20.1.80",
                destination: "198.51.100.80",
                destinationPort: 443,
                sni: "fast-rotate.example",
                tlsVersion: "TLS 1.2",
                ja4: "ja4-short-145",
                process: "agent.exe",
                certValidFrom: new DateTime(2026, 4, 30, 0, 0, 0, DateTimeKind.Utc),
                certValidTo: new DateTime(2026, 5, 10, 0, 0, 0, DateTimeKind.Utc)), baseTime.AddSeconds(index * 20)));
        }

        var evt = AssertSingleEvent(last!, "R145", SeverityLevel.Medium, 0.45);
        AssertEvidence(evt, "matched_conditions", "count", "tls.validityDays");
    }

    [Fact]
    public async Task R145_ignores_ninety_day_certificate()
    {
        var rule = new R145_ShortLivedCertificateWithNewSniRule();
        var baseTime = new DateTime(2026, 4, 30, 12, 15, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 3; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
                source: "10.20.1.81",
                destination: "198.51.100.81",
                destinationPort: 443,
                sni: "normal-letsencrypt.example",
                tlsVersion: "TLS 1.3",
                ja4: "ja4-normal-145",
                process: "agent.exe",
                certValidFrom: new DateTime(2026, 4, 1, 0, 0, 0, DateTimeKind.Utc),
                certValidTo: new DateTime(2026, 6, 30, 0, 0, 0, DateTimeKind.Utc)), baseTime.AddSeconds(index * 20)));
        }

        Assert.NotNull(last);
        Assert.False(last!.Matched);
    }

    [Fact]
    public async Task R146_matches_tls_handshake_failure_spike()
    {
        var rule = new R146_TlsHandshakeFailureSpikeRule();
        var baseTime = new DateTime(2026, 4, 30, 12, 20, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 12; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
                source: "10.20.1.90",
                destination: "198.51.100.90",
                destinationPort: 443,
                sni: "broken.example",
                tlsVersion: "TLS 1.2",
                info: "tls alert handshake failure"), baseTime.AddSeconds(index * 10)));
        }

        var evt = AssertSingleEvent(last!, "R146", SeverityLevel.Medium, 0.45);
        AssertEvidence(evt, "matched_conditions", "count");
    }

    [Fact]
    public async Task R146_ignores_single_handshake_failure()
    {
        var rule = new R146_TlsHandshakeFailureSpikeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.1.91",
            destination: "198.51.100.91",
            destinationPort: 443,
            sni: "broken.example",
            tlsVersion: "TLS 1.2",
            info: "tls alert handshake failure")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R147_matches_explicit_ech_indicator()
    {
        var rule = new R147_EncryptedClienthelloOrEchIndicatorRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.2.10",
            destination: "198.51.100.100",
            destinationPort: 443,
            sni: "privacy.example",
            tlsVersion: "TLS 1.3",
            info: "encrypted client hello negotiated")));

        var evt = AssertSingleEvent(result, "R147", SeverityLevel.Low, 0.25);
        AssertEvidence(evt, "matched_conditions");
    }

    [Fact]
    public async Task R147_ignores_ordinary_tls_traffic()
    {
        var rule = new R147_EncryptedClienthelloOrEchIndicatorRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.2.11",
            destination: "198.51.100.101",
            destinationPort: 443,
            sni: "privacy.example",
            tlsVersion: "TLS 1.3",
            info: "normal tls handshake")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R148_matches_tls_to_dynamic_dns_subdomain()
    {
        var rule = new R148_TlsToDynamicDnsHostRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.2.20",
            destination: "198.51.100.110",
            destinationPort: 443,
            sni: "beacon123.duckdns.org",
            tlsVersion: "TLS 1.2",
            process: "beacon.exe")));

        var evt = AssertSingleEvent(result, "R148", SeverityLevel.Medium, 0.45);
        AssertEvidence(evt, "matched_conditions", "tls.sni");
    }

    [Fact]
    public async Task R148_ignores_browser_to_provider_root()
    {
        var rule = new R148_TlsToDynamicDnsHostRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.2.21",
            destination: "198.51.100.111",
            destinationPort: 443,
            sni: "duckdns.org",
            tlsVersion: "TLS 1.3",
            process: "chrome.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R149_matches_ip_literal_sni()
    {
        var rule = new R149_IpLiteralUsedAsTlsNameRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.2.30",
            destination: "198.51.100.120",
            destinationPort: 443,
            sni: "203.0.113.77",
            tlsVersion: "TLS 1.2")));

        var evt = AssertSingleEvent(result, "R149", SeverityLevel.Medium, 0.45);
        AssertEvidence(evt, "matched_conditions", "tls.sni");
    }

    [Fact]
    public async Task R149_ignores_hostname_sni()
    {
        var rule = new R149_IpLiteralUsedAsTlsNameRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.2.31",
            destination: "198.51.100.121",
            destinationPort: 443,
            sni: "host.example.com",
            tlsVersion: "TLS 1.2")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R150_matches_malware_labeled_fingerprint()
    {
        var rule = new R150_KnownMalwareLikeTlsFingerprintLabelRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.2.40",
            destination: "198.51.100.130",
            destinationPort: 443,
            sni: "c2.example",
            tlsVersion: "TLS 1.2",
            ja3: "771,4865-4866-4867",
            info: "cobalt strike ja3 label from enrichment")));

        var evt = AssertSingleEvent(result, "R150", SeverityLevel.High, 0.75);
        AssertEvidence(evt, "matched_conditions", "tls.ja3");
    }

    [Fact]
    public async Task R150_ignores_label_text_without_fingerprint()
    {
        var rule = new R150_KnownMalwareLikeTlsFingerprintLabelRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.2.41",
            destination: "198.51.100.131",
            destinationPort: 443,
            sni: "c2.example",
            tlsVersion: "TLS 1.2",
            info: "cobalt strike ja3 label from enrichment")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R151_matches_non_browser_h2_on_uncommon_port()
    {
        var rule = new R151_Http2AlpnOnUncommonPortRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.2.50",
            destination: "198.51.100.140",
            destinationPort: 9443,
            sni: "api.example",
            tlsVersion: "TLS 1.3",
            alpn: "h2",
            process: "agent.exe")));

        var evt = AssertSingleEvent(result, "R151", SeverityLevel.Medium, 0.45);
        AssertEvidence(evt, "matched_conditions", "network.destinationPort");
    }

    [Fact]
    public async Task R151_ignores_browser_h2_on_uncommon_port()
    {
        var rule = new R151_Http2AlpnOnUncommonPortRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
            source: "10.20.2.51",
            destination: "198.51.100.141",
            destinationPort: 9443,
            sni: "api.example",
            tlsVersion: "TLS 1.3",
            alpn: "h2",
            process: "chrome.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R152_matches_fingerprint_fanout_to_many_asns()
    {
        var rule = new R152_TlsFingerprintFanOutToManyAsnsRule();
        var baseTime = new DateTime(2026, 4, 30, 12, 30, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        foreach (var (asn, offset) in new[] { ("AS100", 0), ("AS101", 20), ("AS102", 40), ("AS103", 60), ("AS104", 80) })
        {
            last = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
                source: "10.20.2.60",
                destination: "198.51.100.150",
                destinationPort: 443,
                sni: $"fanout-{asn}.example",
                tlsVersion: "TLS 1.2",
                ja4: "ja4-fanout-152",
                process: "beacon.exe",
                whoisAsn: asn), baseTime.AddSeconds(offset)));
        }

        var evt = AssertSingleEvent(last!, "R152", SeverityLevel.Medium, 0.45);
        AssertEvidence(evt, "matched_conditions", "count", "whois.asn");
    }

    [Fact]
    public async Task R152_ignores_browser_fanout()
    {
        var rule = new R152_TlsFingerprintFanOutToManyAsnsRule();
        var baseTime = new DateTime(2026, 4, 30, 12, 35, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        foreach (var (asn, offset) in new[] { ("AS200", 0), ("AS201", 20), ("AS202", 40), ("AS203", 60), ("AS204", 80) })
        {
            last = await rule.EvaluateAsync(CreateContext(CreateTlsRecord(
                source: "10.20.2.61",
                destination: "198.51.100.151",
                destinationPort: 443,
                sni: $"browser-{asn}.example",
                tlsVersion: "TLS 1.3",
                ja4: "ja4-browser-152",
                process: "msedge.exe",
                whoisAsn: asn), baseTime.AddSeconds(offset)));
        }

        Assert.NotNull(last);
        Assert.False(last!.Matched);
    }

    [Fact]
    public void Migrated_tls_rules_register_rule_owned_precision_profiles()
    {
        _ = new R138_SelfSignedCertificateToExternalHostRule();
        _ = new R139_WeakTlsVersionObservedRule();
        _ = new R145_ShortLivedCertificateWithNewSniRule();
        _ = new R150_KnownMalwareLikeTlsFingerprintLabelRule();
        _ = new R152_TlsFingerprintFanOutToManyAsnsRule();

        var r138 = RulePrecisionCatalog.GetProfile("R138", "TlsPki", SeverityLevel.Medium);
        var r139 = RulePrecisionCatalog.GetProfile("R139", "TlsPki", SeverityLevel.High);
        var r145 = RulePrecisionCatalog.GetProfile("R145", "TlsPki", SeverityLevel.Medium);
        var r150 = RulePrecisionCatalog.GetProfile("R150", "TlsPki", SeverityLevel.High);
        var r152 = RulePrecisionCatalog.GetProfile("R152", "TlsPki", SeverityLevel.Medium);

        Assert.Contains(RuleTelemetryKind.Tls, r138.RequiredTelemetry);
        Assert.Equal(RuleRuntimeMode.Alert, r139.DefaultMode);
        Assert.Equal(3, r145.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, r150.DefaultMode);
        Assert.Equal(TimeSpan.FromMinutes(15), r152.Window);
    }

    private static RuleEvaluationContext CreateContext(TrafficRecord record, DateTime? timestampUtc = null)
        => new(record, Sensitivity.Balanced, timestampUtc ?? new DateTime(2026, 4, 30, 11, 0, 0, DateTimeKind.Utc));

    private static TrafficRecord CreateTlsRecord(
        string source,
        string destination,
        int destinationPort,
        string? sni = null,
        string? tlsVersion = null,
        string? alpn = null,
        string? info = null,
        string? process = null,
        string? certIssuer = null,
        string? certSubject = null,
        DateTime? certValidFrom = null,
        DateTime? certValidTo = null,
        string? ja3 = null,
        string? ja4 = null,
        string? whoisAsn = null)
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
            Alpn = alpn,
            Info = info,
            ProcessName = process,
            CertIssuer = certIssuer,
            CertSubject = certSubject,
            CertValidFrom = certValidFrom,
            CertValidTo = certValidTo,
            Ja3 = ja3,
            Ja4 = ja4,
            WhoisASN = whoisAsn,
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
}
