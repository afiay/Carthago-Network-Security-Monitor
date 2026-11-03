// SPDX-License-Identifier: MIT
// R275 selector-safe trusted runtime resolver tests.
// SOURCE CANDIDATE — UNVERIFIED. Default runtime remains resolver-free.
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Health;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.TrustedAudit;
using Xunit;

namespace Carthago.Tests;

public sealed class R275TrustedRuntimeResolverTests
{
    private static TrafficRecord TlsOnlyFlow() => new()
    {
        Source = "203.0.113.25",
        Destination = "20.190.128.10",
        SourcePort = 53000,
        DestinationPort = 443,
        Protocol = "TCP",
        ApplicationProtocol = "TLS",
        IsTcp = true,
        Sni = "login.microsoftonline.com"
    };

    private sealed class ValidResolver : IOAuthDeviceFlowTrustedRuntimeContextResolver
    {
        public bool TryResolve(
            TrafficRecord record,
            Sensitivity sensitivity,
            DateTime timestampUtc,
            RuleEngineHealthSnapshot healthSnapshot,
            out RuleEvaluationContext? context,
            out string reason)
        {
            var occurredAt = new DateTimeOffset(timestampUtc, TimeSpan.Zero);
            var trace = Convert.ToHexString(
                    SHA256.HashData(Guid.NewGuid().ToByteArray()))
                .ToLowerInvariant();

            using var firstKey = RSA.Create(2048);
            using var secondKey = RSA.Create(2048);
            var verifier = new TrustedAuditReceiptVerifier(new[]
            {
                new TrustedAuditIssuer(
                    "idp-primary",
                    Convert.ToBase64String(firstKey.ExportSubjectPublicKeyInfo()),
                    new[] { "R275" }),
                new TrustedAuditIssuer(
                    "idp-secondary",
                    Convert.ToBase64String(secondKey.ExportSubjectPublicKeyInfo()),
                    new[] { "R275" })
            }, () => occurredAt);

            AuditClaim Claim(string issuer) => new()
            {
                IssuerId = issuer,
                RuleId = "R275",
                EvidenceId = Guid.NewGuid(),
                OccurredAtUtc = occurredAt,
                Operation = "OAuthDeviceFlowAbuseConfirmed",
                SourceIp = record.Source!,
                DestinationIp = record.Destination!,
                ActorHash = new string('a', 64),
                ResourceHash = new string('b', 64),
                TraceHash = trace
            };

            static SignedAuditEnvelope Sign(RSA key, AuditClaim claim)
            {
                var payload = JsonSerializer.SerializeToUtf8Bytes(claim);
                var signature = key.SignData(
                    TrustedAuditReceiptVerifier.SigningBytes(payload),
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss);
                return new SignedAuditEnvelope(
                    claim.IssuerId,
                    Convert.ToBase64String(payload),
                    Convert.ToBase64String(signature));
            }

            if (!verifier.TryVerify(
                    Sign(firstKey, Claim("idp-primary")),
                    out var firstReceipt,
                    out reason)
                || !verifier.TryVerify(
                    Sign(secondKey, Claim("idp-secondary")),
                    out var secondReceipt,
                    out reason)
                || !TrustedAuditReceiptCorrelation.TryCorrelate(
                    firstReceipt,
                    secondReceipt,
                    out var pair,
                    out reason)
                || !OAuthDeviceFlowRuleCapability.TryCreate(
                    pair,
                    record,
                    occurredAt,
                    out var capability,
                    out reason)
                || capability == null
                || !OAuthDeviceFlowPromotionAuthorization.TryAuthorize(
                    new OAuthDeviceFlowPromotionPolicyOptions
                    {
                        Enabled = true,
                        ApprovedIssuerIds = new[] { "idp-primary", "idp-secondary" },
                        ApprovedIdentityHosts = new[] { "login.microsoftonline.com" }
                    },
                    capability,
                    record,
                    timestampUtc,
                    out var authorization,
                    out reason)
                || authorization == null)
            {
                context = null;
                return false;
            }

            context = new RuleEvaluationContext(
                record,
                sensitivity,
                timestampUtc,
                healthSnapshot,
                capability,
                authorization);
            reason = "VALID_TEST_RESOLVER_CONTEXT";
            return true;
        }
    }

    private sealed class InvalidPublicContextResolver
        : IOAuthDeviceFlowTrustedRuntimeContextResolver
    {
        public bool TryResolve(
            TrafficRecord record,
            Sensitivity sensitivity,
            DateTime timestampUtc,
            RuleEngineHealthSnapshot healthSnapshot,
            out RuleEvaluationContext? context,
            out string reason)
        {
            context = new RuleEvaluationContext(
                record, sensitivity, timestampUtc, healthSnapshot);
            reason = "UNTRUSTED_PUBLIC_CONTEXT";
            return true;
        }
    }

    private sealed class ThrowingResolver
        : IOAuthDeviceFlowTrustedRuntimeContextResolver
    {
        public bool TryResolve(
            TrafficRecord record,
            Sensitivity sensitivity,
            DateTime timestampUtc,
            RuleEngineHealthSnapshot healthSnapshot,
            out RuleEvaluationContext? context,
            out string reason)
        {
            context = null;
            reason = string.Empty;
            throw new InvalidOperationException("synthetic resolver failure");
        }
    }

    [Fact]
    public void Default_Runtime_Does_Not_Bypass_Http_Selector_For_Tls_Only_R275()
    {
        var flow = TlsOnlyFlow();

        var events = RuleEngine.Evaluate(flow, Sensitivity.Balanced);

        Assert.DoesNotContain(events, evt => evt.RuleId == "R275");
        var trace = Assert.IsType<RuleEvaluationTrace>(RuleEngine.LastEvaluationTrace);
        Assert.Contains("R275", trace.SelectorSkippedRuleIds);
        Assert.DoesNotContain("R275", trace.MatchedRuleIds);
        Assert.Contains(
            "HTTP telemetry not present",
            trace.SelectorReasonsByRuleId["R275"],
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Valid_Internal_Resolver_Can_Narrowly_Bypass_Selector_And_Telemetry_For_R275()
    {
        var flow = TlsOnlyFlow();

        using (RuleEngine.PushR275TrustedRuntimeResolver(new ValidResolver()))
        {
            var events = RuleEngine.Evaluate(flow, Sensitivity.Balanced);

            var r275 = Assert.Single(events.Where(evt => evt.RuleId == "R275"));
            Assert.Equal(SeverityLevel.High, r275.Severity);
            Assert.True(r275.ConfidenceScore >= 0.78);

            var trace = Assert.IsType<RuleEvaluationTrace>(RuleEngine.LastEvaluationTrace);
            Assert.Contains("R275", trace.SelectedRuleIds);
            Assert.Contains("R275", trace.EvaluatedRuleIds);
            Assert.Contains("R275", trace.MatchedRuleIds);
            Assert.DoesNotContain("R275", trace.SelectorSkippedRuleIds);
            Assert.Equal(
                "R275_TRUSTED_RUNTIME_CONTEXT_READY",
                trace.SelectorReasonsByRuleId["R275"]);
        }
    }

    [Fact]
    public void Public_Packet_Context_Cannot_Masquerade_As_Trusted_Runtime_Context()
    {
        var flow = TlsOnlyFlow();

        using (RuleEngine.PushR275TrustedRuntimeResolver(
            new InvalidPublicContextResolver()))
        {
            var events = RuleEngine.Evaluate(flow, Sensitivity.Balanced);

            Assert.DoesNotContain(events, evt => evt.RuleId == "R275");
            var trace = Assert.IsType<RuleEvaluationTrace>(RuleEngine.LastEvaluationTrace);
            Assert.Contains("R275", trace.SelectorSkippedRuleIds);
            Assert.DoesNotContain("R275", trace.MatchedRuleIds);
        }
    }

    [Fact]
    public void Resolver_Exception_Fails_Closed_And_Does_Not_Interrupt_Engine()
    {
        var flow = TlsOnlyFlow();

        using (RuleEngine.PushR275TrustedRuntimeResolver(new ThrowingResolver()))
        {
            var events = RuleEngine.Evaluate(flow, Sensitivity.Balanced);

            Assert.DoesNotContain(events, evt => evt.RuleId == "R275");
            var trace = Assert.IsType<RuleEvaluationTrace>(RuleEngine.LastEvaluationTrace);
            Assert.Contains("R275", trace.SelectorSkippedRuleIds);
            Assert.DoesNotContain("R275", trace.FailedRuleIds);
        }
    }

    [Fact]
    public void Resolver_Scope_Restores_Default_Null_Runtime_State()
    {
        var flow = TlsOnlyFlow();

        using (RuleEngine.PushR275TrustedRuntimeResolver(new ValidResolver()))
        {
            var enabled = RuleEngine.Evaluate(flow, Sensitivity.Balanced);
            Assert.Contains(enabled, evt => evt.RuleId == "R275");
        }

        var afterScope = RuleEngine.Evaluate(TlsOnlyFlow(), Sensitivity.Balanced);
        Assert.DoesNotContain(afterScope, evt => evt.RuleId == "R275");
        var trace = Assert.IsType<RuleEvaluationTrace>(RuleEngine.LastEvaluationTrace);
        Assert.Contains("R275", trace.SelectorSkippedRuleIds);
    }

    [Fact]
    public void R275_Profile_Remains_Http_Gated_For_Normal_Packet_Selection()
    {
        var profile = new R275_OAuthDeviceCodePhishingIndicatorRule()
            .PrecisionProfile;

        Assert.Contains(RuleTelemetryKind.Http, profile.RequiredTelemetry);
        Assert.DoesNotContain(RuleTelemetryKind.Tls, profile.RequiredTelemetry);
    }
}
