// SPDX-License-Identifier: MIT
// R275 selector-safe trusted runtime resolver tests.
// SOURCE CANDIDATE — UNVERIFIED. Default runtime remains resolver-free.
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Health;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.TrustedAudit;
using Xunit;

namespace Carthago.Tests;

[CollectionDefinition("R275 RuleEngine runtime serial", DisableParallelization = true)]
public sealed class R275RuleEngineRuntimeSerialCollection
{
}

[Collection("R275 RuleEngine runtime serial")]
public sealed class R275TrustedRuntimeResolverTests
{
    private sealed class TempJournalScope : IDisposable
    {
        private readonly string _directory;
        private readonly IDisposable _scope;
        private int _disposed;

        public TempJournalScope()
        {
            _directory = Path.Combine(
                Path.GetTempPath(),
                "carthago-r275-runtime-" + Guid.NewGuid().ToString("N"));
            var journal = new DetectionJournal(new DetectionJournalOptions
            {
                DirectoryPath = _directory,
                FlushAfterEveryWrite = true,
                CreateDirectoryIfMissing = true
            });
            _scope = RuleEngine.PushDetectionJournalForTests(journal);
        }

        public void Dispose()
        {
            if (System.Threading.Interlocked.Exchange(ref _disposed, 1) != 0)
                return;

            _scope.Dispose();
            try
            {
                if (Directory.Exists(_directory))
                    Directory.Delete(_directory, recursive: true);
            }
            catch
            {
                // Best-effort cleanup only; the test's trust result does not
                // depend on temporary-file deletion.
            }
        }
    }

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
        using var journal = new TempJournalScope();
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
        using var journal = new TempJournalScope();
        var flow = TlsOnlyFlow();

        using (RuleEngine.PushR275TrustedRuntimeResolver(new ValidResolver()))
        {
            RuleEngine.Evaluate(flow, Sensitivity.Balanced);

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
        using var journal = new TempJournalScope();
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
        using var journal = new TempJournalScope();
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
        using var journal = new TempJournalScope();
        var flow = TlsOnlyFlow();

        using (RuleEngine.PushR275TrustedRuntimeResolver(new ValidResolver()))
        {
            RuleEngine.Evaluate(flow, Sensitivity.Balanced);
            var enabledTrace = Assert.IsType<RuleEvaluationTrace>(
                RuleEngine.LastEvaluationTrace);
            Assert.Contains("R275", enabledTrace.MatchedRuleIds);
        }

        var afterScope = RuleEngine.Evaluate(TlsOnlyFlow(), Sensitivity.Balanced);
        Assert.DoesNotContain(afterScope, evt => evt.RuleId == "R275");
        var trace = Assert.IsType<RuleEvaluationTrace>(RuleEngine.LastEvaluationTrace);
        Assert.Contains("R275", trace.SelectorSkippedRuleIds);
    }

    [Fact]
    public void Trusted_Precision_Path_Overrides_Only_R275_Raw_Http_Telemetry_Check()
    {
        var flow = TlsOnlyFlow();
        var rule = new R275_OAuthDeviceCodePhishingIndicatorRule();
        var evt = new DetectionEvent
        {
            RuleId = "R275",
            RuleName = rule.Descriptor.Name,
            TimestampUtc = DateTime.UtcNow,
            Severity = SeverityLevel.High,
            SourceIp = flow.Source,
            DestinationIp = flow.Destination,
            DestinationPort = flow.DestinationPort,
            Protocol = "TLS",
            ConfidenceScore = 0.95,
            ConfidenceLabel = DetectionConfidenceLabel.High,
            StructuredEvidence = new DetectionEvidenceSet(
                new[]
                {
                    new DetectionEvidenceItem(
                        "identity.signal",
                        "admin-confirmed-device-code-compromise",
                        "trusted-idp-audit"),
                    new DetectionEvidenceItem(
                        "identity.audit.independentIssuers",
                        "2",
                        "trusted-idp-audit"),
                    new DetectionEvidenceItem(
                        "identity.networkBinding",
                        "exact-flow-and-time",
                        "trusted-idp-audit")
                },
                "trusted R275 promotion candidate")
        };

        var normal = RulePrecisionRuntimeEvaluator.Evaluate(
            rule.Descriptor,
            evt,
            flow,
            RuleMode.Alert,
            "SmallBusiness");

        var trusted = RulePrecisionRuntimeEvaluator.EvaluateTrustedR275(
            rule.Descriptor,
            evt,
            flow,
            RuleMode.Alert,
            "SmallBusiness");

        Assert.False(normal.TelemetrySatisfied);
        Assert.NotEmpty(normal.MissingTelemetry);
        Assert.True(trusted.TelemetrySatisfied);
        Assert.Empty(trusted.MissingTelemetry);
        Assert.Empty(trusted.MissingFields);
        Assert.Contains(
            trusted.Reasons,
            reason => reason.Contains(
                "trusted runtime capability",
                StringComparison.OrdinalIgnoreCase));
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
