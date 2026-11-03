// SPDX-License-Identifier: MIT
// R275 explicit promotion policy tests.
// SOURCE CANDIDATE — UNVERIFIED. Production runtime remains unwired.
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services.TrustedAudit;
using Xunit;

namespace Carthago.Tests;

public sealed class R275PromotionPolicyTests
{
    private static readonly DateTimeOffset BaseTime =
        new(2026, 11, 3, 20, 0, 0, TimeSpan.Zero);

    private static TrafficRecord Flow(string host = "login.microsoftonline.com")
        => new()
        {
            Source = "203.0.113.25",
            Destination = "20.190.128.10",
            SourcePort = 53000,
            DestinationPort = 443,
            Protocol = "TCP",
            ApplicationProtocol = "TLS",
            IsTcp = true,
            Sni = host
        };

    private static string Hash(Guid value)
        => Convert.ToHexString(SHA256.HashData(value.ToByteArray()))
            .ToLowerInvariant();

    private static SignedAuditEnvelope Sign(RSA key, AuditClaim claim)
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

    private static CorrelatedAuditReceipts Pair(
        TrafficRecord flow,
        DateTimeOffset occurredAt,
        string traceHash)
    {
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
            SourceIp = flow.Source!,
            DestinationIp = flow.Destination!,
            ActorHash = new string('a', 64),
            ResourceHash = new string('b', 64),
            TraceHash = traceHash
        };

        Assert.True(verifier.TryVerify(
            Sign(firstKey, Claim("idp-primary")),
            out var firstReceipt, out var firstReason), firstReason);
        Assert.True(verifier.TryVerify(
            Sign(secondKey, Claim("idp-secondary")),
            out var secondReceipt, out var secondReason), secondReason);

        Assert.True(TrustedAuditReceiptCorrelation.TryCorrelate(
            firstReceipt, secondReceipt, out var pair, out var pairReason),
            pairReason);

        return Assert.IsType<CorrelatedAuditReceipts>(pair);
    }

    private static OAuthDeviceFlowRuleCapability Capability(
        TrafficRecord flow,
        DateTimeOffset occurredAt,
        string traceHash)
    {
        Assert.True(OAuthDeviceFlowRuleCapability.TryCreate(
            Pair(flow, occurredAt, traceHash),
            flow,
            occurredAt,
            out var capability,
            out var reason), reason);
        return Assert.IsType<OAuthDeviceFlowRuleCapability>(capability);
    }

    private static OAuthDeviceFlowPromotionPolicyOptions EnabledPolicy(
        params string[] hosts)
        => new()
        {
            Enabled = true,
            ApprovedIssuerIds = new[] { "idp-primary", "idp-secondary" },
            ApprovedIdentityHosts = hosts.Length == 0
                ? new[] { "login.microsoftonline.com" }
                : hosts
        };

    private static OAuthDeviceFlowPromotionAuthorization Authorization(
        OAuthDeviceFlowRuleCapability capability,
        TrafficRecord flow,
        DateTimeOffset occurredAt,
        OAuthDeviceFlowPromotionPolicyOptions? options = null)
    {
        Assert.True(OAuthDeviceFlowPromotionAuthorization.TryAuthorize(
            options ?? EnabledPolicy(),
            capability,
            flow,
            occurredAt.UtcDateTime,
            out var authorization,
            out var reason), reason);
        Assert.Equal("R275_PROMOTION_AUTHORIZATION_READY", reason);
        return Assert.IsType<OAuthDeviceFlowPromotionAuthorization>(authorization);
    }

    [Fact]
    public void Promotion_Is_Default_Deny_Even_With_Valid_Trusted_Capability()
    {
        var flow = Flow();
        var capability = Capability(flow, BaseTime, Hash(Guid.NewGuid()));

        Assert.False(OAuthDeviceFlowPromotionAuthorization.TryAuthorize(
            new OAuthDeviceFlowPromotionPolicyOptions(),
            capability,
            flow,
            BaseTime.UtcDateTime,
            out var authorization,
            out var reason));

        Assert.Null(authorization);
        Assert.Equal("R275_PROMOTION_POLICY_DISABLED", reason);
    }

    [Fact]
    public void Both_Independent_Issuers_Must_Be_Operator_Approved()
    {
        var flow = Flow();
        var capability = Capability(flow, BaseTime, Hash(Guid.NewGuid()));
        var policy = new OAuthDeviceFlowPromotionPolicyOptions
        {
            Enabled = true,
            ApprovedIssuerIds = new[] { "idp-primary" },
            ApprovedIdentityHosts = new[] { "login.microsoftonline.com" }
        };

        Assert.False(OAuthDeviceFlowPromotionAuthorization.TryAuthorize(
            policy, capability, flow, BaseTime.UtcDateTime,
            out var authorization, out var reason));

        Assert.Null(authorization);
        Assert.Equal("R275_PROMOTION_ISSUER_POLICY_REJECTED", reason);
    }

    [Fact]
    public void Signed_Receipts_For_Lookalike_Host_Cannot_Be_Promoted()
    {
        var flow = Flow("login.microsoftonline.com.attacker.test");
        var capability = Capability(flow, BaseTime, Hash(Guid.NewGuid()));

        Assert.False(OAuthDeviceFlowPromotionAuthorization.TryAuthorize(
            EnabledPolicy("login.microsoftonline.com"),
            capability,
            flow,
            BaseTime.UtcDateTime,
            out var authorization,
            out var reason));

        Assert.Null(authorization);
        Assert.Equal("R275_PROMOTION_IDENTITY_HOST_REJECTED", reason);
    }

    [Fact]
    public void Authorization_Is_Bound_To_Exact_Capability_Record_And_Time()
    {
        var flow = Flow();
        var trace = Hash(Guid.NewGuid());
        var capability = Capability(flow, BaseTime, trace);
        var authorization = Authorization(capability, flow, BaseTime);

        var differentFlow = Flow();
        var differentCapability = Capability(
            differentFlow, BaseTime, Hash(Guid.NewGuid()));

        Assert.False(authorization.IsBoundTo(
            differentCapability, differentFlow, BaseTime.UtcDateTime));
        Assert.False(authorization.IsBoundTo(
            capability, flow, BaseTime.AddSeconds(1).UtcDateTime));
    }

    [Fact]
    public async Task Explicitly_Authorized_Capability_Produces_Privacy_Minimized_High_Confidence_Event()
    {
        var flow = Flow();
        var trace = Hash(Guid.NewGuid());
        var capability = Capability(flow, BaseTime, trace);
        var authorization = Authorization(capability, flow, BaseTime);

        var context = new RuleEvaluationContext(
            flow,
            Sensitivity.Balanced,
            BaseTime.UtcDateTime,
            healthSnapshot: null,
            trustedR275Capability: capability,
            trustedR275PromotionAuthorization: authorization);

        var result = await new R275_OAuthDeviceCodePhishingIndicatorRule()
            .EvaluateAsync(context);

        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R275", evt.RuleId);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.Equal(DetectionSuppressionStatus.None, evt.SuppressionStatus);
        Assert.True(evt.ConfidenceScore >= 0.78);
        Assert.Equal(DetectionConfidenceLabel.High, evt.ConfidenceLabel);

        var evidence = evt.Evidence ?? string.Empty;
        Assert.Contains(
            "identity.signal=admin-confirmed-device-code-compromise",
            evidence,
            StringComparison.Ordinal);
        Assert.Contains(
            "identity.audit.independentIssuers=2",
            evidence,
            StringComparison.Ordinal);
        Assert.Contains(
            "identity.promotionPolicy=r275-promotion-v1",
            evidence,
            StringComparison.Ordinal);

        Assert.DoesNotContain(trace, evidence, StringComparison.Ordinal);
        Assert.DoesNotContain("idp-primary", evidence, StringComparison.Ordinal);
        Assert.DoesNotContain("idp-secondary", evidence, StringComparison.Ordinal);
        Assert.DoesNotContain(new string('a', 64), evidence, StringComparison.Ordinal);
        Assert.DoesNotContain(new string('b', 64), evidence, StringComparison.Ordinal);
        Assert.DoesNotContain("user_code", evidence, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("device_code", evidence, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Trusted_Capability_Without_Promotion_Authorization_Remains_NoMatch()
    {
        var flow = Flow();
        var capability = Capability(flow, BaseTime, Hash(Guid.NewGuid()));

        var context = new RuleEvaluationContext(
            flow,
            Sensitivity.Balanced,
            BaseTime.UtcDateTime,
            healthSnapshot: null,
            trustedR275Capability: capability);

        var result = await new R275_OAuthDeviceCodePhishingIndicatorRule()
            .EvaluateAsync(context);

        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        Assert.Equal(
            "TRUSTED_DEVICE_CODE_CAPABILITY_PRESENT_NOT_PROMOTED",
            Assert.Single(result.NoMatchReasons).Code);
    }

    [Fact]
    public async Task Same_Trusted_Trace_Is_Suppressed_Inside_Profile_Cooldown()
    {
        var trace = Hash(Guid.NewGuid());

        var firstFlow = Flow();
        var firstCapability = Capability(firstFlow, BaseTime, trace);
        var firstAuthorization = Authorization(
            firstCapability, firstFlow, BaseTime);
        var firstContext = new RuleEvaluationContext(
            firstFlow,
            Sensitivity.Balanced,
            BaseTime.UtcDateTime,
            null,
            firstCapability,
            firstAuthorization);

        var first = await new R275_OAuthDeviceCodePhishingIndicatorRule()
            .EvaluateAsync(firstContext);
        Assert.True(first.Matched);
        Assert.Equal(
            DetectionSuppressionStatus.None,
            Assert.Single(first.Events).SuppressionStatus);

        var secondTime = BaseTime.AddMinutes(1);
        var secondFlow = Flow();
        var secondCapability = Capability(secondFlow, secondTime, trace);
        var secondAuthorization = Authorization(
            secondCapability, secondFlow, secondTime);
        var secondContext = new RuleEvaluationContext(
            secondFlow,
            Sensitivity.Balanced,
            secondTime.UtcDateTime,
            null,
            secondCapability,
            secondAuthorization);

        var second = await new R275_OAuthDeviceCodePhishingIndicatorRule()
            .EvaluateAsync(secondContext);
        Assert.True(second.Matched);
        var secondEvent = Assert.Single(second.Events);
        Assert.Equal(
            DetectionSuppressionStatus.Suppressed,
            secondEvent.SuppressionStatus);
        Assert.Contains(
            "suppression.remainingSeconds",
            secondEvent.Evidence ?? string.Empty,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Promotion_Authorization_Surface_Is_Internal_And_Not_Public_Context_API()
    {
        Assert.False(typeof(OAuthDeviceFlowPromotionAuthorization).IsPublic);

        var publicConstructors = typeof(RuleEvaluationContext).GetConstructors();
        Assert.Single(publicConstructors);
        Assert.DoesNotContain(
            publicConstructors[0].GetParameters(),
            parameter => parameter.ParameterType
                == typeof(OAuthDeviceFlowPromotionAuthorization));

        var publicProperties = typeof(RuleEvaluationContext)
            .GetProperties()
            .Select(property => property.Name)
            .ToArray();
        Assert.DoesNotContain("TrustedR275PromotionAuthorization", publicProperties);
    }
}
