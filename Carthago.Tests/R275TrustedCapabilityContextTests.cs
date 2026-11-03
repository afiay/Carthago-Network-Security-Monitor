// SPDX-License-Identifier: MIT
// R275 internal trusted-capability delivery tests.
// SOURCE CANDIDATE — UNVERIFIED. Capability remains non-alerting.
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

public sealed class R275TrustedCapabilityContextTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 3, 20, 0, 0, TimeSpan.Zero);

    private static TrafficRecord Flow() => new()
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

    private static MicrosoftEntraDeviceCodeAuditObservation Observation()
        => new(
            Now,
            "203.0.113.25",
            new string('a', 64),
            new string('b', 64),
            new string('c', 64),
            fromTrustedProviderTransport: true);

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

    private static CorrelatedAuditReceipts Pair(TrafficRecord flow)
    {
        var builder = new MicrosoftEntraDeviceFlowClaimMaterialBuilder(
            new[] { "login.microsoftonline.com" });
        Assert.True(builder.TryBuild(
            Observation(), flow, Now,
            out var material, out var materialReason), materialReason);
        Assert.NotNull(material);

        Assert.True(OAuthDeviceFlowExternalSigningRequest.TryCreate(
            material, out var request, out var requestReason), requestReason);
        Assert.NotNull(request);

        Assert.True(request.TryCreateUnsignedAuditClaim(
            "idp-primary", Guid.NewGuid(),
            out var firstClaim, out var firstClaimReason), firstClaimReason);
        Assert.True(request.TryCreateUnsignedAuditClaim(
            "idp-secondary", Guid.NewGuid(),
            out var secondClaim, out var secondClaimReason), secondClaimReason);

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
        }, () => Now);

        Assert.True(verifier.TryVerify(
            Sign(firstKey, firstClaim!), out var firstReceipt, out var firstReason),
            firstReason);
        Assert.True(verifier.TryVerify(
            Sign(secondKey, secondClaim!), out var secondReceipt, out var secondReason),
            secondReason);
        Assert.True(TrustedAuditReceiptCorrelation.TryCorrelate(
            firstReceipt, secondReceipt,
            out var pair, out var pairReason), pairReason);

        return Assert.IsType<CorrelatedAuditReceipts>(pair);
    }

    private static OAuthDeviceFlowRuleCapability Capability(TrafficRecord flow)
    {
        Assert.True(OAuthDeviceFlowRuleCapability.TryCreate(
            Pair(flow), flow, Now,
            out var capability, out var reason), reason);
        Assert.Equal("R275_RULE_CAPABILITY_READY_NONALERTING", reason);
        return Assert.IsType<OAuthDeviceFlowRuleCapability>(capability);
    }

    [Fact]
    public async Task Public_Context_Remains_Packet_Only_With_Original_FailClosed_Reason()
    {
        var flow = Flow();
        var context = new RuleEvaluationContext(
            flow, Sensitivity.Balanced, Now.UtcDateTime);

        var result = await new R275_OAuthDeviceCodePhishingIndicatorRule()
            .EvaluateAsync(context);

        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        var reason = Assert.Single(result.NoMatchReasons);
        Assert.Equal("TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE", reason.Code);
        Assert.Equal(RuleNoMatchReasonCategory.InsufficientEvidence, reason.Category);
    }

    [Fact]
    public async Task Internal_Bound_Capability_Reaches_R275_But_Remains_Nonalerting()
    {
        var flow = Flow();
        var capability = Capability(flow);
        var context = new RuleEvaluationContext(
            flow, Sensitivity.Balanced, Now.UtcDateTime,
            healthSnapshot: null, trustedR275Capability: capability);

        var result = await new R275_OAuthDeviceCodePhishingIndicatorRule()
            .EvaluateAsync(context);

        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        var reason = Assert.Single(result.NoMatchReasons);
        Assert.Equal(
            "TRUSTED_DEVICE_CODE_CAPABILITY_PRESENT_NOT_PROMOTED",
            reason.Code);
        Assert.Equal(RuleNoMatchReasonCategory.RuntimePrecisionGate, reason.Category);
    }

    [Fact]
    public void Capability_Cannot_Be_Attached_To_A_Different_Record_Instance()
    {
        var original = Flow();
        var capability = Capability(original);
        var different = Flow();

        Assert.Throws<ArgumentException>(() =>
            new RuleEvaluationContext(
                different, Sensitivity.Balanced, Now.UtcDateTime,
                healthSnapshot: null, trustedR275Capability: capability));
    }

    [Fact]
    public void Capability_Cannot_Be_Reused_After_Bound_Record_Mutation()
    {
        var flow = Flow();
        var capability = Capability(flow);
        flow.Destination = "20.190.128.11";

        Assert.Throws<ArgumentException>(() =>
            new RuleEvaluationContext(
                flow, Sensitivity.Balanced, Now.UtcDateTime,
                healthSnapshot: null, trustedR275Capability: capability));
    }

    [Fact]
    public void Capability_Cannot_Be_Reused_At_A_Different_Context_Timestamp()
    {
        var flow = Flow();
        var capability = Capability(flow);

        Assert.Throws<ArgumentException>(() =>
            new RuleEvaluationContext(
                flow, Sensitivity.Balanced, Now.AddSeconds(1).UtcDateTime,
                healthSnapshot: null, trustedR275Capability: capability));
    }

    [Fact]
    public void Missing_Or_Uncorroborated_Receipts_Cannot_Mint_Capability()
    {
        var flow = Flow();

        Assert.False(OAuthDeviceFlowRuleCapability.TryCreate(
            null, flow, Now,
            out var capability, out var reason));

        Assert.Null(capability);
        Assert.Equal("R275_VERIFIED_IDP_AUDIT_PAIR_UNAVAILABLE", reason);
    }

    [Fact]
    public void Trusted_Capability_Surface_Is_Not_Public()
    {
        Assert.False(typeof(OAuthDeviceFlowRuleCapability).IsPublic);

        var publicConstructors = typeof(RuleEvaluationContext).GetConstructors();
        Assert.Single(publicConstructors);
        Assert.DoesNotContain(
            publicConstructors[0].GetParameters(),
            parameter => parameter.ParameterType
                == typeof(OAuthDeviceFlowRuleCapability));

        var publicProperties = typeof(RuleEvaluationContext)
            .GetProperties()
            .Select(property => property.Name)
            .ToArray();
        Assert.DoesNotContain("TrustedR275Capability", publicProperties);
    }
}
