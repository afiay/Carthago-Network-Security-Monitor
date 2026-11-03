// SPDX-License-Identifier: MIT
// R275 external signer handoff tests. SOURCE CANDIDATE — UNVERIFIED.
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using Carthago.Models;
using Carthago.Services.TrustedAudit;
using Xunit;

namespace Carthago.Tests;

public sealed class OAuthDeviceFlowExternalSigningRequestTests
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

    private static OAuthDeviceFlowExternalSigningRequest Request()
    {
        var builder = new MicrosoftEntraDeviceFlowClaimMaterialBuilder(
            new[] { "login.microsoftonline.com" });
        Assert.True(builder.TryBuild(
            Observation(), Flow(), Now,
            out var material, out var materialReason), materialReason);
        Assert.NotNull(material);

        Assert.True(OAuthDeviceFlowExternalSigningRequest.TryCreate(
            material, out var request, out var requestReason), requestReason);
        return Assert.IsType<OAuthDeviceFlowExternalSigningRequest>(request);
    }

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

    [Fact]
    public void Signing_Request_Is_Fixed_R275_Metadata_Without_Key_Or_Alert_Surface()
    {
        var request = Request();

        Assert.Equal(1, request.SchemaVersion);
        Assert.Equal("R275", request.RuleId);
        Assert.Equal("OAuthDeviceFlowAbuseConfirmed", request.Operation);
        Assert.Equal("203.0.113.25", request.SourceIp);
        Assert.Equal("20.190.128.10", request.DestinationIp);
        Assert.Equal("login.microsoftonline.com", request.IdentityHost);

        var names = typeof(OAuthDeviceFlowExternalSigningRequest)
            .GetProperties().Select(property => property.Name).ToArray();
        Assert.DoesNotContain("PrivateKey", names);
        Assert.DoesNotContain("Signature", names);
        Assert.DoesNotContain("AlertPermitted", names);
    }

    [Fact]
    public void External_Signer_Can_Create_Only_Fixed_R275_Unsigned_Claim()
    {
        var request = Request();
        var evidenceId = Guid.NewGuid();

        Assert.True(request.TryCreateUnsignedAuditClaim(
            "idp-primary", evidenceId,
            out var claim, out var reason), reason);

        Assert.NotNull(claim);
        Assert.Equal("R275_AUDIT_CLAIM_READY_FOR_EXTERNAL_SIGNATURE", reason);
        Assert.Equal("idp-primary", claim.IssuerId);
        Assert.Equal("R275", claim.RuleId);
        Assert.Equal("OAuthDeviceFlowAbuseConfirmed", claim.Operation);
        Assert.Equal(evidenceId, claim.EvidenceId);
        Assert.Equal(request.OccurredAtUtc, claim.OccurredAtUtc);
        Assert.Equal(request.SourceIp, claim.SourceIp);
        Assert.Equal(request.DestinationIp, claim.DestinationIp);
        Assert.Equal(request.ActorHash, claim.ActorHash);
        Assert.Equal(request.ResourceHash, claim.ResourceHash);
        Assert.Equal(request.TraceHash, claim.TraceHash);

        Assert.DoesNotContain("IdentityHost",
            typeof(AuditClaim).GetProperties().Select(property => property.Name));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("issuer with spaces")]
    [InlineData("issuer/slash")]
    public void Invalid_External_Issuer_Is_Rejected(string issuer)
    {
        Assert.False(Request().TryCreateUnsignedAuditClaim(
            issuer, Guid.NewGuid(), out var claim, out var reason));
        Assert.Null(claim);
        Assert.Equal("INVALID_R275_EXTERNAL_SIGNER_IDENTITY", reason);
    }

    [Fact]
    public void Empty_Evidence_Id_Is_Rejected()
    {
        Assert.False(Request().TryCreateUnsignedAuditClaim(
            "idp-primary", Guid.Empty, out var claim, out var reason));
        Assert.Null(claim);
        Assert.Equal("INVALID_R275_EXTERNAL_SIGNER_IDENTITY", reason);
    }

    [Fact]
    public void Two_Independent_External_Signers_Reach_Existing_Nonalerting_Gate()
    {
        var request = Request();

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

        Assert.True(request.TryCreateUnsignedAuditClaim(
            "idp-primary", Guid.NewGuid(), out var firstClaim, out _));
        Assert.True(request.TryCreateUnsignedAuditClaim(
            "idp-secondary", Guid.NewGuid(), out var secondClaim, out _));

        Assert.True(verifier.TryVerify(
            Sign(firstKey, firstClaim!), out var firstReceipt, out var firstReason),
            firstReason);
        Assert.True(verifier.TryVerify(
            Sign(secondKey, secondClaim!), out var secondReceipt, out var secondReason),
            secondReason);

        Assert.True(TrustedAuditReceiptCorrelation.TryCorrelate(
            firstReceipt, secondReceipt, out var pair, out var pairReason),
            pairReason);

        var assessed = OAuthDeviceFlowAuditCandidateGate.Assess(
            pair, Flow(), Now);

        Assert.Equal(
            OAuthDeviceFlowAuditCandidateStatus.CorrelatedCandidateNotIntegrated,
            assessed.Status);
        Assert.Equal(
            "R275_SIGNED_IDP_AUDIT_CANDIDATE_NOT_INTEGRATED",
            assessed.Reason);
        Assert.False(assessed.AlertPermitted);
    }

    [Fact]
    public void Different_Evidence_Ids_Do_Not_Change_Subject_Or_Trace()
    {
        var request = Request();
        Assert.True(request.TryCreateUnsignedAuditClaim(
            "idp-primary", Guid.NewGuid(), out var first, out _));
        Assert.True(request.TryCreateUnsignedAuditClaim(
            "idp-secondary", Guid.NewGuid(), out var second, out _));

        Assert.NotEqual(first!.EvidenceId, second!.EvidenceId);
        Assert.Equal(first.OccurredAtUtc, second.OccurredAtUtc);
        Assert.Equal(first.SourceIp, second.SourceIp);
        Assert.Equal(first.DestinationIp, second.DestinationIp);
        Assert.Equal(first.ActorHash, second.ActorHash);
        Assert.Equal(first.ResourceHash, second.ResourceHash);
        Assert.Equal(first.TraceHash, second.TraceHash);
    }
}
