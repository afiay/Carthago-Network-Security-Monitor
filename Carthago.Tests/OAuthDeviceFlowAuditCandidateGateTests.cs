// SPDX-License-Identifier: MIT
// R275 — SOURCE CANDIDATE — UNVERIFIED. Synthetic signed claims only.
using System;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services.TrustedAudit;
using Xunit;

namespace Carthago.Tests;

public sealed class OAuthDeviceFlowAuditCandidateGateTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 3, 20, 0, 0, TimeSpan.Zero);
    private static readonly string Actor = new('a', 64);
    private static readonly string Resource = new('b', 64);
    private static readonly string Trace = new('c', 64);

    private static AuditClaim Claim(string issuer, string ruleId = "R275") => new()
    {
        IssuerId = issuer,
        RuleId = ruleId,
        EvidenceId = Guid.NewGuid(),
        OccurredAtUtc = Now,
        Operation = ruleId == "R275"
            ? OAuthDeviceFlowAuditCandidateGate.Operation
            : "WinRmEncodedCommandExecuted",
        SourceIp = "10.10.20.30",
        DestinationIp = "20.30.40.50",
        ActorHash = Actor,
        ResourceHash = Resource,
        TraceHash = Trace
    };

    private static SignedAuditEnvelope Sign(RSA key, AuditClaim claim)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(claim);
        var signature = key.SignData(
            TrustedAuditReceiptVerifier.SigningBytes(payload),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return new SignedAuditEnvelope(claim.IssuerId,
            Convert.ToBase64String(payload), Convert.ToBase64String(signature));
    }

    private static TrafficRecord Flow() => new()
    {
        Source = "10.10.20.30",
        Destination = "20.30.40.50",
        SourcePort = 53000,
        DestinationPort = 443,
        Protocol = "TCP",
        ApplicationProtocol = "TLS",
        IsTcp = true,
        Sni = "login.microsoftonline.com"
    };

    private static CorrelatedAuditReceipts Pair(string ruleId = "R275")
    {
        using var firstKey = RSA.Create(2048);
        using var secondKey = RSA.Create(2048);
        var verifier = new TrustedAuditReceiptVerifier(new[]
        {
            new TrustedAuditIssuer("idp-primary",
                Convert.ToBase64String(firstKey.ExportSubjectPublicKeyInfo()),
                new[] { ruleId }),
            new TrustedAuditIssuer("idp-secondary",
                Convert.ToBase64String(secondKey.ExportSubjectPublicKeyInfo()),
                new[] { ruleId })
        }, () => Now);

        Assert.True(verifier.TryVerify(
            Sign(firstKey, Claim("idp-primary", ruleId)),
            out var first, out var firstReason), firstReason);
        Assert.True(verifier.TryVerify(
            Sign(secondKey, Claim("idp-secondary", ruleId)),
            out var second, out var secondReason), secondReason);
        Assert.True(TrustedAuditReceiptCorrelation.TryCorrelate(
            first, second, out var pair, out var pairReason), pairReason);
        return Assert.IsType<CorrelatedAuditReceipts>(pair);
    }

    [Fact]
    public void Two_Independent_Signed_Idp_Receipts_Create_Only_Nonalerting_Candidate()
    {
        var assessed = OAuthDeviceFlowAuditCandidateGate.Assess(
            Pair(), Flow(), Now);

        Assert.Equal(
            OAuthDeviceFlowAuditCandidateStatus.CorrelatedCandidateNotIntegrated,
            assessed.Status);
        Assert.Equal("R275_SIGNED_IDP_AUDIT_CANDIDATE_NOT_INTEGRATED",
            assessed.Reason);
        Assert.False(assessed.AlertPermitted);
    }

    [Fact]
    public void Missing_Network_Observation_Fails_Closed()
    {
        var assessed = OAuthDeviceFlowAuditCandidateGate.Assess(
            Pair(), null, Now);
        Assert.Equal(OAuthDeviceFlowAuditCandidateStatus.MissingNetworkObservation,
            assessed.Status);
        Assert.False(assessed.AlertPermitted);
    }

    [Fact]
    public void Arbitrary_Tcp_443_Without_Identity_Web_Context_Is_Not_Corroboration()
    {
        var flow = Flow();
        flow.ApplicationProtocol = "TCP";
        flow.Sni = null;
        flow.HttpHost = null;

        var assessed = OAuthDeviceFlowAuditCandidateGate.Assess(
            Pair(), flow, Now);

        Assert.Equal(OAuthDeviceFlowAuditCandidateStatus.MissingNetworkObservation,
            assessed.Status);
        Assert.False(assessed.AlertPermitted);
    }

    [Fact]
    public void Signed_Audit_Endpoints_Must_Match_Observed_Tls_Flow()
    {
        var flow = Flow();
        flow.Destination = "20.30.40.51";
        var assessed = OAuthDeviceFlowAuditCandidateGate.Assess(
            Pair(), flow, Now);
        Assert.Equal(OAuthDeviceFlowAuditCandidateStatus.NetworkEndpointMismatch,
            assessed.Status);
        Assert.False(assessed.AlertPermitted);
    }

    [Fact]
    public void Audit_To_Network_Clock_Alignment_Is_Bounded_And_Utc_Only()
    {
        var pair = Pair();
        Assert.Equal(
            OAuthDeviceFlowAuditCandidateStatus.CorrelatedCandidateNotIntegrated,
            OAuthDeviceFlowAuditCandidateGate.Assess(
                pair, Flow(), Now.AddMinutes(2)).Status);
        Assert.Equal(OAuthDeviceFlowAuditCandidateStatus.NetworkClockMismatch,
            OAuthDeviceFlowAuditCandidateGate.Assess(
                pair, Flow(), Now.AddMinutes(2).AddSeconds(1)).Status);
        Assert.Equal(OAuthDeviceFlowAuditCandidateStatus.NetworkClockMismatch,
            OAuthDeviceFlowAuditCandidateGate.Assess(
                pair, Flow(), Now.ToOffset(TimeSpan.FromHours(1))).Status);
    }

    [Fact]
    public void Wrong_Rule_Pair_Cannot_Be_Reused_As_R275_Evidence()
    {
        var assessed = OAuthDeviceFlowAuditCandidateGate.Assess(
            Pair("R343"), Flow(), Now);
        Assert.Equal(OAuthDeviceFlowAuditCandidateStatus.WrongRuleOrOperation,
            assessed.Status);
        Assert.False(assessed.AlertPermitted);
    }

    [Fact]
    public void End_To_End_Intake_Requires_Two_Pinned_Independent_Issuers()
    {
        using var firstKey = RSA.Create(2048);
        using var secondKey = RSA.Create(2048);
        var verifier = new TrustedAuditReceiptVerifier(new[]
        {
            new TrustedAuditIssuer("idp-primary",
                Convert.ToBase64String(firstKey.ExportSubjectPublicKeyInfo()),
                new[] { "R275" }),
            new TrustedAuditIssuer("idp-secondary",
                Convert.ToBase64String(secondKey.ExportSubjectPublicKeyInfo()),
                new[] { "R275" })
        }, () => Now);
        var intake = new OAuthDeviceFlowSignedAuditCandidateIntake(verifier);
        var first = Sign(firstKey, Claim("idp-primary"));
        var second = Sign(secondKey, Claim("idp-secondary"));

        var accepted = intake.Assess(first, second, Flow(), Now);
        Assert.Equal(
            OAuthDeviceFlowAuditCandidateStatus.CorrelatedCandidateNotIntegrated,
            accepted.Status);
        Assert.False(accepted.AlertPermitted);

        var replay = intake.Assess(first, second, Flow(), Now);
        Assert.Equal(OAuthDeviceFlowAuditCandidateStatus.SignatureOrReplayRejected,
            replay.Status);
        Assert.False(replay.AlertPermitted);
    }

    [Fact]
    public void Forged_Signer_And_Missing_Second_Receipt_Are_Rejected()
    {
        using var trusted = RSA.Create(2048);
        using var second = RSA.Create(2048);
        using var attacker = RSA.Create(2048);
        var verifier = new TrustedAuditReceiptVerifier(new[]
        {
            new TrustedAuditIssuer("idp-primary",
                Convert.ToBase64String(trusted.ExportSubjectPublicKeyInfo()),
                new[] { "R275" }),
            new TrustedAuditIssuer("idp-secondary",
                Convert.ToBase64String(second.ExportSubjectPublicKeyInfo()),
                new[] { "R275" })
        }, () => Now);
        var intake = new OAuthDeviceFlowSignedAuditCandidateIntake(verifier);
        var primary = Sign(trusted, Claim("idp-primary"));
        var forged = Sign(attacker, Claim("idp-secondary"));

        Assert.Equal(OAuthDeviceFlowAuditCandidateStatus.MissingVerifiedAudits,
            intake.Assess(primary, null, Flow(), Now).Status);
        Assert.Equal(OAuthDeviceFlowAuditCandidateStatus.SignatureOrReplayRejected,
            intake.Assess(forged, primary, Flow(), Now).Status);
    }

    [Fact]
    public void One_Signer_Cannot_Corroborate_Its_Own_Two_Events()
    {
        using var key = RSA.Create(2048);
        var verifier = new TrustedAuditReceiptVerifier(new[]
        {
            new TrustedAuditIssuer("idp-primary",
                Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
                new[] { "R275" })
        }, () => Now);
        var intake = new OAuthDeviceFlowSignedAuditCandidateIntake(verifier);

        var assessed = intake.Assess(
            Sign(key, Claim("idp-primary")),
            Sign(key, Claim("idp-primary")),
            Flow(), Now);

        Assert.Equal(
            OAuthDeviceFlowAuditCandidateStatus.IndependentAuditCorrelationRejected,
            assessed.Status);
        Assert.False(assessed.AlertPermitted);
    }

    [Fact]
    public async Task Candidate_Path_Remains_Unwired_And_Cannot_Promote_R275()
    {
        var candidate = OAuthDeviceFlowAuditCandidateGate.Assess(
            Pair(), Flow(), Now);
        Assert.Equal(
            OAuthDeviceFlowAuditCandidateStatus.CorrelatedCandidateNotIntegrated,
            candidate.Status);

        var result = await new R275_OAuthDeviceCodePhishingIndicatorRule()
            .EvaluateAsync(new RuleEvaluationContext(
                Flow(), Sensitivity.Balanced, Now.UtcDateTime));

        Assert.False(result.Matched);
        Assert.Empty(result.Events);
    }
}
