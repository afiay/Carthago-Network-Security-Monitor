// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Carthago.Services.TrustedAudit;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class TrustedAuditReceiptVerifierTests
{
    private static readonly DateTimeOffset Clock =
        new(2026, 10, 28, 22, 0, 0, TimeSpan.Zero);
    private const string Actor = "a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123";
    private const string Resource = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    private static AuditClaim Claim(string rule = "R343") => new()
    {
        IssuerId = "winrm-issuer",
        RuleId = rule,
        EvidenceId = Guid.NewGuid(),
        OccurredAtUtc = Clock.AddMinutes(-1),
        Operation = rule switch
        {
            "R343" => "WinRmEncodedCommandExecuted",
            "R295" => "KubernetesPodExecAuthorized",
            "R275" => "OAuthDeviceFlowAbuseConfirmed",
            "R163" => "HttpMetadataRequestCausallyLinked",
            _ => "Unknown"
        },
        SourceIp = "10.0.0.70",
        DestinationIp = "10.0.0.20",
        ActorHash = Actor,
        ResourceHash = Resource
    };

    private static TrustedAuditReceiptVerifier Verifier(RSA key, string[] rules)
        => new(
            new[] {
                new TrustedAuditIssuer("winrm-issuer",
                    Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()), rules)
            },
            () => Clock);

    private static SignedAuditEnvelope Signed(RSA key, AuditClaim claim)
        => SignedPayload(key, JsonSerializer.SerializeToUtf8Bytes(claim));

    private static SignedAuditEnvelope SignedPayload(RSA key, byte[] payload)
    {
        var bytes = TrustedAuditReceiptVerifier.SigningBytes(payload);
        var signature = key.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return new SignedAuditEnvelope("winrm-issuer",
            Convert.ToBase64String(payload), Convert.ToBase64String(signature));
    }

    [Fact]
    public void Valid_Pinned_WinRm_Receipt_Produces_Immutable_Claim_Only()
    {
        using var key = RSA.Create(2048);
        var verifier = Verifier(key, new[] { "R343" });
        var claim = Claim();
        Assert.True(verifier.TryVerify(Signed(key, claim), out var verified, out var reason));
        Assert.Equal("VERIFIED", reason);
        Assert.NotNull(verified);
        Assert.Equal(claim.EvidenceId, verified.EvidenceId);
        Assert.Equal("R343", verified.RuleId);
        Assert.Equal("WinRmEncodedCommandExecuted", verified.Operation);
        Assert.Equal(Actor, verified.ActorHash);
    }

    [Fact]
    public void Tampered_Signed_Operation_Is_Rejected()
    {
        using var key = RSA.Create(2048);
        var verifier = Verifier(key, new[] { "R343" });
        var envelope = Signed(key, Claim());
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(envelope.PayloadBase64));
        var forgedPayload = Encoding.UTF8.GetBytes(json.Replace(
            "WinRmEncodedCommandExecuted", "KubernetesPodExecAuthorized", StringComparison.Ordinal));
        var forged = envelope with { PayloadBase64 = Convert.ToBase64String(forgedPayload) };
        Assert.False(verifier.TryVerify(forged, out var receipt, out var reason));
        Assert.Null(receipt);
        Assert.Equal("INVALID_SIGNATURE", reason);
    }

    [Fact]
    public void Unknown_Signer_And_Wrong_Key_Are_Refused()
    {
        using var trusted = RSA.Create(2048);
        using var attacker = RSA.Create(2048);
        var verifier = Verifier(trusted, new[] { "R343" });
        Assert.False(verifier.TryVerify(Signed(attacker, Claim()), out _, out var reason));
        Assert.Equal("INVALID_SIGNATURE", reason);
        var unknown = Signed(trusted, Claim()) with { IssuerId = "unregistered-issuer" };
        Assert.False(verifier.TryVerify(unknown, out _, out _));
    }

    [Fact]
    public void Signer_Allowed_Only_R343_Cannot_Attest_Kubernetes_Or_Idp()
    {
        using var key = RSA.Create(2048);
        var verifier = Verifier(key, new[] { "R343" });
        foreach (var rule in new[] { "R295", "R275", "R163" })
        {
            var claim = Claim(rule);
            Assert.False(verifier.TryVerify(Signed(key, claim), out _, out var reason));
            Assert.Equal("INVALID_CLAIM", reason);
        }
    }

    [Fact]
    public void Wrong_Rule_Operation_Pair_Fails_Closed_Even_When_Signed()
    {
        using var key = RSA.Create(2048);
        var verifier = Verifier(key, new[] { "R343" });
        var claim = Claim();
        claim.Operation = "KubernetesPodExecAuthorized";
        Assert.False(verifier.TryVerify(Signed(key, claim), out _, out var reason));
        Assert.Equal("INVALID_CLAIM", reason);
    }

    [Fact]
    public void Expired_And_Future_Signed_Claims_Are_Rejected()
    {
        using var key = RSA.Create(2048);
        var verifier = Verifier(key, new[] { "R343" });
        var expired = Claim();
        expired.OccurredAtUtc = Clock.AddMinutes(-11);
        Assert.False(verifier.TryVerify(Signed(key, expired), out _, out var expiredReason));
        Assert.Equal("STALE_OR_FUTURE_AUDIT", expiredReason);
        var future = Claim();
        future.OccurredAtUtc = Clock.AddMinutes(3);
        Assert.False(verifier.TryVerify(Signed(key, future), out _, out var futureReason));
        Assert.Equal("STALE_OR_FUTURE_AUDIT", futureReason);
    }

    [Fact]
    public void Duplicate_Signed_Receipt_Is_Consumed_At_Most_Once()
    {
        using var key = RSA.Create(2048);
        var verifier = Verifier(key, new[] { "R343" });
        var envelope = Signed(key, Claim());
        Assert.True(verifier.TryVerify(envelope, out _, out _));
        Assert.False(verifier.TryVerify(envelope, out var second, out var reason));
        Assert.Null(second);
        Assert.Equal("REPLAY_OR_CAPACITY", reason);
    }

    [Fact]
    public void Missing_ActorHash_Or_Identical_Endpoints_Fails_Closed()
    {
        using var key = RSA.Create(2048);
        var verifier = Verifier(key, new[] { "R343" });
        var badActor = Claim();
        badActor.ActorHash = "powershell.exe -enc secret";
        Assert.False(verifier.TryVerify(Signed(key, badActor), out _, out _));
        var loop = Claim();
        loop.DestinationIp = loop.SourceIp;
        Assert.False(verifier.TryVerify(Signed(key, loop), out _, out _));
    }

    [Fact]
    public void Signed_Duplicate_Or_Unexpected_Json_Fields_Are_Rejected()
    {
        using var key = RSA.Create(2048);
        var verifier = Verifier(key, new[] { "R343" });
        var json = JsonSerializer.Serialize(Claim());
        var duplicate = json.Insert(1, "\"RuleId\":\"R343\",");
        Assert.False(verifier.TryVerify(SignedPayload(key, Encoding.UTF8.GetBytes(duplicate)),
            out _, out _));
        var extra = json.Insert(1, "\"RawCommand\":\"-EncodedCommand secret\",");
        Assert.False(verifier.TryVerify(SignedPayload(key, Encoding.UTF8.GetBytes(extra)),
            out _, out _));
    }

    [Fact]
    public void Invalid_Envelope_And_Untrusted_Claims_Never_Become_Receipts()
    {
        using var key = RSA.Create(2048);
        var verifier = Verifier(key, new[] { "R343" });
        Assert.False(verifier.TryVerify(new SignedAuditEnvelope("winrm-issuer",
            "%%%", "%%%"), out var receipt, out _));
        Assert.Null(receipt);
        var mismatch = Claim();
        mismatch.IssuerId = "different-issuer";
        Assert.False(verifier.TryVerify(Signed(key, mismatch), out _, out _));
    }

    [Theory]
    [InlineData("R343")]
    [InlineData("R295")]
    [InlineData("R275")]
    public async System.Threading.Tasks.Task A_Verified_Envelope_Alone_Cannot_Promote_An_Unwired_Rule(string ruleId)
    {
        // A unit-test signer is NOT a trusted upstream audit producer.
        // The receipt boundary is deliberately not connected to the live
        // RuleEngine or benchmark; normal packet text must still fail closed.
        using var key = RSA.Create(2048);
        var verifier = Verifier(key, new[] { ruleId });
        var claim = Claim(ruleId);
        Assert.True(verifier.TryVerify(Signed(key, claim), out var receipt, out _));
        Assert.NotNull(receipt);

        IDetectionRule rule = ruleId switch
        {
            "R343" => new R343_PowerShellRemotingEncodedCommandRule(),
            "R295" => new R295_KubernetesExecIntoPodOverAPIRule(),
            "R275" => new R275_OAuthDeviceCodePhishingIndicatorRule(),
            _ => throw new ArgumentOutOfRangeException(nameof(ruleId))
        };
        var record = new TrafficRecord
        {
            Source = claim.SourceIp,
            Destination = claim.DestinationIp,
            Protocol = "TCP",
            IsTcp = true,
            SourcePort = 53000,
            DestinationPort = ruleId == "R343" ? 5985 : ruleId == "R295" ? 6443 : 443,
            ProcessName = "powershell.exe",
            ApplicationProtocol = "WinRM",
            Info = claim.Operation + " verified with synthetic signature"
        };
        var result = await rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, Clock.UtcDateTime));
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
    }

    [Fact]
    public void Invalid_Trust_Anchor_And_Undersized_Key_Cannot_Be_Registered()
    {
        using var small = RSA.Create(1024);
        Assert.Throws<ArgumentException>(() => Verifier(small, new[] { "R343" }));
        using var valid = RSA.Create(2048);
        Assert.Throws<ArgumentException>(() => Verifier(valid, new[] { "R999" }));
        Assert.Throws<ArgumentException>(() => new TrustedAuditReceiptVerifier(
            Array.Empty<TrustedAuditIssuer>()));
    }
}
