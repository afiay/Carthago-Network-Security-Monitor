// SPDX-License-Identifier: MIT
using System;
using System.Security.Cryptography;
using System.Text.Json;
using Carthago.Services.TrustedAudit;
using Xunit;

namespace Carthago.Tests;

public sealed class TrustedAuditReceiptCorrelationTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 10, 28, 22, 0, 0, TimeSpan.Zero);

    private const string TraceHash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ActorHash =
        "a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123";
    private const string ResourceHash =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    private static TrustedAuditReceiptVerifier CreateVerifier(RSA a, RSA b)
        => new(new[]
        {
            new TrustedAuditIssuer("winrm-primary",
                Convert.ToBase64String(a.ExportSubjectPublicKeyInfo()), new[] { "R343", "R275" }),
            new TrustedAuditIssuer("winrm-secondary",
                Convert.ToBase64String(b.ExportSubjectPublicKeyInfo()), new[] { "R343", "R275" })
        }, () => Now);

    private static AuditClaim Claim(string issuer = "winrm-primary") => new()
    {
        IssuerId = issuer,
        RuleId = "R343",
        EvidenceId = Guid.NewGuid(),
        OccurredAtUtc = Now.AddMinutes(-1),
        Operation = "WinRmEncodedCommandExecuted",
        SourceIp = "10.20.30.40",
        DestinationIp = "10.20.30.50",
        ActorHash = ActorHash,
        ResourceHash = ResourceHash,
        TraceHash = TraceHash
    };

    private static VerifiedAuditReceipt Verify(
        TrustedAuditReceiptVerifier verifier, RSA privateKey, AuditClaim claim)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(claim);
        var signature = privateKey.SignData(
            TrustedAuditReceiptVerifier.SigningBytes(json),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var envelope = new SignedAuditEnvelope(claim.IssuerId,
            Convert.ToBase64String(json), Convert.ToBase64String(signature));
        Assert.True(verifier.TryVerify(envelope, out var receipt, out var reason), reason);
        return Assert.IsType<VerifiedAuditReceipt>(receipt);
    }

    [Fact]
    public void Two_Distinct_Trusted_Signers_With_Identical_Subject_And_Trace_Correlate()
    {
        using var a = RSA.Create(2048);
        using var b = RSA.Create(2048);
        var verifier = CreateVerifier(a, b);
        var first = Verify(verifier, a, Claim());
        var second = Verify(verifier, b, Claim("winrm-secondary"));
        Assert.True(TrustedAuditReceiptCorrelation.TryCorrelate(first, second,
            out var pair, out var reason));
        Assert.Equal("CORRELATED_NOT_AUTHORIZED_FOR_ALERT", reason);
        Assert.NotNull(pair);
        Assert.Same(first, pair.First);
        Assert.Same(second, pair.Second);
    }

    [Fact]
    public void Same_Signer_Cannot_Independently_Corroborate_Itself()
    {
        using var a = RSA.Create(2048);
        using var b = RSA.Create(2048);
        var verifier = CreateVerifier(a, b);
        var first = Verify(verifier, a, Claim());
        var second = Verify(verifier, a, Claim());
        Assert.False(TrustedAuditReceiptCorrelation.TryCorrelate(first, second,
            out var pair, out var reason));
        Assert.Null(pair);
        Assert.Equal("NON_INDEPENDENT_AUDIT_RECEIPTS", reason);
    }

    [Fact]
    public void Separately_Constructed_Verifiers_Never_Mix_Receipt_Capabilities()
    {
        using var a = RSA.Create(2048);
        using var b = RSA.Create(2048);
        var first = Verify(CreateVerifier(a, b), a, Claim());
        var second = Verify(CreateVerifier(a, b), b, Claim("winrm-secondary"));
        Assert.False(TrustedAuditReceiptCorrelation.TryCorrelate(first, second,
            out var pair, out var reason));
        Assert.Null(pair);
        Assert.Equal("UNRELATED_TRUST_REGISTRIES", reason);
    }

    [Theory]
    [InlineData("trace")]
    [InlineData("actor")]
    [InlineData("resource")]
    [InlineData("source")]
    [InlineData("destination")]
    [InlineData("rule")]
    [InlineData("operation")]
    [InlineData("time")]
    public void Signed_But_Unrelated_Events_Cannot_Be_Paired(string mismatch)
    {
        using var a = RSA.Create(2048);
        using var b = RSA.Create(2048);
        var verifier = CreateVerifier(a, b);
        var first = Verify(verifier, a, Claim());
        var altered = Claim("winrm-secondary");
        switch (mismatch)
        {
            case "trace":
                altered.TraceHash = new string('b', 64);
                break;
            case "actor":
                altered.ActorHash = new string('b', 64);
                break;
            case "resource":
                altered.ResourceHash = new string('b', 64);
                break;
            case "source":
                altered.SourceIp = "10.20.30.41";
                break;
            case "destination":
                altered.DestinationIp = "10.20.30.51";
                break;
            case "rule":
                altered.RuleId = "R275";
                altered.Operation = "OAuthDeviceFlowAbuseConfirmed";
                break;
            case "operation":
                // A different valid operation is only possible in a different
                // rule scope, whose mismatch must fail closed.
                altered.RuleId = "R275";
                altered.Operation = "OAuthDeviceFlowAbuseConfirmed";
                break;
            case "time":
                altered.OccurredAtUtc = Now.AddMinutes(-4);
                break;
        }

        var second = Verify(verifier, b, altered);
        Assert.False(TrustedAuditReceiptCorrelation.TryCorrelate(first, second,
            out var pair, out var reason));
        Assert.Null(pair);
        Assert.Equal("AUDIT_SUBJECT_OR_TRACE_MISMATCH", reason);
    }

    [Fact]
    public void Shared_Evidence_Uuid_From_Two_Signers_Is_Not_Independent()
    {
        using var a = RSA.Create(2048);
        using var b = RSA.Create(2048);
        var verifier = CreateVerifier(a, b);
        var firstClaim = Claim();
        var secondClaim = Claim("winrm-secondary");
        secondClaim.EvidenceId = firstClaim.EvidenceId;
        var first = Verify(verifier, a, firstClaim);
        var second = Verify(verifier, b, secondClaim);
        Assert.False(TrustedAuditReceiptCorrelation.TryCorrelate(first, second,
            out var pair, out var reason));
        Assert.Null(pair);
        Assert.Equal("NON_INDEPENDENT_AUDIT_RECEIPTS", reason);
    }

    [Fact]
    public void Missing_Verified_Receipt_Never_Correlates()
    {
        Assert.False(TrustedAuditReceiptCorrelation.TryCorrelate(
            null, null, out var pair, out var reason));
        Assert.Null(pair);
        Assert.Equal("MISSING_VERIFIED_RECEIPT", reason);
    }
}
