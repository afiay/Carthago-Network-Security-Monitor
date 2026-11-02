// SPDX-License-Identifier: MIT
// R437 — SOURCE CANDIDATE — UNVERIFIED. Synthetic signed claims only.
using System;
using System.Security.Cryptography;
using System.Text.Json;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;
using Carthago.Services.TrustedAudit;
using Xunit;

namespace Carthago.Tests;

public sealed class RedisTrustedAuditCandidateGateTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 2, 17, 0, 0, TimeSpan.Zero);
    private static readonly string Actor = new('a', 64);
    private static readonly string Resource = new('b', 64);
    private static readonly string Trace = new('c', 64);

    private static AuditClaim Claim(string issuer) => new()
    {
        IssuerId = issuer,
        RuleId = "R437",
        EvidenceId = Guid.NewGuid(),
        OccurredAtUtc = Now,
        Operation = RedisTrustedAuditCandidateGate.Operation,
        SourceIp = "10.4.0.9",
        DestinationIp = "10.4.0.10",
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

    private static CorrelatedAuditReceipts Pair()
    {
        using var firstKey = RSA.Create(2048);
        using var secondKey = RSA.Create(2048);
        var verifier = new TrustedAuditReceiptVerifier(new[]
        {
            new TrustedAuditIssuer("redis-audit-primary",
                Convert.ToBase64String(firstKey.ExportSubjectPublicKeyInfo()), new[] { "R437" }),
            new TrustedAuditIssuer("redis-audit-secondary",
                Convert.ToBase64String(secondKey.ExportSubjectPublicKeyInfo()), new[] { "R437" })
        }, () => Now);

        Assert.True(verifier.TryVerify(Sign(firstKey, Claim("redis-audit-primary")),
            out var first, out var whyFirst), whyFirst);
        Assert.True(verifier.TryVerify(Sign(secondKey, Claim("redis-audit-secondary")),
            out var second, out var whySecond), whySecond);
        Assert.True(TrustedAuditReceiptCorrelation.TryCorrelate(first, second,
            out var pair, out var whyPair), whyPair);
        return Assert.IsType<CorrelatedAuditReceipts>(pair);
    }

    private static TrafficRecord Reply() => new()
    {
        Source = "10.4.0.10", Destination = "10.4.0.9",
        SourcePort = 6379, DestinationPort = 40000,
        Protocol = "TCP", IsTcp = true,
        RedisRespConfigSetReplyOkObserved = true
    };

    private static ApprovedAssetRegistry Registry(bool server = true, bool adminPolicy = true,
        bool clientApproved = false)
    {
        var options = new EnvironmentTuningOptions();
        if (server) options.Approved.RedisServers.Add("10.4.0.10");
        if (adminPolicy) options.Approved.AdminHosts.Add(
            clientApproved ? "10.4.0.9" : "10.4.0.8");
        return new ApprovedAssetRegistry(options);
    }

    [Fact]
    public void Two_Independently_Verified_R437_Signers_Produce_Only_A_Nonalerting_Candidate()
    {
        var pair = Pair();
        var assessed = RedisTrustedAuditCandidateGate.Assess(
            pair, Reply(), Registry(), Now);

        Assert.Equal(RedisAuditCandidateStatus.UnapprovedClientRequiresTransactionBinding,
            assessed.Status);
        Assert.Equal("R437_SIGNED_AUDIT_CANDIDATE_TRANSACTION_UNBOUND",
            assessed.Reason);
        Assert.False(assessed.AlertPermitted);
        Assert.Equal("R437", pair.First.RuleId);
        Assert.Equal("RedisConfigSetCommandSucceeded", pair.Second.Operation);
    }

    [Fact]
    public void Approved_Administrator_Remains_Nonalerting_Even_With_Two_Signed_Claims()
    {
        var assessed = RedisTrustedAuditCandidateGate.Assess(
            Pair(), Reply(), Registry(clientApproved: true), Now);
        Assert.Equal(RedisAuditCandidateStatus.ApprovedAdminClient, assessed.Status);
        Assert.False(assessed.AlertPermitted);
    }

    [Fact]
    public void Missing_Server_Inventory_Or_Admin_Policy_Always_Fails_Closed()
    {
        var pair = Pair();
        Assert.Equal(RedisAuditCandidateStatus.RedisServerInventoryUnconfigured,
            RedisTrustedAuditCandidateGate.Assess(
                pair, Reply(), Registry(server: false), Now).Status);
        Assert.Equal(RedisAuditCandidateStatus.AdminPolicyUnconfigured,
            RedisTrustedAuditCandidateGate.Assess(
                pair, Reply(), Registry(adminPolicy: false), Now).Status);
        Assert.Equal(RedisAuditCandidateStatus.RedisServerInventoryUnconfigured,
            RedisTrustedAuditCandidateGate.Assess(
                pair, Reply(), null, Now).Status);
    }

    [Fact]
    public void Server_Not_In_Approved_Inventory_Is_Never_Trusted()
    {
        var options = new EnvironmentTuningOptions();
        options.Approved.RedisServers.Add("10.4.0.50");
        options.Approved.AdminHosts.Add("10.4.0.8");
        var assessed = RedisTrustedAuditCandidateGate.Assess(
            Pair(), Reply(), new ApprovedAssetRegistry(options), Now);
        Assert.Equal(RedisAuditCandidateStatus.RedisServerNotApproved, assessed.Status);
        Assert.False(assessed.AlertPermitted);
    }

    [Fact]
    public void Missing_Wire_Reply_Or_Rejected_Command_Cannot_Confirm_Audit()
    {
        var pair = Pair();
        Assert.Equal(RedisAuditCandidateStatus.MissingWireResponse,
            RedisTrustedAuditCandidateGate.Assess(
                pair, null, Registry(), Now).Status);
        var rejected = Reply();
        rejected.RedisRespConfigSetReplyOkObserved = false;
        rejected.RedisRespConfigSetReplyErrorObserved = true;
        Assert.Equal(RedisAuditCandidateStatus.MissingWireResponse,
            RedisTrustedAuditCandidateGate.Assess(
                pair, rejected, Registry(), Now).Status);
        var wrongPort = Reply();
        wrongPort.SourcePort = 6380;
        Assert.Equal(RedisAuditCandidateStatus.MissingWireResponse,
            RedisTrustedAuditCandidateGate.Assess(
                pair, wrongPort, Registry(), Now).Status);
    }

    [Fact]
    public void Signed_Endpoints_Must_Match_The_Reverse_Direction_Wire_Reply()
    {
        var pair = Pair();
        var wrongSource = Reply();
        wrongSource.Destination = "10.4.0.8";
        Assert.Equal(RedisAuditCandidateStatus.AuditEndpointMismatch,
            RedisTrustedAuditCandidateGate.Assess(
                pair, wrongSource, Registry(), Now).Status);
        var wrongServer = Reply();
        wrongServer.Source = "10.4.0.11";
        Assert.Equal(RedisAuditCandidateStatus.AuditEndpointMismatch,
            RedisTrustedAuditCandidateGate.Assess(
                pair, wrongServer, Registry(), Now).Status);
    }

    [Fact]
    public void Audit_To_Capture_Clock_Alignment_Has_Strict_Thirty_Second_Boundary()
    {
        var pair = Pair();
        Assert.Equal(RedisAuditCandidateStatus.UnapprovedClientRequiresTransactionBinding,
            RedisTrustedAuditCandidateGate.Assess(
                pair, Reply(), Registry(), Now.AddSeconds(30)).Status);
        Assert.Equal(RedisAuditCandidateStatus.AuditClockMismatch,
            RedisTrustedAuditCandidateGate.Assess(
                pair, Reply(), Registry(), Now.AddSeconds(31)).Status);
        Assert.Equal(RedisAuditCandidateStatus.AuditClockMismatch,
            RedisTrustedAuditCandidateGate.Assess(
                pair, Reply(), Registry(), Now.AddSeconds(-31)).Status);
        Assert.Equal(RedisAuditCandidateStatus.AuditClockMismatch,
            RedisTrustedAuditCandidateGate.Assess(
                pair, Reply(), Registry(), Now.ToOffset(TimeSpan.FromHours(1))).Status);
    }

    [Fact]
    public void Raw_Unverified_Claims_And_Unrelated_Signers_Cannot_Be_Introduced_As_Trusted_Pair()
    {
        Assert.Equal(RedisAuditCandidateStatus.MissingVerifiedAudits,
            RedisTrustedAuditCandidateGate.Assess(
                null, Reply(), Registry(), Now).Status);
        using var trusted = RSA.Create(2048);
        using var attacker = RSA.Create(2048);
        var verifier = new TrustedAuditReceiptVerifier(new[]
        {
            new TrustedAuditIssuer("redis-audit-primary",
                Convert.ToBase64String(trusted.ExportSubjectPublicKeyInfo()), new[] { "R437" })
        }, () => Now);
        var fake = Sign(attacker, Claim("redis-audit-primary"));
        Assert.False(verifier.TryVerify(fake, out var receipt, out _));
        Assert.Null(receipt);
    }

    [Fact]
    public void End_To_End_Signed_Intake_Requires_Two_Pinned_Independent_Issuers()
    {
        using var firstKey = RSA.Create(2048);
        using var secondKey = RSA.Create(2048);
        var verifier = new TrustedAuditReceiptVerifier(new[]
        {
            new TrustedAuditIssuer("redis-audit-primary",
                Convert.ToBase64String(firstKey.ExportSubjectPublicKeyInfo()),
                new[] { "R437" }),
            new TrustedAuditIssuer("redis-audit-secondary",
                Convert.ToBase64String(secondKey.ExportSubjectPublicKeyInfo()),
                new[] { "R437" })
        }, () => Now);
        var intake = new RedisSignedAuditCandidateIntake(verifier, Registry());
        var first = Sign(firstKey, Claim("redis-audit-primary"));
        var second = Sign(secondKey, Claim("redis-audit-secondary"));

        var accepted = intake.Assess(first, second, Reply(), Now);
        Assert.Equal(RedisAuditCandidateStatus.UnapprovedClientRequiresTransactionBinding,
            accepted.Status);
        Assert.False(accepted.AlertPermitted);

        // Once a pair was consumed by the replay verifier, presenting it
        // again is never a second independent audit observation.
        var replay = intake.Assess(first, second, Reply(), Now);
        Assert.Equal(RedisAuditCandidateStatus.SignatureOrReplayRejected, replay.Status);
        Assert.False(replay.AlertPermitted);
    }

    [Fact]
    public void Invalid_Signer_Or_One_Receipt_Cannot_Enter_The_Trusted_Audit_Path()
    {
        using var key = RSA.Create(2048);
        using var attacker = RSA.Create(2048);
        var verifier = new TrustedAuditReceiptVerifier(new[]
        {
            new TrustedAuditIssuer("redis-audit-primary",
                Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
                new[] { "R437" })
        }, () => Now);
        var intake = new RedisSignedAuditCandidateIntake(verifier, Registry());
        var first = Sign(key, Claim("redis-audit-primary"));
        var forged = Sign(attacker, Claim("redis-audit-primary"));

        Assert.Equal(RedisAuditCandidateStatus.MissingVerifiedAudits,
            intake.Assess(first, null, Reply(), Now).Status);
        Assert.Equal(RedisAuditCandidateStatus.SignatureOrReplayRejected,
            intake.Assess(forged, first, Reply(), Now).Status);
    }

    [Fact]
    public void One_Signer_Cannot_Corroborate_Their_Own_Two_Signed_Events()
    {
        using var key = RSA.Create(2048);
        var verifier = new TrustedAuditReceiptVerifier(new[]
        {
            new TrustedAuditIssuer("redis-audit-primary",
                Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
                new[] { "R437" })
        }, () => Now);
        var intake = new RedisSignedAuditCandidateIntake(verifier, Registry());

        var result = intake.Assess(
            Sign(key, Claim("redis-audit-primary")),
            Sign(key, Claim("redis-audit-primary")), Reply(), Now);
        Assert.Equal(RedisAuditCandidateStatus.IndependentAuditCorrelationRejected,
            result.Status);
        Assert.False(result.AlertPermitted);
    }

    [Fact]
    public void Generic_Config_Command_Is_Not_An_Attestable_R437_Config_Set_Outcome()
    {
        using var key = RSA.Create(2048);
        var verifier = new TrustedAuditReceiptVerifier(new[]
        {
            new TrustedAuditIssuer("redis-audit-primary",
                Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()), new[] { "R437" })
        }, () => Now);

        // Redis Software's generic command audit contains "CONFIG" and status,
        // but no independently attested CONFIG SET subcommand.
        var generic = Claim("redis-audit-primary");
        generic.Operation = "RedisConfigCommandSucceeded";
        Assert.False(verifier.TryVerify(Sign(key, generic), out _, out var reason));
        Assert.Equal("INVALID_CLAIM", reason);
    }
}
