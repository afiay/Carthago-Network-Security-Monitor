// SPDX-License-Identifier: MIT
// R437 audit corroboration gate. SOURCE CANDIDATE — UNVERIFIED.
// Deliberately not a live ingestion endpoint or authorization to emit alerts.
using System;
using System.Net;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Services.TrustedAudit
{
    public enum RedisAuditCandidateStatus
    {
        MissingVerifiedAudits,
        SignatureOrReplayRejected,
        IndependentAuditCorrelationRejected,
        WrongRuleOrOperation,
        MissingWireResponse,
        AuditEndpointMismatch,
        AuditClockMismatch,
        RedisServerInventoryUnconfigured,
        RedisServerNotApproved,
        AdminPolicyUnconfigured,
        ApprovedAdminClient,
        UnapprovedClientRequiresTransactionBinding
    }

    /// <summary>
    /// Metadata-only diagnostics for an independently signed Redis audit pair.
    /// The constructor and result are NOT an alert capability. A signed audit
    /// claim and IP/time coincidence cannot prove the precise TCP transaction.
    /// </summary>
    public sealed record RedisAuditCandidateAssessment(
        RedisAuditCandidateStatus Status,
        string Reason)
    {
        // Fixed false until a separately reviewed producer-to-transaction
        // provenance and detection-quality gate is explicitly implemented.
        public bool AlertPermitted => false;
    }

    /// <summary>
    /// Reuses the existing RSA-PSS audit receipt verifier and independent-issuer
    /// correlation. Does not accept raw JSON or a caller-supplied "trusted" flag.
    ///
    /// The operator must provision two independent trusted audit issuers scoped
    /// to R437. A Redis Software command audit's plain "CONFIG" name does not
    /// establish the CONFIG SET subcommand; an external producer must obtain
    /// and attest that distinction independently before signing.
    /// </summary>
    public static class RedisTrustedAuditCandidateGate
    {
        public const string RuleId = "R437";
        public const string Operation = "RedisConfigSetCommandSucceeded";
        private static readonly TimeSpan MaxWireAuditOffset = TimeSpan.FromSeconds(30);

        public static RedisAuditCandidateAssessment Assess(
            CorrelatedAuditReceipts? signedPair,
            TrafficRecord? observedServerReply,
            ApprovedAssetRegistry? approvals,
            DateTimeOffset observedReplyUtc)
        {
            if (signedPair == null)
                return Deny(RedisAuditCandidateStatus.MissingVerifiedAudits,
                    "R437_VERIFIED_AUDIT_PAIR_UNAVAILABLE");

            var first = signedPair.First;
            var second = signedPair.Second;
            if (first.RuleId != RuleId || second.RuleId != RuleId
                || first.Operation != Operation || second.Operation != Operation)
                return Deny(RedisAuditCandidateStatus.WrongRuleOrOperation,
                    "R437_AUDIT_RULE_OR_OPERATION_MISMATCH");

            if (observedServerReply == null
                || !observedServerReply.IsTcp
                || !observedServerReply.RedisRespConfigSetReplyOkObserved
                || observedServerReply.RedisRespConfigSetReplyErrorObserved
                || observedServerReply.SourcePort != 6379
                || observedServerReply.DestinationPort is not (> 0 and <= 65535)
                || !IPAddress.TryParse(observedServerReply.Source, out var server)
                || !IPAddress.TryParse(observedServerReply.Destination, out var client))
                return Deny(RedisAuditCandidateStatus.MissingWireResponse,
                    "R437_CAPTURE_CORRELATED_OK_UNAVAILABLE");

            if (!Matches(first.SourceIp, client)
                || !Matches(first.DestinationIp, server)
                || !Matches(second.SourceIp, client)
                || !Matches(second.DestinationIp, server))
                return Deny(RedisAuditCandidateStatus.AuditEndpointMismatch,
                    "R437_VERIFIED_AUDIT_ENDPOINT_MISMATCH");

            // Audit time is verified by the signature/replay verifier; the
            // capture timestamp is supplied separately by the internal caller.
            // Do not parse mutable TrafficRecord.Timestamp for trust decisions.
            if (observedReplyUtc.Offset != TimeSpan.Zero
                || !Within(first.OccurredAtUtc, observedReplyUtc)
                || !Within(second.OccurredAtUtc, observedReplyUtc))
                return Deny(RedisAuditCandidateStatus.AuditClockMismatch,
                    "R437_VERIFIED_AUDIT_WIRE_TIME_MISMATCH");

            if (approvals == null || !approvals.HasApprovedRedisServers)
                return Deny(RedisAuditCandidateStatus.RedisServerInventoryUnconfigured,
                    "R437_REDIS_SERVER_INVENTORY_UNCONFIGURED");
            if (!approvals.IsApprovedRedisServer(server.ToString()))
                return Deny(RedisAuditCandidateStatus.RedisServerNotApproved,
                    "R437_REDIS_SERVER_NOT_IN_TRUSTED_INVENTORY");
            if (!approvals.HasApprovedAdminHosts)
                return Deny(RedisAuditCandidateStatus.AdminPolicyUnconfigured,
                    "R437_ADMIN_HOST_POLICY_UNCONFIGURED");

            if (approvals.IsAdminHost(client.ToString()))
                return Deny(RedisAuditCandidateStatus.ApprovedAdminClient,
                    "R437_APPROVED_ADMIN_CLIENT_AUDITED");

            // The result stays non-alerting even after two independent signed
            // statements: there is no shared, independently verified unique TCP
            // transaction identifier bound to the packet-capture observation.
            return Deny(RedisAuditCandidateStatus.UnapprovedClientRequiresTransactionBinding,
                "R437_SIGNED_AUDIT_CANDIDATE_TRANSACTION_UNBOUND");
        }

        private static bool Within(DateTimeOffset audit, DateTimeOffset reply)
            => (audit - reply).Duration() <= MaxWireAuditOffset;

        private static bool Matches(string auditAddress, IPAddress observed)
            => IPAddress.TryParse(auditAddress, out var address)
                && address.Equals(observed);

        private static RedisAuditCandidateAssessment Deny(
            RedisAuditCandidateStatus status, string diagnostic)
            => new(status, diagnostic);
    }
}
