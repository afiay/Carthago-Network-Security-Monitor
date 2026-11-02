// SPDX-License-Identifier: MIT
// Source candidate, unverified. Signed Redis audit intake is opt-in and non-alerting.
using System;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// Narrow authenticated intake for metadata-only R437 candidate assessments.
    /// Reuses CARTHAGO's existing pinned RSA-PSS verifier, replay cache and
    /// independent-issuer correlation. It accepts signed envelopes only, not
    /// arbitrary Redis Software audit JSON, packet Info or synthetic trust flags.
    ///
    /// No network listener, signer private key, implicit trust root, live R437
    /// registration or alert promotion is created by this component.
    /// </summary>
    public sealed class RedisSignedAuditCandidateIntake
    {
        private readonly TrustedAuditReceiptVerifier _verifier;
        private readonly ApprovedAssetRegistry _approvals;

        public RedisSignedAuditCandidateIntake(
            TrustedAuditReceiptVerifier verifier,
            ApprovedAssetRegistry approvals)
        {
            _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
            _approvals = approvals ?? throw new ArgumentNullException(nameof(approvals));
        }

        public RedisAuditCandidateAssessment Assess(
            SignedAuditEnvelope? primary,
            SignedAuditEnvelope? corroborating,
            TrafficRecord? capturedReply,
            DateTimeOffset capturedReplyUtc)
        {
            if (primary == null || corroborating == null)
                return new(RedisAuditCandidateStatus.MissingVerifiedAudits,
                    "R437_SIGNED_AUDIT_ENVELOPES_MISSING");

            if (!_verifier.TryVerify(primary, out var first, out _))
                return new(RedisAuditCandidateStatus.SignatureOrReplayRejected,
                    "R437_PRIMARY_AUDIT_SIGNATURE_OR_REPLAY_REJECTED");
            if (!_verifier.TryVerify(corroborating, out var second, out _))
                return new(RedisAuditCandidateStatus.SignatureOrReplayRejected,
                    "R437_CORROBORATING_AUDIT_SIGNATURE_OR_REPLAY_REJECTED");

            if (!TrustedAuditReceiptCorrelation.TryCorrelate(first, second,
                    out var pair, out _))
                return new(RedisAuditCandidateStatus.IndependentAuditCorrelationRejected,
                    "R437_INDEPENDENT_AUDIT_CORRELATION_REJECTED");

            return RedisTrustedAuditCandidateGate.Assess(
                pair, capturedReply, _approvals, capturedReplyUtc);
        }
    }
}
