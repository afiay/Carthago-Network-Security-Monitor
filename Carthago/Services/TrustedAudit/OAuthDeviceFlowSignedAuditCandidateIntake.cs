// SPDX-License-Identifier: MIT
// R275 signed IdP audit intake. SOURCE CANDIDATE — UNVERIFIED.
using System;
using Carthago.Models;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// Accepts only signed envelopes that pass the existing operator-pinned
    /// RSA-PSS verifier and independent-issuer correlation contract.
    /// Raw IdP JSON, OAuth codes, bearer tokens and caller-supplied trust flags
    /// are never accepted by this boundary.
    ///
    /// No listener, provider credential, signer private key, rule-engine wiring
    /// or alert promotion is introduced here.
    /// </summary>
    public sealed class OAuthDeviceFlowSignedAuditCandidateIntake
    {
        private readonly TrustedAuditReceiptVerifier _verifier;

        public OAuthDeviceFlowSignedAuditCandidateIntake(
            TrustedAuditReceiptVerifier verifier)
        {
            _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        }

        public OAuthDeviceFlowAuditCandidateAssessment Assess(
            SignedAuditEnvelope? primary,
            SignedAuditEnvelope? corroborating,
            TrafficRecord? observedFlow,
            DateTimeOffset observedFlowUtc)
        {
            if (primary == null || corroborating == null)
                return new(OAuthDeviceFlowAuditCandidateStatus.MissingVerifiedAudits,
                    "R275_SIGNED_IDP_AUDIT_ENVELOPES_MISSING");

            if (!_verifier.TryVerify(primary, out var first, out _))
                return new(OAuthDeviceFlowAuditCandidateStatus.SignatureOrReplayRejected,
                    "R275_PRIMARY_AUDIT_SIGNATURE_OR_REPLAY_REJECTED");
            if (!_verifier.TryVerify(corroborating, out var second, out _))
                return new(OAuthDeviceFlowAuditCandidateStatus.SignatureOrReplayRejected,
                    "R275_CORROBORATING_AUDIT_SIGNATURE_OR_REPLAY_REJECTED");

            if (!TrustedAuditReceiptCorrelation.TryCorrelate(
                    first, second, out var pair, out _))
                return new(OAuthDeviceFlowAuditCandidateStatus.IndependentAuditCorrelationRejected,
                    "R275_INDEPENDENT_AUDIT_CORRELATION_REJECTED");

            return OAuthDeviceFlowAuditCandidateGate.Assess(
                pair, observedFlow, observedFlowUtc);
        }
    }
}
