// SPDX-License-Identifier: MIT
// R275 trusted IdP audit candidate gate. SOURCE CANDIDATE — UNVERIFIED.
using System;
using System.Net;
using Carthago.Models;

namespace Carthago.Services.TrustedAudit
{
    public enum OAuthDeviceFlowAuditCandidateStatus
    {
        MissingVerifiedAudits,
        SignatureOrReplayRejected,
        IndependentAuditCorrelationRejected,
        WrongRuleOrOperation,
        MissingNetworkObservation,
        NetworkEndpointMismatch,
        NetworkClockMismatch,
        CorrelatedCandidateNotIntegrated
    }

    /// <summary>
    /// Privacy-minimized assessment of independently signed IdP audit receipts
    /// against one captured outbound TLS flow. This result is deliberately
    /// non-alerting; it is not exposed through TrafficRecord or RuleEvaluationContext.
    /// </summary>
    public sealed record OAuthDeviceFlowAuditCandidateAssessment(
        OAuthDeviceFlowAuditCandidateStatus Status,
        string Reason)
    {
        public bool AlertPermitted => false;
    }

    public static class OAuthDeviceFlowAuditCandidateGate
    {
        public const string RuleId = "R275";
        public const string Operation = "OAuthDeviceFlowAbuseConfirmed";
        private static readonly TimeSpan MaxNetworkAuditOffset = TimeSpan.FromMinutes(2);

        public static OAuthDeviceFlowAuditCandidateAssessment Assess(
            CorrelatedAuditReceipts? signedPair,
            TrafficRecord? observedFlow,
            DateTimeOffset observedFlowUtc)
        {
            if (signedPair == null)
                return Deny(OAuthDeviceFlowAuditCandidateStatus.MissingVerifiedAudits,
                    "R275_VERIFIED_IDP_AUDIT_PAIR_UNAVAILABLE");

            var first = signedPair.First;
            var second = signedPair.Second;
            if (!string.Equals(first.RuleId, RuleId, StringComparison.Ordinal)
                || !string.Equals(second.RuleId, RuleId, StringComparison.Ordinal)
                || !string.Equals(first.Operation, Operation, StringComparison.Ordinal)
                || !string.Equals(second.Operation, Operation, StringComparison.Ordinal))
                return Deny(OAuthDeviceFlowAuditCandidateStatus.WrongRuleOrOperation,
                    "R275_AUDIT_RULE_OR_OPERATION_MISMATCH");

            if (observedFlow == null
                || !observedFlow.IsTcp
                || observedFlow.DestinationPort != 443
                || observedFlow.SourcePort is not (> 0 and <= 65535)
                || !IPAddress.TryParse(observedFlow.Source, out var client)
                || !IPAddress.TryParse(observedFlow.Destination, out var idp))
                return Deny(OAuthDeviceFlowAuditCandidateStatus.MissingNetworkObservation,
                    "R275_CAPTURE_CORROBORATION_UNAVAILABLE");

            if (!Matches(first.SourceIp, client)
                || !Matches(first.DestinationIp, idp)
                || !Matches(second.SourceIp, client)
                || !Matches(second.DestinationIp, idp))
                return Deny(OAuthDeviceFlowAuditCandidateStatus.NetworkEndpointMismatch,
                    "R275_VERIFIED_AUDIT_ENDPOINT_MISMATCH");

            if (observedFlowUtc.Offset != TimeSpan.Zero
                || !Within(first.OccurredAtUtc, observedFlowUtc)
                || !Within(second.OccurredAtUtc, observedFlowUtc))
                return Deny(OAuthDeviceFlowAuditCandidateStatus.NetworkClockMismatch,
                    "R275_VERIFIED_AUDIT_NETWORK_TIME_MISMATCH");

            // The two signed receipts prove only that configured producers
            // attested the same privacy-minimized abuse event. The packet binds
            // endpoint/time metadata but does not prove user intent. A separate
            // reviewed integration is required before R275 can consume this.
            return Deny(OAuthDeviceFlowAuditCandidateStatus.CorrelatedCandidateNotIntegrated,
                "R275_SIGNED_IDP_AUDIT_CANDIDATE_NOT_INTEGRATED");
        }

        private static bool Within(DateTimeOffset audit, DateTimeOffset observed)
            => (audit - observed).Duration() <= MaxNetworkAuditOffset;

        private static bool Matches(string auditAddress, IPAddress observed)
            => IPAddress.TryParse(auditAddress, out var address)
                && address.Equals(observed);

        private static OAuthDeviceFlowAuditCandidateAssessment Deny(
            OAuthDeviceFlowAuditCandidateStatus status, string reason)
            => new(status, reason);
    }
}
