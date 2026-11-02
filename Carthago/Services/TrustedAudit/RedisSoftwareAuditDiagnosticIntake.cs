// SPDX-License-Identifier: MIT
// GA R437 — SOURCE CANDIDATE — UNVERIFIED. No live listener or alert path.
using System;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// Opt-in integration point for an external, independently authenticated
    /// collector that can deliver ONE framed, complete Redis Software JSON
    /// notification at a time. The Redis Software TCP sink itself is best effort
    /// and NOT authenticated by this component.
    ///
    /// Diagnostics combine the vendor decoder and bounded per-worker sequence
    /// tracker with PacketHandler's verified RESP2 reply observations. This
    /// component does not sign audit receipts, enable R437, or accept the generic
    /// CONFIG command as proof of CONFIG SET success.
    /// </summary>
    public sealed class RedisSoftwareAuditDiagnosticIntake
    {
        private readonly RedisSoftwareAuditContinuityTracker _continuity = new();
        private readonly ApprovedAssetRegistry _approvals;

        public RedisSoftwareAuditDiagnosticIntake(ApprovedAssetRegistry approvals)
            => _approvals = approvals
                ?? throw new ArgumentNullException(nameof(approvals));

        /// <summary>
        /// Caller must obtain a complete vendor notification from its own
        /// operator-authenticated, bounded framing transport and supply a UTC
        /// packet capture timestamp separately. This is not a trust assertion.
        /// The source ID must come from provisioned collector configuration,
        /// never from JSON fields or packet-provided text.
        /// </summary>
        public RedisSoftwareWireCorrelationAssessment Inspect(
            string provisionedSourceId,
            ReadOnlyMemory<byte> completeVendorNotification,
            TrafficRecord? capturedReply,
            DateTimeOffset capturedReplyUtc)
        {
            if (!RedisSoftwareAuditNotificationParser.TryParse(
                completeVendorNotification, out var observation))
                return new(RedisSoftwareWireCorrelationStatus.MalformedVendorNotification,
                    "R437_VENDOR_AUDIT_MALFORMED");

            var continuity = _continuity.Observe(provisionedSourceId, observation);
            return RedisSoftwareAuditWireCorrelation.Assess(observation,
                continuity, capturedReply, capturedReplyUtc, _approvals);
        }
    }
}
