// SPDX-License-Identifier: MIT
// File: Services/TrustedAudit/TrustedAuditReceiptCorrelation.cs
using System;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// A strict association between two independently signed receipts that
    /// were verified by the SAME configured trust registry. Correlation alone
    /// does not prove a phishing action, SSRF, exec outcome or attack intent.
    /// </summary>
    public sealed class CorrelatedAuditReceipts
    {
        internal CorrelatedAuditReceipts(VerifiedAuditReceipt first, VerifiedAuditReceipt second)
        {
            First = first;
            Second = second;
        }

        public VerifiedAuditReceipt First { get; }
        public VerifiedAuditReceipt Second { get; }
    }

    public static class TrustedAuditReceiptCorrelation
    {
        private static readonly TimeSpan MaxSourceSkew = TimeSpan.FromMinutes(2);

        /// <summary>
        /// Rejects cross-issuer spoofing, cross-registry evidence mixing,
        /// mismatched pseudonymous actor/asset/trace keys, and stale ordering.
        /// Both inputs must already have passed RSA-PSS verification and the
        /// individual replay cache; this method cannot authenticate a source.
        /// </summary>
        public static bool TryCorrelate(
            VerifiedAuditReceipt? first,
            VerifiedAuditReceipt? second,
            out CorrelatedAuditReceipts? association,
            out string reason)
        {
            association = null;
            reason = "MISSING_VERIFIED_RECEIPT";
            if (first == null || second == null)
                return false;

            if (first.TrustRegistryInstanceId != second.TrustRegistryInstanceId)
            {
                reason = "UNRELATED_TRUST_REGISTRIES";
                return false;
            }
            if (string.Equals(first.IssuerId, second.IssuerId, StringComparison.Ordinal)
                || first.EvidenceId == second.EvidenceId)
            {
                reason = "NON_INDEPENDENT_AUDIT_RECEIPTS";
                return false;
            }

            if (!string.Equals(first.RuleId, second.RuleId, StringComparison.Ordinal)
                || !string.Equals(first.Operation, second.Operation, StringComparison.Ordinal)
                || !string.Equals(first.ActorHash, second.ActorHash, StringComparison.Ordinal)
                || !string.Equals(first.ResourceHash, second.ResourceHash, StringComparison.Ordinal)
                || !string.Equals(first.TraceHash, second.TraceHash, StringComparison.Ordinal)
                || !string.Equals(first.SourceIp, second.SourceIp, StringComparison.Ordinal)
                || !string.Equals(first.DestinationIp, second.DestinationIp, StringComparison.Ordinal)
                || (first.OccurredAtUtc - second.OccurredAtUtc).Duration() > MaxSourceSkew)
            {
                reason = "AUDIT_SUBJECT_OR_TRACE_MISMATCH";
                return false;
            }

            association = new CorrelatedAuditReceipts(first, second);
            reason = "CORRELATED_NOT_AUTHORIZED_FOR_ALERT";
            return true;
        }
    }
}
