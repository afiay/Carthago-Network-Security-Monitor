// SPDX-License-Identifier: MIT
// R275 opaque rule-evaluation capability.
// SOURCE CANDIDATE — UNVERIFIED. Internal-only and non-alerting.
using System;
using System.Linq;
using Carthago.Models;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// Opaque in-process capability proving that one exact TrafficRecord has
    /// already passed the independently signed R275 audit + packet gate.
    ///
    /// The constructor is private and the type is internal. Public packet
    /// callers cannot mint or attach this capability. It is also bound to a
    /// snapshot of the exact TrafficRecord instance and observed UTC timestamp,
    /// preventing reuse on a different or subsequently mutated record.
    /// </summary>
    internal sealed class OAuthDeviceFlowRuleCapability
    {
        private readonly TrafficRecord _boundRecord;
        private readonly string? _source;
        private readonly string? _destination;
        private readonly int? _sourcePort;
        private readonly int? _destinationPort;
        private readonly bool _isTcp;
        private readonly string? _applicationProtocol;
        private readonly string? _sni;
        private readonly string? _tlsSni;
        private readonly string? _httpHost;

        private OAuthDeviceFlowRuleCapability(
            CorrelatedAuditReceipts pair,
            TrafficRecord record,
            DateTimeOffset observedFlowUtc)
        {
            _boundRecord = record;
            _source = record.Source;
            _destination = record.Destination;
            _sourcePort = record.SourcePort;
            _destinationPort = record.DestinationPort;
            _isTcp = record.IsTcp;
            _applicationProtocol = record.ApplicationProtocol;
            _sni = record.Sni;
            _tlsSni = record.TlsSni;
            _httpHost = record.HttpHost;

            ObservedFlowUtc = observedFlowUtc;
            TraceHash = pair.First.TraceHash;
            FirstIssuerId = pair.First.IssuerId;
            SecondIssuerId = pair.Second.IssuerId;
            IdentityHost = NormalizeHost(
                FirstNonEmpty(record.Sni, record.TlsSni, record.HttpHost));
        }

        internal DateTimeOffset ObservedFlowUtc { get; }
        internal string TraceHash { get; }
        internal string FirstIssuerId { get; }
        internal string SecondIssuerId { get; }
        internal string IdentityHost { get; }

        internal static bool TryCreate(
            CorrelatedAuditReceipts? pair,
            TrafficRecord? observedFlow,
            DateTimeOffset observedFlowUtc,
            out OAuthDeviceFlowRuleCapability? capability,
            out string reason)
        {
            capability = null;

            var assessment = OAuthDeviceFlowAuditCandidateGate.Assess(
                pair, observedFlow, observedFlowUtc);

            if (assessment.Status
                != OAuthDeviceFlowAuditCandidateStatus.CorrelatedCandidateNotIntegrated
                || pair == null
                || observedFlow == null)
            {
                reason = assessment.Reason;
                return false;
            }

            capability = new OAuthDeviceFlowRuleCapability(
                pair, observedFlow, observedFlowUtc);
            reason = "R275_RULE_CAPABILITY_READY_NONALERTING";
            return true;
        }

        internal bool IsBoundTo(
            TrafficRecord record,
            DateTime normalizedTimestampUtc)
        {
            if (!ReferenceEquals(record, _boundRecord)
                || normalizedTimestampUtc.Kind != DateTimeKind.Utc
                || normalizedTimestampUtc != ObservedFlowUtc.UtcDateTime)
                return false;

            return string.Equals(record.Source, _source, StringComparison.Ordinal)
                && string.Equals(record.Destination, _destination, StringComparison.Ordinal)
                && record.SourcePort == _sourcePort
                && record.DestinationPort == _destinationPort
                && record.IsTcp == _isTcp
                && string.Equals(record.ApplicationProtocol, _applicationProtocol,
                    StringComparison.Ordinal)
                && string.Equals(record.Sni, _sni, StringComparison.Ordinal)
                && string.Equals(record.TlsSni, _tlsSni, StringComparison.Ordinal)
                && string.Equals(record.HttpHost, _httpHost, StringComparison.Ordinal);
        }

        private static string FirstNonEmpty(params string?[] values)
        {
            foreach (var value in values)
                if (!string.IsNullOrWhiteSpace(value))
                    return value;
            return string.Empty;
        }

        private static string NormalizeHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host))
                return string.Empty;
            var normalized = host.Trim().TrimEnd('.').ToLowerInvariant();
            if (normalized.Length is < 1 or > 253
                || normalized.StartsWith(".", StringComparison.Ordinal)
                || normalized.EndsWith(".", StringComparison.Ordinal)
                || normalized.Contains("..", StringComparison.Ordinal)
                || normalized.Any(c => !(char.IsAsciiLetterOrDigit(c)
                    || c is '-' or '.')))
                return string.Empty;
            return normalized;
        }
    }
}
