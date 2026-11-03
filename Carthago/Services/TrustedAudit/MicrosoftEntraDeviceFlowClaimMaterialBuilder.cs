// SPDX-License-Identifier: MIT
// R275 authenticated Entra + packet correlation material.
// SOURCE CANDIDATE — UNVERIFIED. No signing key and no alert capability.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// Privacy-minimized material that a separately managed signer may review
    /// before creating an R275 AuditClaim. It is deliberately unsigned and
    /// cannot be used as a VerifiedAuditReceipt.
    /// </summary>
    public sealed class MicrosoftEntraDeviceFlowClaimMaterial
    {
        internal MicrosoftEntraDeviceFlowClaimMaterial(
            DateTimeOffset occurredAtUtc,
            string sourceIp,
            string destinationIp,
            string actorHash,
            string resourceHash,
            string traceHash,
            string identityHost)
        {
            OccurredAtUtc = occurredAtUtc;
            SourceIp = sourceIp;
            DestinationIp = destinationIp;
            ActorHash = actorHash;
            ResourceHash = resourceHash;
            TraceHash = traceHash;
            IdentityHost = identityHost;
        }

        public DateTimeOffset OccurredAtUtc { get; }
        public string SourceIp { get; }
        public string DestinationIp { get; }
        public string ActorHash { get; }
        public string ResourceHash { get; }
        public string TraceHash { get; }
        // Host is retained only for signer policy review. It is never copied
        // into AuditClaim or rule evidence.
        public string IdentityHost { get; }
    }

    /// <summary>
    /// Correlates one authenticated Microsoft Entra observation with one
    /// independently captured identity TLS flow. This is the only place in the
    /// current R275 producer path where the IdP destination IP is introduced,
    /// and it comes from packet capture rather than provider JSON.
    /// </summary>
    public sealed class MicrosoftEntraDeviceFlowClaimMaterialBuilder
    {
        private static readonly TimeSpan MaxSourceToFlowOffset =
            TimeSpan.FromMinutes(2);
        private readonly string[] _approvedIdentityHosts;

        public MicrosoftEntraDeviceFlowClaimMaterialBuilder(
            IEnumerable<string> approvedIdentityHosts)
        {
            if (approvedIdentityHosts == null)
                throw new ArgumentNullException(nameof(approvedIdentityHosts));

            _approvedIdentityHosts = approvedIdentityHosts
                .Select(NormalizeHost)
                .Where(host => host.Length > 0)
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            if (_approvedIdentityHosts.Length == 0)
                throw new ArgumentException(
                    "At least one approved identity host is required.",
                    nameof(approvedIdentityHosts));
        }

        public bool TryBuild(
            MicrosoftEntraDeviceCodeAuditObservation? observation,
            TrafficRecord? observedFlow,
            DateTimeOffset observedFlowUtc,
            out MicrosoftEntraDeviceFlowClaimMaterial? material,
            out string reason)
        {
            material = null;
            reason = "INVALID_R275_CLAIM_MATERIAL_INPUT";

            if (observation == null || !observation.FromTrustedProviderTransport)
            {
                reason = "R275_ENTRA_TRANSPORT_NOT_AUTHENTICATED";
                return false;
            }

            if (observedFlow == null
                || !observedFlow.IsTcp
                || observedFlow.DestinationPort != 443
                || observedFlow.SourcePort is not (> 0 and <= 65535)
                || !IPAddress.TryParse(observedFlow.Source, out var client)
                || !IPAddress.TryParse(observedFlow.Destination, out var idp)
                || IPAddress.IsLoopback(client)
                || IPAddress.IsLoopback(idp)
                || client.Equals(idp))
            {
                reason = "R275_CAPTURE_CORROBORATION_UNAVAILABLE";
                return false;
            }

            if (!IPAddress.TryParse(observation.SourceIp, out var source)
                || !source.Equals(client))
            {
                reason = "R275_ENTRA_CAPTURE_SOURCE_MISMATCH";
                return false;
            }

            if (observedFlowUtc.Offset != TimeSpan.Zero
                || observation.OccurredAtUtc.Offset != TimeSpan.Zero
                || (observation.OccurredAtUtc - observedFlowUtc).Duration()
                    > MaxSourceToFlowOffset)
            {
                reason = "R275_ENTRA_CAPTURE_TIME_MISMATCH";
                return false;
            }

            var host = ExtractIdentityHost(observedFlow);
            if (host.Length == 0 || !IsApprovedHost(host))
            {
                reason = "R275_IDENTITY_HOST_NOT_APPROVED";
                return false;
            }

            material = new MicrosoftEntraDeviceFlowClaimMaterial(
                observation.OccurredAtUtc,
                source.ToString(),
                idp.ToString(),
                observation.ActorHash,
                observation.ResourceHash,
                observation.TraceHash,
                host);
            reason = "R275_UNSIGNED_CLAIM_MATERIAL_READY_FOR_EXTERNAL_SIGNER";
            return true;
        }

        private bool IsApprovedHost(string host)
            => _approvedIdentityHosts.Any(approved =>
                string.Equals(host, approved, StringComparison.Ordinal)
                || host.EndsWith("." + approved, StringComparison.Ordinal));

        private static string ExtractIdentityHost(TrafficRecord record)
        {
            var host = FirstNonEmpty(record.Sni, record.TlsSni, record.HttpHost);
            return NormalizeHost(host);
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
                    || c == '-' || c == '.')))
                return string.Empty;
            return normalized;
        }
    }
}
