// SPDX-License-Identifier: MIT
// R275 keyless external-signing request boundary.
// SOURCE CANDIDATE — UNVERIFIED. This file never handles private keys.
using System;
using System.Linq;
using System.Net;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// Immutable, privacy-minimized request material for a separately managed
    /// R275 signer. It contains no private key and cannot produce a signature.
    /// The identity host remains visible for signer-side policy review but is
    /// deliberately not copied into AuditClaim.
    /// </summary>
    public sealed class OAuthDeviceFlowExternalSigningRequest
    {
        public const int CurrentSchemaVersion = 1;

        private OAuthDeviceFlowExternalSigningRequest(
            MicrosoftEntraDeviceFlowClaimMaterial material)
        {
            OccurredAtUtc = material.OccurredAtUtc;
            SourceIp = material.SourceIp;
            DestinationIp = material.DestinationIp;
            ActorHash = material.ActorHash;
            ResourceHash = material.ResourceHash;
            TraceHash = material.TraceHash;
            IdentityHost = material.IdentityHost;
        }

        public int SchemaVersion => CurrentSchemaVersion;
        public string RuleId => OAuthDeviceFlowAuditCandidateGate.RuleId;
        public string Operation => OAuthDeviceFlowAuditCandidateGate.Operation;
        public DateTimeOffset OccurredAtUtc { get; }
        public string SourceIp { get; }
        public string DestinationIp { get; }
        public string ActorHash { get; }
        public string ResourceHash { get; }
        public string TraceHash { get; }
        public string IdentityHost { get; }

        public static bool TryCreate(
            MicrosoftEntraDeviceFlowClaimMaterial? material,
            out OAuthDeviceFlowExternalSigningRequest? request,
            out string reason)
        {
            request = null;
            reason = "INVALID_R275_EXTERNAL_SIGNING_MATERIAL";

            if (material == null
                || material.OccurredAtUtc == default
                || material.OccurredAtUtc.Offset != TimeSpan.Zero
                || !ValidIpPair(material.SourceIp, material.DestinationIp)
                || !ValidHash(material.ActorHash)
                || !ValidHash(material.ResourceHash)
                || !ValidHash(material.TraceHash)
                || !ValidHost(material.IdentityHost))
                return false;

            request = new OAuthDeviceFlowExternalSigningRequest(material);
            reason = "R275_EXTERNAL_SIGNING_REQUEST_READY";
            return true;
        }

        /// <summary>
        /// Creates only the unsigned AuditClaim payload. The external signer
        /// supplies its operator-pinned issuer identity and a unique evidence ID,
        /// then signs the serialized claim with its own out-of-process key.
        /// </summary>
        public bool TryCreateUnsignedAuditClaim(
            string? issuerId,
            Guid evidenceId,
            out AuditClaim? claim,
            out string reason)
        {
            claim = null;
            reason = "INVALID_R275_EXTERNAL_SIGNER_IDENTITY";

            if (!ValidIssuerId(issuerId) || evidenceId == Guid.Empty)
                return false;

            claim = new AuditClaim
            {
                IssuerId = issuerId!,
                RuleId = RuleId,
                EvidenceId = evidenceId,
                OccurredAtUtc = OccurredAtUtc,
                Operation = Operation,
                SourceIp = SourceIp,
                DestinationIp = DestinationIp,
                ActorHash = ActorHash,
                ResourceHash = ResourceHash,
                TraceHash = TraceHash
            };
            reason = "R275_AUDIT_CLAIM_READY_FOR_EXTERNAL_SIGNATURE";
            return true;
        }

        private static bool ValidIssuerId(string? value)
            => value is { Length: >= 3 and <= 64 }
                && value.All(c => char.IsAsciiLetterOrDigit(c)
                    || c is '-' or '_' or '.');

        private static bool ValidIpPair(string? source, string? destination)
            => IPAddress.TryParse(source, out var first)
                && IPAddress.TryParse(destination, out var second)
                && first.AddressFamily == second.AddressFamily
                && !first.Equals(second)
                && !IPAddress.IsLoopback(first)
                && !IPAddress.IsLoopback(second);

        private static bool ValidHash(string? value)
            => value is { Length: 64 }
                && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

        private static bool ValidHost(string? host)
            => host is { Length: >= 1 and <= 253 }
                && !host.StartsWith(".", StringComparison.Ordinal)
                && !host.EndsWith(".", StringComparison.Ordinal)
                && !host.Contains("..", StringComparison.Ordinal)
                && host.All(c => char.IsAsciiLetterOrDigit(c)
                    || c is '-' or '.');
    }
}
