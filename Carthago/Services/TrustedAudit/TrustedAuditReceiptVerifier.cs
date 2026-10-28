// SPDX-License-Identifier: MIT
// File: Services/TrustedAudit/TrustedAuditReceiptVerifier.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// Trust anchors MUST come from operator-controlled configuration, never
    /// packet metadata, replay JSON, or the unsigned audit envelope itself.
    /// Only the SubjectPublicKeyInfo DER (not any private key) is stored here.
    /// </summary>
    public sealed record TrustedAuditIssuer(
        string IssuerId,
        string PublicKeySpkiBase64,
        IReadOnlyCollection<string> AllowedRuleIds);

    public sealed record SignedAuditEnvelope(
        string IssuerId,
        string PayloadBase64,
        string SignatureBase64);

    /// <summary>
    /// A deliberately narrow, immutable capability. The only constructor is
    /// internal: unverified fixture fields cannot directly create one.
    /// This contract does NOT itself permit a detection or policy promotion.
    /// </summary>
    public sealed class VerifiedAuditReceipt
    {
        internal VerifiedAuditReceipt(AuditClaim claim)
        {
            IssuerId = claim.IssuerId;
            RuleId = claim.RuleId;
            EvidenceId = claim.EvidenceId;
            OccurredAtUtc = claim.OccurredAtUtc;
            Operation = claim.Operation;
            SourceIp = claim.SourceIp;
            DestinationIp = claim.DestinationIp;
            ActorHash = claim.ActorHash;
            ResourceHash = claim.ResourceHash;
            TraceHash = claim.TraceHash;
        }

        public string IssuerId { get; }
        public string RuleId { get; }
        public Guid EvidenceId { get; }
        public DateTimeOffset OccurredAtUtc { get; }
        public string Operation { get; }
        public string SourceIp { get; }
        public string DestinationIp { get; }
        public string ActorHash { get; }
        public string ResourceHash { get; }
        // Correlation key must originate from the audit producer. IP/time
        // coincidence alone cannot bind a receipt to a network observation.
        public string TraceHash { get; }
    }

    /// <summary>
    /// Signed, metadata-only audit statement. Raw command lines, OAuth codes,
    /// Kubernetes exec streams, JWTs and bearer tokens are NOT part of this
    /// contract. Producer-specific parsing and authorization remain separate.
    /// </summary>
    public sealed class AuditClaim
    {
        public string IssuerId { get; set; } = "";
        public string RuleId { get; set; } = "";
        public Guid EvidenceId { get; set; }
        public DateTimeOffset OccurredAtUtc { get; set; }
        public string Operation { get; set; } = "";
        public string SourceIp { get; set; } = "";
        public string DestinationIp { get; set; } = "";
        public string ActorHash { get; set; } = "";
        public string ResourceHash { get; set; } = "";
        public string TraceHash { get; set; } = "";
    }

    /// <summary>
    /// RSA-PSS/SHA-256 attestation verifier with domain separation, explicit
    /// rule/operation scopes, freshness, and a bounded fail-closed replay cache.
    /// No global ambient trust and no automatic binding to TrafficRecord.
    /// </summary>
    public sealed class TrustedAuditReceiptVerifier
    {
        private const string Domain = "CARTHAGO-TRUSTED-AUDIT-V1\n";
        private const int MaxPayloadBytes = 4096;
        private const int MaxEnvelopeChars = 8192;
        private const int MaxSeenEvents = 8192;
        private static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan MaxFutureSkew = TimeSpan.FromMinutes(2);
        private static readonly byte[] DomainBytes = Encoding.ASCII.GetBytes(Domain);
        private static readonly IReadOnlyDictionary<string, string> RuleOperations =
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["R343"] = "WinRmEncodedCommandExecuted",
                ["R295"] = "KubernetesPodExecAuthorized",
                ["R275"] = "OAuthDeviceFlowAbuseConfirmed",
                ["R163"] = "HttpMetadataRequestCausallyLinked"
            };

        private readonly Dictionary<string, (byte[] PublicKey, HashSet<string> AllowedRules)> _issuers =
            new(StringComparer.Ordinal);
        private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
        private readonly object _replayGate = new();
        private readonly Func<DateTimeOffset> _now;

        public TrustedAuditReceiptVerifier(
            IEnumerable<TrustedAuditIssuer> trustedIssuers,
            Func<DateTimeOffset>? utcClock = null)
        {
            if (trustedIssuers == null) throw new ArgumentNullException(nameof(trustedIssuers));
            _now = utcClock ?? (() => DateTimeOffset.UtcNow);
            foreach (var issuer in trustedIssuers)
            {
                if (issuer == null || !ValidIssuerId(issuer.IssuerId)
                    || string.IsNullOrWhiteSpace(issuer.PublicKeySpkiBase64)
                    || issuer.AllowedRuleIds == null)
                    throw new ArgumentException("Invalid audit trust anchor.", nameof(trustedIssuers));
                byte[] key;
                try
                {
                    key = Convert.FromBase64String(issuer.PublicKeySpkiBase64);
                    using var rsa = RSA.Create();
                    rsa.ImportSubjectPublicKeyInfo(key, out var consumed);
                    if (consumed != key.Length || rsa.KeySize < 2048)
                        throw new CryptographicException("Unsupported signing key.");
                }
                catch (Exception e) when (e is FormatException or CryptographicException or ArgumentException)
                {
                    throw new ArgumentException("Invalid RSA public key in audit trust anchor.", nameof(trustedIssuers), e);
                }
                var allowed = issuer.AllowedRuleIds.ToHashSet(StringComparer.Ordinal);
                if (allowed.Count == 0 || allowed.Any(rule => !RuleOperations.ContainsKey(rule))
                    || !_issuers.TryAdd(issuer.IssuerId, (key, allowed)))
                    throw new ArgumentException("Invalid or duplicate audit issuer scope.", nameof(trustedIssuers));
            }
            if (_issuers.Count == 0)
                throw new ArgumentException("At least one trusted audit issuer is required.", nameof(trustedIssuers));
        }

        public bool TryVerify(SignedAuditEnvelope? envelope,
            out VerifiedAuditReceipt? verified, out string reason)
        {
            verified = null;
            reason = "INVALID_ENVELOPE";
            if (envelope == null || !ValidIssuerId(envelope.IssuerId)
                || !_issuers.TryGetValue(envelope.IssuerId, out var authority)
                || string.IsNullOrEmpty(envelope.PayloadBase64)
                || string.IsNullOrEmpty(envelope.SignatureBase64)
                || envelope.PayloadBase64.Length > MaxEnvelopeChars
                || envelope.SignatureBase64.Length > MaxEnvelopeChars)
                return false;

            byte[] payload, signature;
            try
            {
                payload = Convert.FromBase64String(envelope.PayloadBase64);
                signature = Convert.FromBase64String(envelope.SignatureBase64);
            }
            catch (FormatException)
            {
                return false;
            }
            if (payload.Length is < 2 or > MaxPayloadBytes || signature.Length is < 256 or > 1024)
                return false;

            var signedData = new byte[DomainBytes.Length + payload.Length];
            DomainBytes.CopyTo(signedData, 0);
            payload.CopyTo(signedData, DomainBytes.Length);
            try
            {
                using var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(authority.PublicKey, out _);
                if (!rsa.VerifyData(signedData, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                {
                    reason = "INVALID_SIGNATURE";
                    return false;
                }
            }
            catch (CryptographicException)
            {
                reason = "INVALID_SIGNATURE";
                return false;
            }

            AuditClaim? claim;
            try
            {
                using var json = JsonDocument.Parse(payload, new JsonDocumentOptions
                {
                    MaxDepth = 3,
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow
                });
                if (json.RootElement.ValueKind != JsonValueKind.Object)
                    return false;
                // Reject ambiguous duplicate or unexpected properties even
                // when the bytes carry a valid signature.
                var seenNames = new HashSet<string>(StringComparer.Ordinal);
                var allowedNames = new HashSet<string>(StringComparer.Ordinal)
                {
                    nameof(AuditClaim.IssuerId), nameof(AuditClaim.RuleId),
                    nameof(AuditClaim.EvidenceId), nameof(AuditClaim.OccurredAtUtc),
                    nameof(AuditClaim.Operation), nameof(AuditClaim.SourceIp),
                    nameof(AuditClaim.DestinationIp), nameof(AuditClaim.ActorHash),
                    nameof(AuditClaim.ResourceHash), nameof(AuditClaim.TraceHash)
                };
                foreach (var prop in json.RootElement.EnumerateObject())
                    if (!seenNames.Add(prop.Name) || !allowedNames.Contains(prop.Name))
                        return false;
                if (seenNames.Count != allowedNames.Count)
                    return false;
                claim = json.RootElement.Deserialize<AuditClaim>();
            }
            catch (Exception e) when (e is JsonException or ArgumentException or FormatException)
            {
                return false;
            }
            if (claim == null || !string.Equals(claim.IssuerId, envelope.IssuerId, StringComparison.Ordinal)
                || !authority.AllowedRules.Contains(claim.RuleId)
                || !RuleOperations.TryGetValue(claim.RuleId, out var operation)
                || !string.Equals(claim.Operation, operation, StringComparison.Ordinal)
                || claim.EvidenceId == Guid.Empty
                || claim.OccurredAtUtc == default
                || claim.OccurredAtUtc.Offset != TimeSpan.Zero
                || !ValidIpPair(claim.SourceIp, claim.DestinationIp)
                || !ValidHash(claim.ActorHash) || !ValidHash(claim.ResourceHash)
                || !ValidHash(claim.TraceHash))
            {
                reason = "INVALID_CLAIM";
                return false;
            }

            var age = _now() - claim.OccurredAtUtc;
            if (age > MaxAge || age < -MaxFutureSkew)
            {
                reason = "STALE_OR_FUTURE_AUDIT";
                return false;
            }

            lock (_replayGate)
            {
                // Saturation does NOT silently evict recent event IDs and
                // permit duplicates. The owner must rotate the verifier
                // instance with operator-controlled trust configuration.
                if (_seen.Count >= MaxSeenEvents ||
                    !_seen.Add(claim.IssuerId + ":" + claim.EvidenceId.ToString("N")))
                {
                    reason = "REPLAY_OR_CAPACITY";
                    return false;
                }
            }
            verified = new VerifiedAuditReceipt(claim);
            reason = "VERIFIED";
            return true;
        }

        public static byte[] SigningBytes(ReadOnlySpan<byte> claimPayload)
        {
            if (claimPayload.Length is < 2 or > MaxPayloadBytes)
                throw new ArgumentOutOfRangeException(nameof(claimPayload));
            var buffer = new byte[DomainBytes.Length + claimPayload.Length];
            DomainBytes.CopyTo(buffer, 0);
            claimPayload.CopyTo(buffer.AsSpan(DomainBytes.Length));
            return buffer;
        }

        private static bool ValidIssuerId(string? value)
            => value is { Length: >= 3 and <= 64 }
                && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');

        private static bool ValidIpPair(string? source, string? destination)
            => IPAddress.TryParse(source, out var a)
                && IPAddress.TryParse(destination, out var b)
                && a.AddressFamily == b.AddressFamily && !a.Equals(b)
                && !IPAddress.IsLoopback(a) && !IPAddress.IsLoopback(b);

        private static bool ValidHash(string? value)
            => value is { Length: 64 }
                && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    }
}
