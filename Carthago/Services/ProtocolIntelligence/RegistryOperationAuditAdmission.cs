// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated, bounded registry-exporter audit admission for R304-R306.
    /// HMAC proves possession of a configured key, NOT the identity of the
    /// registry, absence of authentication, workstation role or upload content.
    /// No detector or runtime ingestion is enabled by this component.
    /// </summary>
    public sealed class RegistryOperationAuditAdmission
    {
        private const int Capacity = 4096;
        private readonly object _gate = new();
        private readonly Dictionary<string, DateTime> _seen = new(StringComparer.Ordinal);
        private DateTime _watermark = DateTime.MinValue;

        public bool TryAdmit(RegistryAuditCandidate? candidate, ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> signature, DateTime nowUtc, out RegistryAuditObservation observation)
        {
            observation = default;
            if (candidate is null || key.Length < 32 || signature.Length != 32 ||
                nowUtc.Kind != DateTimeKind.Utc || candidate.TimestampUtc.Kind != DateTimeKind.Utc ||
                candidate.TimestampUtc > nowUtc.AddMinutes(2) ||
                candidate.TimestampUtc < nowUtc.AddMinutes(-10) ||
                !Safe(candidate.EventId, 128) || !Safe(candidate.RegistryId, 128) ||
                !Safe(candidate.ActorId, 128) || !Safe(candidate.Repository, 256) ||
                !Safe(candidate.Operation, 16) ||
                (candidate.Operation != "pull" && candidate.Operation != "push" &&
                 candidate.Operation != "build-context") ||
                candidate.HttpStatus is < 100 or > 599 ||
                !Safe(candidate.AuthenticatedActor, 8) ||
                (candidate.AuthenticatedActor != "yes" && candidate.AuthenticatedActor != "no" &&
                 candidate.AuthenticatedActor != "unknown"))
                return false;

            static string Field(string value) => value.Length.ToString(CultureInfo.InvariantCulture) + ":" + value;
            string payload = string.Join("|", new[] {
                Field(candidate.EventId), Field(candidate.RegistryId), Field(candidate.ActorId),
                Field(candidate.Repository), Field(candidate.Operation),
                Field(candidate.AuthenticatedActor),
                candidate.HttpStatus.ToString(CultureInfo.InvariantCulture),
                candidate.TimestampUtc.Ticks.ToString(CultureInfo.InvariantCulture)
            });
            byte[] bytes = Encoding.UTF8.GetBytes("carthago-registry-audit-v1|" + payload);
            byte[] digest = HMACSHA256.HashData(key, bytes);
            bool valid = CryptographicOperations.FixedTimeEquals(digest, signature);
            CryptographicOperations.ZeroMemory(digest);
            CryptographicOperations.ZeroMemory(bytes);
            if (!valid) return false;

            lock (_gate)
            {
                // Replay rejection precedes watermark advancement, even for
                // signed future-dated duplicate events.
                string replayId = candidate.RegistryId + "|" + candidate.EventId;
                if (_seen.ContainsKey(replayId)) return false;
                DateTime next = candidate.TimestampUtc > _watermark
                    ? candidate.TimestampUtc : _watermark;
                DateTime cutoff = next.AddMinutes(-10);
                if (candidate.TimestampUtc < cutoff) return false;
                // Saturation fails closed. Never evict replay identities to
                // admit a newer event without a persistent replay journal.
                if (_seen.Count >= Capacity) return false;
                _seen.Add(replayId, candidate.TimestampUtc);
                _watermark = next;
                observation = new RegistryAuditObservation(candidate.Operation,
                    candidate.HttpStatus >= 200 && candidate.HttpStatus < 300,
                    candidate.AuthenticatedActor == "yes",
                    candidate.AuthenticatedActor == "no",
                    candidate.TimestampUtc);
                return true;
            }
        }

        private static bool Safe(string? value, int max) =>
            !string.IsNullOrWhiteSpace(value) && value.Length <= max &&
            value.IndexOfAny(new[] { '\r', '\n', '\0', '|' }) < 0;
    }

    public sealed record RegistryAuditCandidate(
        string EventId, string RegistryId, string ActorId, string Repository,
        string Operation, string AuthenticatedActor, int HttpStatus, DateTime TimestampUtc);

    public readonly record struct RegistryAuditObservation(
        string Operation, bool HttpAccepted, bool AuthenticatedActor,
        bool ExplicitlyUnauthenticated, DateTime TimestampUtc);
}
