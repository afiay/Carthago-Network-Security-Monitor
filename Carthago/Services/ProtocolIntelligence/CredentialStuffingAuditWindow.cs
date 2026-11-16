// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated, operator-keyed authentication-audit verification boundary for R279.
    /// No TrafficRecord text or HTTP header is a trusted authentication outcome.
    /// This contract is not wired into R279 and does not authorize an alert.
    /// </summary>
    public sealed class CredentialStuffingAuditWindow
    {
        public const int Capacity = 4096;
        private static readonly TimeSpan Window = TimeSpan.FromMinutes(20);
        private readonly object _gate = new();
        private readonly Dictionary<string, AuditEvent> _events = new(StringComparer.Ordinal);
        private DateTime _watermark = DateTime.MinValue;
        private readonly record struct AuditEvent(string Source, string Destination,
            string AccountDigest, string AgentDigest, DateTime Timestamp);

        /// <summary>
        /// Canonical authenticated fields supplied by a trusted audit exporter:
        /// source, destination, account digest, user-agent digest, event id and UTC timestamp.
        /// Signature is HMAC-SHA256 over the length-delimited UTF-8 representation.
        /// The caller must provision and protect the exporter key out of band.
        /// </summary>
        public static byte[] SignForExporter(string source, string destination,
            string accountDigest, string agentDigest, string eventId,
            DateTime timestampUtc, ReadOnlySpan<byte> key)
        {
            if (!Valid(source) || !Valid(destination) || !Valid(accountDigest) ||
                !Valid(agentDigest) || !Valid(eventId) ||
                timestampUtc.Kind != DateTimeKind.Utc || key.Length < 32)
                throw new ArgumentException("Invalid audit signing material.");
            using var hmac = new HMACSHA256(key.ToArray());
            return hmac.ComputeHash(Encoding.UTF8.GetBytes(Canonical(
                source, destination, accountDigest, agentDigest, eventId, timestampUtc)));
        }

        public bool TryObserveFailure(string source, string destination,
            string accountDigest, string agentDigest, string eventId,
            DateTime timestampUtc, ReadOnlySpan<byte> signature,
            ReadOnlySpan<byte> exporterKey, out int distinctAccounts,
            out int distinctAgents)
        {
            distinctAccounts = distinctAgents = 0;
            if (!Valid(source) || !Valid(destination) || !Valid(accountDigest) ||
                !Valid(agentDigest) || !Valid(eventId) ||
                timestampUtc.Kind != DateTimeKind.Utc ||
                signature.Length != 32 || exporterKey.Length < 32)
                return false;
            byte[] expected = SignForExporter(source, destination,
                accountDigest, agentDigest, eventId, timestampUtc, exporterKey);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(expected, signature))
                    return false;
            }
            finally { CryptographicOperations.ZeroMemory(expected); }
            lock (_gate)
            {
                if (timestampUtc < _watermark || _events.ContainsKey(eventId))
                    return false;
                DateTime lower = timestampUtc.Ticks < Window.Ticks
                    ? DateTime.MinValue : timestampUtc - Window;
                // Fail closed on capacity, never evict unexpired events to admit new ones.
                if (_events.Count >= Capacity) return false;
                _watermark = timestampUtc;
                foreach (var old in _events.Where(x => x.Value.Timestamp < lower)
                    .Select(x => x.Key).ToArray()) _events.Remove(old);
                _events.Add(eventId, new AuditEvent(source, destination,
                    accountDigest, agentDigest, timestampUtc));
                var group = _events.Values.Where(x =>
                    x.Source == source && x.Destination == destination);
                distinctAccounts = group.Select(x => x.AccountDigest).Distinct(StringComparer.Ordinal).Count();
                distinctAgents = group.Select(x => x.AgentDigest).Distinct(StringComparer.Ordinal).Count();
                return true;
            }
        }

        private static bool Valid(string? value) =>
            !string.IsNullOrWhiteSpace(value) && value.Length <= 256 &&
            !value.Any(char.IsControl);
        private static string Canonical(params object[] fields) =>
            string.Concat(fields.Select(x => {
                string s = x is DateTime d ? d.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    : (string)x;
                return s.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + s;
            }));
    }
}
