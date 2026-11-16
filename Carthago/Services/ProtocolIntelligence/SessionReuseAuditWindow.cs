// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated signed session-use audit contract for R280. An exporter key
    /// authenticates transport provenance only; operator-approved exporter identity,
    /// session semantics and geolocation integrity remain external prerequisites.
    /// Not wired to the detector and never an alert authorization.
    /// </summary>
    public sealed class SessionReuseAuditWindow
    {
        public const int Capacity = 4096;
        private static readonly TimeSpan Window = TimeSpan.FromMinutes(30);
        private readonly object _gate = new();
        private readonly Dictionary<string, Observation> _events = new(StringComparer.Ordinal);
        private DateTime _watermark = DateTime.MinValue;

        private readonly record struct Observation(string Account, string Token,
            string Country, string Source, string Destination, DateTime Timestamp);

        public static byte[] SignForExporter(string eventId, string accountDigest,
            string tokenDigest, string source, string destination, string country,
            bool authenticatedSessionAccepted, DateTime timestampUtc,
            ReadOnlySpan<byte> key)
        {
            if (!Valid(eventId) || !Valid(accountDigest) || !Valid(tokenDigest) ||
                !Valid(source) || !Valid(destination) || !Valid(country) ||
                timestampUtc.Kind != DateTimeKind.Utc || key.Length < 32)
                throw new ArgumentException("Invalid signed session audit.");
            using var hmac = new HMACSHA256(key.ToArray());
            return hmac.ComputeHash(Encoding.UTF8.GetBytes(Canonical(
                "R280-session-use-v1", eventId, accountDigest, tokenDigest, source,
                destination, country.ToUpperInvariant(),
                authenticatedSessionAccepted ? "accepted" : "rejected",
                timestampUtc.Ticks.ToString(CultureInfo.InvariantCulture))));
        }

        public bool TryObserve(string eventId, string accountDigest,
            string tokenDigest, string source, string destination, string country,
            bool authenticatedSessionAccepted, DateTime timestampUtc,
            ReadOnlySpan<byte> signature, ReadOnlySpan<byte> exporterKey,
            out int distinctCountries)
        {
            distinctCountries = 0;
            if (!authenticatedSessionAccepted || !Valid(eventId) ||
                !Valid(accountDigest) || !Valid(tokenDigest) || !Valid(source) ||
                !Valid(destination) || !Valid(country) ||
                timestampUtc.Kind != DateTimeKind.Utc ||
                signature.Length != 32 || exporterKey.Length < 32)
                return false;
            byte[] expected = SignForExporter(eventId, accountDigest, tokenDigest,
                source, destination, country, authenticatedSessionAccepted,
                timestampUtc, exporterKey);
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
                // Capacity is deliberately checked before cleanup: a saturated
                // audit stream must not silently evict replay IDs to admit traffic.
                if (_events.Count >= Capacity) return false;
                foreach (var id in _events.Where(x => x.Value.Timestamp < lower)
                    .Select(x => x.Key).ToArray()) _events.Remove(id);
                _watermark = timestampUtc;
                string normalizedCountry = country.ToUpperInvariant();
                _events.Add(eventId, new Observation(accountDigest, tokenDigest,
                    normalizedCountry, source, destination, timestampUtc));
                distinctCountries = _events.Values.Where(x =>
                    x.Account == accountDigest && x.Token == tokenDigest &&
                    x.Destination == destination)
                    .Select(x => x.Country).Distinct(StringComparer.Ordinal).Count();
                return true;
            }
        }

        private static bool Valid(string? value) =>
            !string.IsNullOrWhiteSpace(value) && value.Length <= 256 &&
            !value.Any(char.IsControl);

        private static string Canonical(params string[] fields) =>
            string.Concat(fields.Select(s =>
                s.Length.ToString(CultureInfo.InvariantCulture) + ":" + s));
    }
}
