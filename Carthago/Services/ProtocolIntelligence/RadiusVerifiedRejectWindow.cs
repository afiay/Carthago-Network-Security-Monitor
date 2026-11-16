// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// In-memory correlation of distinct secret-verified RADIUS Access-Reject
    /// exchanges. Never exposes credentials, authenticators, attributes or secrets.
    /// NOT evidence of a named user's failed login or NAS authorization outcome;
    /// no live ingestion or R289 detector promotion is implied.
    /// </summary>
    public sealed class RadiusVerifiedRejectWindow
    {
        public const int MaximumObservations = 4096;
        public static readonly TimeSpan Window = TimeSpan.FromMinutes(10);

        private readonly object _sync = new();
        private readonly List<Observation> _observations = new();
        // Retain replay identities beyond the counting window so an old
        // authenticated exchange cannot be replayed as a fresh observation.
        private readonly Dictionary<string, DateTime> _seen = new(StringComparer.Ordinal);
        private DateTime _watermark = DateTime.MinValue;
        public static readonly TimeSpan ReplayRetention = TimeSpan.FromHours(24);

        private readonly record struct Observation(
            string Client, string Server, string Identity, DateTime AtUtc);

        public bool TryObserve(
            ReadOnlySpan<byte> request, string? requestSource, ushort requestSourcePort,
            string? requestDestination, ushort requestDestinationPort,
            ReadOnlySpan<byte> response, string? responseSource, ushort responseSourcePort,
            string? responseDestination, ushort responseDestinationPort,
            ReadOnlySpan<byte> sharedSecret, bool completeUdpPayloads,
            DateTime observedUtc, out RadiusVerifiedRejectSummary summary)
        {
            summary = default;
            if (observedUtc.Kind != DateTimeKind.Utc ||
                !RadiusAccessRejectExchangeVerifier.TryVerify(
                    request, requestSource, requestSourcePort,
                    requestDestination, requestDestinationPort,
                    response, responseSource, responseSourcePort,
                    responseDestination, responseDestinationPort,
                    sharedSecret, completeUdpPayloads, out _))
                return false;

            string client = Canonical(requestSource!);
            string server = Canonical(requestDestination!);
            // The 128-bit request authenticator and identifier distinguish
            // exchanges without retaining the authenticator itself.
            // Digest is a local replay key, not a user identifier.
            string identity = client + "|" + server + "|" +
                requestSourcePort.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                "|" + request[1].ToString(System.Globalization.CultureInfo.InvariantCulture) +
                "|" + Convert.ToHexString(SHA256.HashData(request.Slice(4, 16)));

            lock (_sync)
            {
                // Out-of-order authenticated captures cannot backfill a
                // historical burst after newer evidence has been observed.
                // Refuse them before mutating the retention watermark or state.
                if (observedUtc < _watermark || _seen.ContainsKey(identity))
                    return false;
                // A duplicate exchange is not a new observation and must not
                // advance the clock or expire other replay identities.
                // Capacity checks below remain fail-closed for new identities.
                _watermark = observedUtc;
                DateTime expiry = _watermark.Ticks < Window.Ticks
                    ? DateTime.MinValue : _watermark - Window;
                _observations.RemoveAll(item => item.AtUtc < expiry);
                DateTime replayExpiry = _watermark.Ticks < ReplayRetention.Ticks
                    ? DateTime.MinValue : _watermark - ReplayRetention;
                foreach (var key in _seen.Where(item => item.Value < replayExpiry)
                    .Select(item => item.Key).ToArray())
                    _seen.Remove(key);
                if (observedUtc < expiry ||
                    _seen.ContainsKey(identity) ||
                    _observations.Count >= MaximumObservations ||
                    _seen.Count >= MaximumObservations)
                    return false;

                _observations.Add(new Observation(client, server, identity, observedUtc));
                _seen.Add(identity, observedUtc);
                DateTime lower = observedUtc.Ticks < Window.Ticks
                    ? DateTime.MinValue : observedUtc - Window;
                int count = _observations.Count(item =>
                    item.Client == client && item.Server == server &&
                    item.AtUtc >= lower && item.AtUtc <= observedUtc);
                summary = new RadiusVerifiedRejectSummary(count,
                    count >= 4, observedUtc);
                return true;
            }
        }

        public void Reset()
        {
            lock (_sync)
            {
                _observations.Clear();
                _seen.Clear();
                _watermark = DateTime.MinValue;
            }
        }

        private static string Canonical(string address)
        {
            var parsed = IPAddress.Parse(address);
            return (parsed.IsIPv4MappedToIPv6
                ? parsed.MapToIPv4() : parsed).ToString();
        }
    }

    /// <summary>
    /// Counts independently authenticated RADIUS protocol rejection responses,
    /// not accounts, password failures, identities or confirmed attacks.
    /// Four is an observational threshold only, never an alert decision.
    /// </summary>
    public readonly record struct RadiusVerifiedRejectSummary(
        int DistinctProtocolRejects, bool HasFourDistinctRejects, DateTime TimestampUtc);
}
