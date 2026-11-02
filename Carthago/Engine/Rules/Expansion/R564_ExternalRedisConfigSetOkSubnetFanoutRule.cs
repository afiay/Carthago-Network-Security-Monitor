// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.
// File: Engine/Rules/Expansion/R564_ExternalRedisConfigSetOkSubnetFanoutRule.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Correlates first-command RESP2 CONFIG SET +OK-shaped replies from Redis
    /// endpoints in two different RFC1918 /24 networks to one public IPv4 client.
    /// PacketHandler validates the request/reply TCP sequence. Neither the
    /// server identity nor the authorization or persistence of the change is attested.
    /// </summary>
    public sealed class R564_ExternalRedisConfigSetOkSubnetFanoutRule
        : DatabaseServiceExposurePrecisionDetectionRuleBase
    {
        private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan EmissionCooldown = TimeSpan.FromMinutes(10);
        private const int MaxClients = 512;
        private const int MaxSubnetsPerClient = 32;
        private const int MaxIdsPerClient = 128;

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R564",
            Name: "External Redis CONFIG SET OK Reply Across Private Subnets",
            Category: "DatabaseServiceExposure",
            Description: "One public IPv4 client receives independently correlated Redis CONFIG SET +OK-shaped replies from servers in two different private /24 networks within five minutes; server identity, authorization and persistent configuration changes remain unverified.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R564.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R564",
            Name = "External Redis CONFIG SET OK Reply Across Private Subnets",
            Category = "DatabaseServiceExposure",
            Description = "Correlated RESP2 CONFIG SET +OK-shaped replies across two private server subnets, not an authenticated multi-server configuration change.",
            Severity = SeverityLevel.High,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination_or_host", "protocol_or_port" },
            EvidenceFields = new[]
            {
                "redis.reply_shape", "redis.distinct_private_subnets",
                "matched_conditions", "count", "window_seconds", "network.direction"
            },
            PositiveConditions = new[]
            {
                "The existing PacketHandler must correlate a first RESP2 CONFIG SET command after SYN/SYN-ACK to an in-order, complete +OK-shaped server reply on TCP/6379.",
                "The same globally routable public IPv4 client must receive independently correlated +OK-shaped replies from two different RFC1918 /24 server networks on distinct client ephemeral ports within 300 seconds.",
                "Require parser-only reply flags, coherent reverse TCP metadata, distinct packet IDs, monotonic timestamps, bounded per-client state and explicit approved-admin policy."
            },
            NegativeConditions = new[]
            {
                "Reject CONFIG SET error replies, ordinary SET/PING, absent SYN/SYN-ACK, malformed RESP, incomplete frames, port/Info-only claims, and same-subnet server fanout.",
                "Reject mixed public clients, identical client ports, duplicate packet IDs, out-of-order or stale timestamps, TLS/QUIC, contradictory HTTP/DNS metadata and reserved/public-test IPv4 addresses.",
                "Do not infer authenticated Redis identity, permission bypass, accepted dangerous parameter values, durable configuration changes, compromise or any specific CVE."
            },
            FalsePositives = new[]
            {
                "Approved Redis fleet configuration and recovery automation may change settings on several clusters through an external NAT or management gateway.",
                "Reverse proxies, spoofed packets, packet loss, TCP segmentation, Redis TLS and one-sided capture can prevent or misattribute the correlation; independent Redis server audit and asset policy are required for promotion."
            },
            MinimumConfidence = 90,
            WindowThreshold = 2,
            Window = ObservationWindow,
            Cooldown = EmissionCooldown,
            DistinctBy = "public_client+two_private_24s+two_distinct_client_ports+correlated_config_set_ok_replies",
            TuningKnobs = new[] { "Mode", "ApprovedAdminHosts" },
            RequiredTests = new[]
            {
                "actual bidirectional PacketHandler producer-positive on two private subnets",
                "same-subnet, error, unrelated command, missing handshake and reserved-address negatives",
                "spoofed imported flag, Info-only, contradictory TLS/HTTP/DNS and malformed frames",
                "distinct client ports, duplicate IDs, stale/out-of-order observations, cooldown and concurrency",
                "privacy, explicit approved-admin suppression, registry and Shadow confidence invariants"
            }
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        private sealed class Target
        {
            internal int ClientPort;
            internal DateTime At;
        }

        private sealed class ClientBucket
        {
            internal readonly Dictionary<string, Target> Subnets = new(StringComparer.Ordinal);
            internal readonly Dictionary<Guid, DateTime> SeenIds = new();
            internal DateTime Latest;
            internal DateTime? LastEmission;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, ClientBucket> _clients = new(StringComparer.Ordinal);

        public R564_ExternalRedisConfigSetOkSubnetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryQualify(context.Record, out var client,
                    out var subnet, out var clientPort))
                return NoMatch();

            if (IsApprovedClient(client, ApprovedAssetRegistry.Current))
                return NoMatch();

            if (!Observe(client, subnet, clientPort, context.Record.Id,
                    context.TimestampUtc, out var count, out var suppressed))
                return NoMatch();

            if (suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            // Fixed evidence only: no RESP command parameter/value, HTTP headers,
            // server reply body, raw Info, source IP or endpoint list in evidence.
            // The underlying event still contains its normal packet direction:
            // SourceIp=private Redis server, DestinationIp=public client.
            var evidence = new[]
            {
                new DetectionEvidenceItem("redis.reply_shape", "resp2.ok_after_correlated_config_set", "packet-handler-correlator"),
                new DetectionEvidenceItem("redis.distinct_private_subnets", count.ToString(CultureInfo.InvariantCulture), "rule"),
                new DetectionEvidenceItem("matched_conditions", "one_public_client,two_private_24s,distinct_client_ports,correlated_ok_replies", "rule"),
                new DetectionEvidenceItem("network.direction", "private_server_to_public_client", "packet"),
                new DetectionEvidenceItem("count", count.ToString(CultureInfo.InvariantCulture), "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "One public client received correlated Redis CONFIG SET OK-shaped replies from multiple private subnets (identity and authorization unverified)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.48, "packet-handler-syn-anchored-resp2-request-reply-correlation");
                    confidence.AddEvidence(0.26, "distinct-private-subnets-and-client-ports");
                    confidence.AddCorrelation(0.24, "one-public-client-five-minute-window");
                }, count: count, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        internal static bool IsApprovedClient(string client, ApprovedAssetRegistry registry)
            => registry.HasApprovedAdminHosts && registry.IsAdminHost(client);

        private static bool TryQualify(TrafficRecord r, out string client,
            out string subnet, out int clientPort)
        {
            client = string.Empty;
            subnet = string.Empty;
            clientPort = 0;

            if (r.Id == Guid.Empty || !r.RedisRespConfigSetReplyOkObserved
                || r.RedisRespConfigSetReplyErrorObserved || r.RedisRespConfigSetRequestObserved
                || !r.IsTcp || r.IsUdp || r.IsQuic || r.IpVersion != 4
                || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(r.ApplicationProtocol, "redis.resp2", StringComparison.Ordinal)
                || r.SourcePort != 6379 || r.DestinationPort is null or < 1024 or > 65535 or 6379
                || r.L4Len != 5 || r.Length < 45
                || r.TlsVersion != null || r.Sni != null || r.Alpn != null
                || r.HttpMethod != null || r.HttpUri != null || r.HttpHost != null
                || r.HttpRequestHeaders != null || r.DnsQname != null || r.DnsQtype != null
                || r.DnsRcode != null || r.DnsAnswers != null
                || !TryPrivateServer(r.Source, out subnet)
                || !TryPublicClient(r.Destination, out client))
                return false;

            clientPort = r.DestinationPort.Value;
            return true;
        }

        private bool Observe(string client, string subnet,
            int clientPort, Guid id, DateTime now, out int count, out bool suppressed)
        {
            count = 0;
            suppressed = false;
            lock (_gate)
            {
                if (!_clients.TryGetValue(client, out var bucket))
                {
                    if (_clients.Count >= MaxClients)
                    {
                        var stale = new List<string>();
                        foreach (var entry in _clients)
                            if (now >= entry.Value.Latest && now - entry.Value.Latest > EmissionCooldown)
                                stale.Add(entry.Key);
                        foreach (var key in stale)
                            _clients.Remove(key);
                        if (_clients.Count >= MaxClients)
                            return false;
                    }
                    bucket = new ClientBucket();
                    _clients.Add(client, bucket);
                }

                if (now <= bucket.Latest || bucket.SeenIds.ContainsKey(id))
                    return false;

                var oldIds = new List<Guid>();
                foreach (var entry in bucket.SeenIds)
                    if (now >= entry.Value && now - entry.Value > ObservationWindow)
                        oldIds.Add(entry.Key);
                foreach (var old in oldIds)
                    bucket.SeenIds.Remove(old);

                var oldSubnets = new List<string>();
                foreach (var entry in bucket.Subnets)
                    if (now >= entry.Value.At && now - entry.Value.At > ObservationWindow)
                        oldSubnets.Add(entry.Key);
                foreach (var old in oldSubnets)
                    bucket.Subnets.Remove(old);

                if (bucket.SeenIds.Count >= MaxIdsPerClient
                    || !bucket.Subnets.ContainsKey(subnet)
                        && bucket.Subnets.Count >= MaxSubnetsPerClient)
                    return false;

                bucket.SeenIds.Add(id, now);
                bucket.Latest = now;
                if (!bucket.Subnets.ContainsKey(subnet))
                    bucket.Subnets.Add(subnet, new Target
                    {
                        ClientPort = clientPort,
                        At = now
                    });

                // Different private subnets and client ports are both required.
                // A repeated +OK on the same /24 cannot inflate the threshold.
                if (bucket.Subnets.Count < 2)
                    return false;

                var ports = new HashSet<int>();
                foreach (var entry in bucket.Subnets.Values)
                    ports.Add(entry.ClientPort);
                if (ports.Count < 2)
                    return false;

                count = bucket.Subnets.Count;
                bucket.Subnets.Clear(); // Require fresh independent replies for another match.
                if (bucket.LastEmission.HasValue && now >= bucket.LastEmission.Value
                    && now - bucket.LastEmission.Value < EmissionCooldown)
                {
                    suppressed = true;
                    return true;
                }
                bucket.LastEmission = now;
                return true;
            }
        }

        private static bool TryPrivateServer(string? value, out string subnet)
        {
            subnet = string.Empty;
            if (!IPAddress.TryParse(value, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            if (!(b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168))
                return false;
            subnet = string.Concat(b[0].ToString(CultureInfo.InvariantCulture), ".",
                b[1].ToString(CultureInfo.InvariantCulture), ".",
                b[2].ToString(CultureInfo.InvariantCulture));
            return true;
        }

        private static bool TryPublicClient(string? value, out string normalized)
        {
            normalized = string.Empty;
            if (!NetworkBatch226230Evidence.Public(value)
                || !IPAddress.TryParse(value, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            if (b[0] is 0 or 10 or 127 or >= 224
                || b[0] == 100 && b[1] is >= 64 and <= 127
                || b[0] == 169 && b[1] == 254
                || b[0] == 192 && (b[1] == 0 || b[1] == 88 && b[2] == 99)
                || b[0] == 198 && (b[1] is 18 or 19 || b[1] == 51 && b[2] == 100)
                || b[0] == 203 && b[1] == 0 && b[2] == 113)
                return false;
            normalized = ip.ToString();
            return true;
        }
    }
}
