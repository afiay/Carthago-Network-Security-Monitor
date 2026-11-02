// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.
// File: Engine/Rules/Expansion/R563_DefaultBasicThenModbusWriteRule.cs
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Correlates one parsed, cleartext known-default HTTP Basic admin request
    /// with a later Modbus/TCP write-request shape from the same private client
    /// to the same private target. Neither login success nor write outcome is known.
    /// </summary>
    public sealed class R563_DefaultBasicThenModbusWriteRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan SequenceWindow = TimeSpan.FromSeconds(120);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private const int MaxPairs = 512;
        private const int MaxPacketIdsPerPair = 64;

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R563",
            Name: "Default HTTP Admin Credential Then Modbus Write Request",
            Category: "IotOtAdvanced",
            Description: "A private client sends a known-default Basic admin request and later a Modbus write request to the same other-subnet private target; authentication and write outcomes are unknown.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R563.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R563",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "http.defaultBasicObserved", "ot.write_request", "matched_conditions", "count", "window_seconds" },
            positiveConditions: new[]
            {
                "PacketHandler must classify a complete, redacted HTTP/1.x admin request and internally set HttpBasicDefaultCredentialObserved.",
                "The same private IPv4 client must send a bounded, parsed Modbus/TCP WRITE-request shape to the exact same private target in a different /24, within 120 seconds and in order.",
                "Use distinct packet IDs, coherent TCP/IPv4 metadata, monotonic timestamps and per-client/target bounded state."
            },
            negativeConditions: new[]
            {
                "Reject unknown Basic credentials, duplicate Authorization, missing headers, non-admin routes, same-subnet traffic, Modbus reads, generic ports and Info-only claims.",
                "Reject TLS/QUIC, contradictory HTTP/DNS fields on Modbus, spoofed/imported HTTP credentials, duplicate IDs, stale/out-of-order traffic and approved admin sources.",
                "Never infer an authenticated login, PLC identity, accepted register write, actual process change or exploitation."
            },
            minimumConfidence: 90,
            threshold: 1,
            window: SequenceWindow,
            cooldown: Cooldown,
            distinctBy: "private_client+exact_private_target+ordered_http_default_basic_then_modbus_write",
            falsePositives: new[]
            {
                "Commissioning, factory-reset recovery, approved engineering tools and vulnerability assessments can legitimately use default credentials and Modbus writes.",
                "NAT, TCP segmentation, capture starting mid-flow and publicly writable Modbus protocol labels limit attribution; keep Shadow pending sensor provenance and approval."
            },
            tuningKnobs: new[] { "Mode", "ApprovedAdminHosts", "ApprovedEngineeringHosts", "ApprovedMaintenanceWindows" },
            requiredTests: new[]
            {
                "actual PacketHandler HTTP and Modbus producer-positive plus benign negative",
                "wrong-order, different-target, same-subnet, read-operation and malformed input fail-closed",
                "duplicate ID, replay ordering, 120-second boundary, cooldown and concurrency",
                "imported credential flag and contradictory transport cannot fabricate a match",
                "redaction, explicit admin policy, registry, Shadow and confidence invariants"
            });

        private sealed class PairState
        {
            internal readonly HashSet<Guid> PacketIds = new();
            internal DateTime Latest;
            internal DateTime? PendingHttpAt;
            internal DateTime? LastEmission;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, PairState> _pairs = new(StringComparer.Ordinal);

        public R563_DefaultBasicThenModbusWriteRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (record.Id == Guid.Empty || !record.IsTcp || record.IsUdp || record.IsQuic
                || record.IpVersion != 4
                || !string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || record.Sni != null || record.Alpn != null || record.TlsVersion != null
                || record.DnsQname != null || record.DnsQtype != null
                || record.DnsRcode != null || record.DnsAnswers != null
                || record.SourcePort is null or < 1024 or > 65535
                || record.L4Len is null or < 12 or > 4096
                || record.Length < record.L4Len.Value + 40
                || !TryPrivateIpv4(record.Source, out var client, out var clientSubnet)
                || !TryPrivateIpv4(record.Destination, out var target, out var targetSubnet)
                || client == target || clientSubnet == targetSubnet)
                return NoMatch();

            // An explicit approved-client policy suppresses known maintenance
            // traffic; no policy is NOT evidence that activity is unauthorized.
            var approvals = ApprovedAssetRegistry.Current;
            if (approvals.HasApprovedAdminHosts && approvals.IsAdminHost(client))
                return NoMatch();

            var http = record.HttpBasicDefaultCredentialObserved
                && string.Equals(record.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                && record.HttpMethod is "GET" or "POST"
                && record.DestinationPort is 80 or 8080 or 8000 or 8008 or 8888
                && record.L4Len >= 40
                && IsAdminPath(record.HttpUri)
                && record.HttpHost != null && record.HttpHost.Length is > 0 and <= 253
                && record.HttpRequestHeaders?.Contains("Authorization: [REDACTED]", StringComparison.OrdinalIgnoreCase) == true;

            var write = !http && !record.HttpBasicDefaultCredentialObserved
                && NetworkBatch236240Evidence.ModbusWrite(record)
                && record.DestinationPort == 502
                && record.L4Len is >= 12 and <= 260
                && record.HttpMethod == null && record.HttpUri == null
                && record.HttpHost == null && record.HttpRequestHeaders == null;

            if (!http && !write)
                return NoMatch();

            if (!TryObserve(client + "|" + target, record.Id, context.TimestampUtc,
                    http, out var suppressed))
                return NoMatch();
            if (suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            // No Authorization bytes, HTTP URI, host, controller addresses,
            // Modbus register/value, raw Info or header contents in evidence.
            var evidence = new[]
            {
                new DetectionEvidenceItem("http.defaultBasicObserved", "true", "packet-handler-http-parser"),
                new DetectionEvidenceItem("ot.write_request", "modbus.write.request", "bounded-packet-classifier"),
                new DetectionEvidenceItem("matched_conditions", "same_private_client_and_target,cross_subnet,http_before_modbus,within_120_seconds", "rule"),
                new DetectionEvidenceItem("count", "1", "rule"),
                new DetectionEvidenceItem("window_seconds", "120", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Default HTTP admin credential attempt preceded a Modbus write request to the same private endpoint (outcomes unknown)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.48, "http-parser-confirmed-default-basic");
                    confidence.AddEvidence(0.24, "bounded-modbus-write-request-shape");
                    confidence.AddCorrelation(0.24, "same-client-target-ordered-two-minute-sequence");
                }, count: 1, windowSeconds: 120);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private bool TryObserve(string key, Guid id, DateTime now, bool http, out bool suppressed)
        {
            suppressed = false;
            lock (_gate)
            {
                if (!_pairs.TryGetValue(key, out var state))
                {
                    if (!http)
                        return false;
                    if (_pairs.Count >= MaxPairs)
                    {
                        var stale = new List<string>();
                        foreach (var entry in _pairs)
                            if (now >= entry.Value.Latest && now - entry.Value.Latest >= Cooldown)
                                stale.Add(entry.Key);
                        foreach (var old in stale)
                            _pairs.Remove(old);
                        if (_pairs.Count >= MaxPairs)
                            return false;
                    }
                    state = new PairState { Latest = now };
                    _pairs.Add(key, state);
                }

                if (now < state.Latest || state.PacketIds.Contains(id)
                    || state.PacketIds.Count >= MaxPacketIdsPerPair)
                    return false;

                if (http)
                {
                    // Repeated HTTP attempts never create a positive themselves.
                    // Do not extend an active window by replaying an HTTP request.
                    if (state.PendingHttpAt is null || now - state.PendingHttpAt.Value > SequenceWindow)
                        state.PendingHttpAt = now;
                    state.PacketIds.Add(id);
                    state.Latest = now;
                    return false;
                }

                if (state.PendingHttpAt is null || now <= state.PendingHttpAt.Value
                    || now - state.PendingHttpAt.Value > SequenceWindow)
                    return false;

                state.PacketIds.Add(id);
                state.Latest = now;
                state.PendingHttpAt = null; // A second candidate needs another HTTP request.
                if (state.LastEmission.HasValue && now >= state.LastEmission.Value
                    && now - state.LastEmission.Value < Cooldown)
                {
                    suppressed = true;
                    return true;
                }
                state.LastEmission = now;
                return true;
            }
        }

        private static bool IsAdminPath(string? uri)
        {
            if (string.IsNullOrEmpty(uri) || uri.Length > 256 || uri[0] != '/')
                return false;
            var query = uri.IndexOf('?');
            var path = query < 0 ? uri : uri.Substring(0, query);
            return path.Equals("/admin", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/admin/", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/login.cgi", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/setup.cgi", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/cgi-bin/luci/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/goform/", StringComparison.OrdinalIgnoreCase);
        }

        private static bool TryPrivateIpv4(string? address, out string normalized, out string subnet)
        {
            normalized = string.Empty;
            subnet = string.Empty;
            if (!IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            if (!(b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168))
                return false;
            normalized = ip.ToString();
            subnet = b[0].ToString(System.Globalization.CultureInfo.InvariantCulture) + "."
                + b[1].ToString(System.Globalization.CultureInfo.InvariantCulture) + "."
                + b[2].ToString(System.Globalization.CultureInfo.InvariantCulture);
            return true;
        }
    }
}
