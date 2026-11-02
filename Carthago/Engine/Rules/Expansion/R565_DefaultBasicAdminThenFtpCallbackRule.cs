// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.
// File: Engine/Rules/Expansion/R565_DefaultBasicAdminThenFtpCallbackRule.cs
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// A public peer attempts known-default Basic authentication at an internal
    /// HTTP admin endpoint, then the same internal host issues an FTP STOR/APPE
    /// command back to that exact public peer. This is request-only correlation:
    /// neither credential acceptance nor file transfer is established.
    /// </summary>
    public sealed class R565_DefaultBasicAdminThenFtpCallbackRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan SequenceWindow = TimeSpan.FromSeconds(120);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private const int MaxPairs = 512;
        private const int MaxIdsPerPair = 64;

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R565",
            Name: "Default HTTP Admin Credential Attempt Then FTP Callback",
            Category: "ExfiltrationAdvanced",
            Description: "A public peer sends a known-default HTTP Basic admin request to a private host; within two minutes that exact private host sends an FTP STOR/APPE command back to the same public peer. No authentication or transfer outcome is established.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R565.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile(
            ruleId: "R565",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port", "http_any" },
            evidenceFields: new[] { "http.defaultBasicObserved", "ftp.operation", "ftp.transfer_status", "matched_conditions", "count", "window_seconds" },
            positiveConditions: new[]
            {
                "The existing PacketHandler must classify a complete plaintext HTTP/1.x administrative request and internally mark a recognized known-default Basic credential, with header redaction.",
                "Within 120 seconds, the same RFC1918 IPv4 HTTP destination must issue a bounded parsed FTP STOR/APPE command on TCP/21 to the exact globally routable IPv4 peer that originated the HTTP request.",
                "Require reverse exact endpoint pairing, two distinct packet IDs, coherent TCP/IPv4 metadata and strictly increasing observation timestamps."
            },
            negativeConditions: new[]
            {
                "Reject ordinary/unknown Basic, duplicate Authorization, non-admin HTTP paths, FTP RETR/LIST/replies, wrong external peer, wrong internal host and reverse order.",
                "Reject port-only or Info-only claims, missing/contradictory HTTP/DNS/TLS/QUIC context, reserved or private external peers, duplicate IDs, stale/out-of-order observations and saturation.",
                "Never claim a successful login, device compromise, FTP data-channel bytes, file contents, successful server storage, data theft or any specific CVE."
            },
            minimumConfidence: 90,
            threshold: 1,
            window: SequenceWindow,
            cooldown: Cooldown,
            distinctBy: "private_http_target+same_public_http_origin_and_ftp_destination+ordered_two_protocol_request_shapes",
            falsePositives: new[]
            {
                "Approved remote maintenance and provisioning can use factory credentials and then trigger FTP-based configuration backup to the management gateway.",
                "NAT, reverse proxies, one-sided capture, fragmented TCP, HTTP over TLS and FTPS obscure peer attribution or payloads; absent approvals do not establish malicious intent."
            },
            tuningKnobs: new[] { "Mode", "ApprovedAdminHosts", "ApprovedMaintenanceWindows", "ApprovedFtpServers" },
            requiredTests: new[]
            {
                "actual PacketHandler HTTP default-credential and FTP STOR/APPE producer-positive",
                "ordinary credentials, duplicate headers, non-admin path, FTP RETR and alternate peers negative",
                "malformed/truncated, reserved IP, port/Info-only, forged JSON and contradictory TLS/DNS negative",
                "duplicate IDs, reverse/equal/out-of-order timestamps, 120-second expiry, cooldown and concurrent duplicate",
                "secret and filename redaction, explicit admin approval, Candidate/Shadow confidence and registry invariants"
            });

        private sealed class PairState
        {
            internal readonly Dictionary<Guid, DateTime> Seen = new();
            internal DateTime Latest;
            internal DateTime? HttpAt;
            internal DateTime? LastEmission;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, PairState> _pairs = new(StringComparer.Ordinal);

        public R565_DefaultBasicAdminThenFtpCallbackRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!TryQualify(r, out var privateHost, out var publicPeer, out var isHttp))
                return NoMatch();

            var approved = ApprovedAssetRegistry.Current;
            if (approved.HasApprovedAdminHosts
                && (approved.IsAdminHost(publicPeer) || approved.IsAdminHost(privateHost)))
                return NoMatch();

            if (!Observe(privateHost + "|" + publicPeer, r.Id, context.TimestampUtc,
                    isHttp, out var suppressed))
                return NoMatch();

            if (suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            // Only fixed labels. No Authorization bytes, HTTP path/host, FTP
            // filename, payload, raw Info, endpoint list or credential in evidence.
            var evidence = new[]
            {
                new DetectionEvidenceItem("http.defaultBasicObserved", "true", "packet-handler-http-parser"),
                new DetectionEvidenceItem("ftp.operation", "stor_or_appe.request", "bounded-packet-classifier"),
                new DetectionEvidenceItem("ftp.transfer_status", "request_only_unverified", "rule"),
                new DetectionEvidenceItem("matched_conditions", "public_default_basic_admin_attempt,private_target_ftp_command_to_same_public_peer,ordered_within_120_seconds", "rule"),
                new DetectionEvidenceItem("count", "1", "rule"),
                new DetectionEvidenceItem("window_seconds", "120", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Known-default HTTP admin credential attempt preceded an FTP upload command from the target back to the same public peer (outcomes unknown)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.46, "parser-confirmed-default-basic-admin-request");
                    confidence.AddEvidence(0.28, "bounded-ftp-stor-appe-request-shape");
                    confidence.AddCorrelation(0.23, "reverse-exact-private-public-endpoint-pair");
                }, count: 1, windowSeconds: 120);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private static bool TryQualify(TrafficRecord r,
            out string privateHost, out string publicPeer, out bool isHttp)
        {
            privateHost = string.Empty;
            publicPeer = string.Empty;
            isHttp = false;
            if (r.Id == Guid.Empty || r.IpVersion != 4 || !r.IsTcp || r.IsUdp || r.IsQuic
                || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || r.SourcePort is null or < 1024 or > 65535
                || r.L4Len is null or < 8 or > 4096
                || r.Length < r.L4Len.Value + 40
                || r.TlsVersion != null || r.Sni != null || r.Alpn != null
                || r.DnsQname != null || r.DnsQtype != null || r.DnsAnswers != null
                || r.DnsRcode != null)
                return false;

            if (r.HttpBasicDefaultCredentialObserved
                && string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                && r.DestinationPort is 80 or 8080 or 8000 or 8008 or 8888
                && r.L4Len is >= 40 and <= 4096
                && r.HttpMethod is "GET" or "POST"
                && IsAdminPath(r.HttpUri) && SafeHost(r.HttpHost)
                && r.HttpRequestHeaders?.Contains("Authorization: [REDACTED]", StringComparison.OrdinalIgnoreCase) == true
                && TryPublicIpv4(r.Source, out publicPeer)
                && TryPrivateIpv4(r.Destination, out privateHost))
            {
                isHttp = true;
                return true;
            }

            if (!r.HttpBasicDefaultCredentialObserved
                && r.DestinationPort == 21 && r.L4Len is >= 8 and <= 256
                && r.HttpMethod == null && r.HttpUri == null
                && r.HttpHost == null && r.HttpRequestHeaders == null
                && NetworkBatch246250Evidence.FtpUpload(r)
                && TryPrivateIpv4(r.Source, out privateHost)
                && TryPublicIpv4(r.Destination, out publicPeer))
                return true;

            return false;
        }

        private bool Observe(string key, Guid id, DateTime now,
            bool isHttp, out bool suppressed)
        {
            suppressed = false;
            lock (_gate)
            {
                if (!_pairs.TryGetValue(key, out var state))
                {
                    if (!isHttp)
                        return false;
                    if (_pairs.Count >= MaxPairs)
                    {
                        var expired = new List<string>();
                        foreach (var entry in _pairs)
                            if (now >= entry.Value.Latest
                                && now - entry.Value.Latest >= Cooldown)
                                expired.Add(entry.Key);
                        foreach (var old in expired)
                            _pairs.Remove(old);
                        if (_pairs.Count >= MaxPairs)
                            return false;
                    }
                    state = new PairState();
                    _pairs.Add(key, state);
                }

                if (now < state.Latest || state.Seen.ContainsKey(id))
                    return false;

                var expiredIds = new List<Guid>();
                foreach (var entry in state.Seen)
                    if (now >= entry.Value && now - entry.Value > Cooldown)
                        expiredIds.Add(entry.Key);
                foreach (var old in expiredIds)
                    state.Seen.Remove(old);

                if (state.Seen.Count >= MaxIdsPerPair)
                    return false;

                if (isHttp)
                {
                    // Repeated HTTP attempts do not perpetually extend a seed.
                    if (state.HttpAt is null || now - state.HttpAt.Value > SequenceWindow)
                        state.HttpAt = now;
                    state.Seen.Add(id, now);
                    state.Latest = now;
                    return false;
                }

                if (state.HttpAt is null || now <= state.HttpAt.Value
                    || now - state.HttpAt.Value > SequenceWindow)
                    return false;

                state.Seen.Add(id, now);
                state.Latest = now;
                state.HttpAt = null; // A later FTP request needs a new HTTP seed.
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
            var end = uri.IndexOf('?');
            var path = end < 0 ? uri : uri.Substring(0, end);
            return path.Equals("/admin", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/admin/", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/login", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/login.cgi", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/setup.cgi", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/cgi-bin/luci/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/goform/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/boaform/", StringComparison.OrdinalIgnoreCase);
        }

        private static bool SafeHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host) || host.Length > 253)
                return false;
            foreach (var ch in host)
                if (char.IsWhiteSpace(ch) || ch is '@' or '/' or '?' or '#' or '\\')
                    return false;
            return true;
        }

        private static bool TryPrivateIpv4(string? value, out string normalized)
        {
            normalized = string.Empty;
            if (!IPAddress.TryParse(value, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            if (!(b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168))
                return false;
            normalized = ip.ToString();
            return true;
        }

        private static bool TryPublicIpv4(string? value, out string normalized)
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
