// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R516_CloudflaredTunnelHandshakeRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R516_CloudflaredTunnelHandshakeRule : EvasionTunnelPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R516",
            Name: "Cloudflared Tunnel Handshake",
            Category: "EvasionTunnel",
            Description: "Detects Cloudflared Tunnel Handshake only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R516.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R516",
            Name = "Cloudflared Tunnel Handshake",
            Category = "EvasionTunnel",
            Description = "Detects Cloudflared Tunnel Handshake only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            // HTTP and DNS are optional corroboration: a TLS handshake record cannot
            // inherently contain both an HTTP request and a DNS answer.
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "external_destination_or_resolver", "tunnel_or_proxy_indicator" },
            EvidenceFields = new[] { "network.destination", "http.host", "tls.sni", "matched_conditions" },
            PositiveConditions = new[] { "Cloudflared Tunnel Handshake requires observable EvasionTunnel telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Approved VPN, ZTNA, secure web gateway, remote-support, and developer tunnel usage can look similar; tune approved tunnel providers and users." },
            TextIndicators = new[] { "cloudflared tunnel handshake", "cloudflared", "tunnel", "handshake", "proxy", "connect", "socks", "quic", "websocket", "domain fronting", "beacon", "resolver" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "/api/tunnels", "/tunnel", "/agent", "authtoken", "connect", "upgrade: websocket", "socks", "quic", "masque", "connect-udp" },
            ProcessIndicators = new[] { "ssh", "plink", "chisel", "frpc", "frps", "cloudflared", "ngrok", "tailscale", "zerotier-one", "rathole", "socat", "curl" },
            ProtocolIndicators = new[] { "http", "https", "tls", "dns" },
            Methods = new[] { "connect", "get", "post" },
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 7844, 443 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 84,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(35),
            DistinctBy = "source+destination+evasiontunnel+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedTunnelProviders", "ApprovedProxyPorts", "ApprovedResolvers", "BeaconWindowSeconds" },
            RequiredTests = new[] { "positive R516 evidence-gated sample", "negative R516 descriptor-only sample", "negative R516 missing telemetry sample", "negative R516 approved-admin sample" },
            RequireOutboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R516_CloudflaredTunnelHandshakeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var hasCloudflaredProcess = (record.ProcessName ?? string.Empty).Contains("cloudflared", StringComparison.OrdinalIgnoreCase);
            var endpoint = string.Join(" ", record.Sni, record.TlsSni, record.HttpHost);
            var hasTunnelEndpoint = endpoint.Contains("trycloudflare.com", StringComparison.OrdinalIgnoreCase)
                                    || endpoint.Contains("argotunnel.com", StringComparison.OrdinalIgnoreCase)
                                    || endpoint.Contains("cloudflare.com", StringComparison.OrdinalIgnoreCase);

            if (!hasCloudflaredProcess || !hasTunnelEndpoint)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "CLOUDFLARED_HANDSHAKE_NOT_CORROBORATED",
                    "Rule requires both a cloudflared process and a Cloudflare tunnel TLS endpoint.");

            return EvaluateSpec(context, Spec);
        }
    }
}
