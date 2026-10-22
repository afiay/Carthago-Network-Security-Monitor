// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R521_HTTPCONNECTToNonProxyPortRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R521_HTTPCONNECTToNonProxyPortRule : EvasionTunnelPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R521",
            Name: "HTTP CONNECT To Non Proxy Port",
            Category: "EvasionTunnel",
            Description: "Detects HTTP CONNECT To Non Proxy Port only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R521.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R521",
            Name = "HTTP CONNECT To Non Proxy Port",
            Category = "EvasionTunnel",
            Description = "Detects HTTP CONNECT To Non Proxy Port only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Medium,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Dns, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "external_destination_or_resolver", "tunnel_or_proxy_indicator" },
            EvidenceFields = new[] { "network.destination", "http.host", "tls.sni", "matched_conditions" },
            PositiveConditions = new[] { "HTTP CONNECT To Non Proxy Port requires observable EvasionTunnel telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Approved VPN, ZTNA, secure web gateway, remote-support, and developer tunnel usage can look similar; tune approved tunnel providers and users." },
            TextIndicators = new[] { "http connect to non proxy port", "http", "connect", "non", "proxy", "port", "tunnel", "socks", "quic", "websocket", "domain fronting", "beacon", "resolver" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "connect", "upgrade: websocket", "socks", "/api/tunnels", "quic", "masque", "connect-udp" },
            ProcessIndicators = new[] { "ssh", "plink", "chisel", "frpc", "frps", "cloudflared", "ngrok", "tailscale", "zerotier-one", "rathole", "socat", "curl" },
            ProtocolIndicators = new[] { "http", "https", "tls", "dns" },
            Methods = new[] { "post", "put", "connect", "get" },
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 8080, 3128, 443 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 84,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(35),
            DistinctBy = "source+destination+evasiontunnel+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedTunnelProviders", "ApprovedProxyPorts", "ApprovedResolvers", "BeaconWindowSeconds" },
            RequiredTests = new[] { "positive R521 evidence-gated sample", "negative R521 descriptor-only sample", "negative R521 missing telemetry sample", "negative R521 approved-admin sample" },
            RequireHttp = true,
            RequireOutboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R521_HTTPCONNECTToNonProxyPortRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
            => EvaluateSpec(context, Spec);
    }
}
