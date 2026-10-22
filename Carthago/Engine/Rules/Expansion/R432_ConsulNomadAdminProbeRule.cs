// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R432_ConsulNomadAdminProbeRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R432_ConsulNomadAdminProbeRule : NetworkApplianceExposurePrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R432",
            Name: "Consul Nomad Admin Probe",
            Category: "NetworkApplianceExposure",
            Description: "Detects Consul Nomad Admin Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R432.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R432",
            Name = "Consul Nomad Admin Probe",
            Category = "NetworkApplianceExposure",
            Description = "Detects Consul Nomad Admin Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "external_source", "internal_appliance_destination", "service_or_admin_endpoint" },
            EvidenceFields = new[] { "network.destinationPort", "http.path", "appliance.product", "matched_conditions" },
            PositiveConditions = new[] { "Consul Nomad Admin Probe requires observable NetworkApplianceExposure telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Approved vulnerability scanners, exposure-management systems, and administrator jump hosts can probe these endpoints; tune approved scanner identities." },
            TextIndicators = new[] { "consul nomad admin probe", "consul", "nomad", "admin", "login", "gateway", "vpn", "console", "api", "exposure" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "/v1/agent", "/ui/", "/v1/kv", "/v1/jobs", "/ui/jobs" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "http", "https" },
            Methods = new[] { "get", "post" },
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 8500, 8600, 4646 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 82,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(10),
            Cooldown = TimeSpan.FromMinutes(30),
            DistinctBy = "source+destination+networkapplianceexposure+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedScanners", "ApprovedJumpHosts", "AdminSubnets", "ExposureMode" },
            RequiredTests = new[] { "positive R432 evidence-gated sample", "negative R432 descriptor-only sample", "negative R432 missing telemetry sample", "negative R432 approved-admin sample" },
            RequireHttp = true,
            RequireInboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R432_ConsulNomadAdminProbeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
            => EvaluateSpec(context, Spec);
    }
}
