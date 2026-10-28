// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R342_WindowsAdminCenterExposureProbeRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R342_WindowsAdminCenterExposureProbeRule : ActiveDirectoryWindowsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R342",
            Name: "Windows Admin Center Exposure Probe",
            Category: "ActiveDirectoryWindows",
            Description: "Candidate R342 requires verified operation and provenance; packet-only indicators return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R342.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R342",
            Name = "Windows Admin Center Exposure Probe",
            Category = "ActiveDirectoryWindows",
            Description = "Candidate R342 requires verified operation and provenance; packet-only indicators return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Identity, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "windows_protocol_context" },
            EvidenceFields = new[] { "ad.protocol", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Windows Admin Center Exposure Probe requires concrete ActiveDirectoryWindows telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Domain controller administration, vulnerability scanning, GPO operations, and backup tooling can resemble some Windows/AD behaviors." },
            TextIndicators = new[] { "windows admin center", "servermanagement", "/api/nodes", "wac" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "/api/nodes", "/servermanagement", "/gateway" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 6516, 443 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+activedirectorywindows+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R342 evidence-gated sample", "negative R342 descriptor-only sample", "negative R342 missing telemetry sample" },
            RequireHttp = true,
            RequireInboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R342_WindowsAdminCenterExposureProbeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Capture exposes network observations, not authenticated operation/outcome audit.
            // Do not promote text indicators, port hints or unverified enrichment to attack evidence.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "WINDOWS_ADMIN_CENTER_IDENTITY_UNAVAILABLE",
                "Windows Admin Center exposure requires verified gateway identity, externally originated parsed request and endpoint/response evidence; port or path alone is insufficient.");
        }
    }
}
