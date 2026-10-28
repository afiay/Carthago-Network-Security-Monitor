// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R351_NTLMAuthenticationToExternalHostRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R351_NTLMAuthenticationToExternalHostRule : ActiveDirectoryWindowsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R351",
            Name: "NTLM Authentication To External Host",
            Category: "ActiveDirectoryWindows",
            Description: "Detects NTLM Authentication To External Host only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R351.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R351",
            Name = "NTLM Authentication To External Host",
            Category = "ActiveDirectoryWindows",
            Description = "Detects NTLM Authentication To External Host only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Identity, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "windows_protocol_context" },
            EvidenceFields = new[] { "ad.protocol", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "NTLM Authentication To External Host requires concrete ActiveDirectoryWindows telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Domain controller administration, vulnerability scanning, GPO operations, and backup tooling can resemble some Windows/AD behaviors." },
            TextIndicators = new[] { "ntlm", "external host", "netntlm", "challenge response" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "ntlm", "smb" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 80, 445, 139, 8080 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+activedirectorywindows+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R351 evidence-gated sample", "negative R351 descriptor-only sample", "negative R351 missing telemetry sample" },
            RequireOutboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R351_NTLMAuthenticationToExternalHostRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // SMB transport or descriptive Info text alone does not establish
            // an NTLM authentication exchange. Preserve the existing outbound
            // boundary, confidence, approval and signal gates in EvaluateSpec.
            var record = context.Record;
            if (!record.IsTcp || record.IsUdp)
                return NoMatch(RuleNoMatchReasonCategory.MissingTelemetry,
                    "NTLM_TCP_TRANSPORT_NOT_ATTRIBUTED",
                    "An attributed TCP transport is required for this NTLM exchange candidate.");
            // A free-form Protocol/Info label is not a parser-attributed NTLM
            // exchange. ApplicationProtocol/Service must be supplied by a
            // trusted NTLM-aware producer (not currently PacketHandler).
            var observedProtocol = record.ApplicationProtocol ?? string.Empty;
            var observedService = record.ApplicationService ?? string.Empty;
            if (!observedProtocol.Equals("NTLM", StringComparison.OrdinalIgnoreCase)
                && !observedProtocol.Equals("NTLMSSP", StringComparison.OrdinalIgnoreCase)
                && !observedService.Equals("NTLM", StringComparison.OrdinalIgnoreCase)
                && !observedService.Equals("NTLMSSP", StringComparison.OrdinalIgnoreCase))
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "NTLM_PROTOCOL_NOT_ATTRIBUTED",
                    "An NTLM-attributed protocol observation is required; SMB alone is insufficient.");
            return EvaluateSpec(context, Spec);
        }
    }
}
