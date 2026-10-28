// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R352_LLMNRNBNSResponderToolIndicatorRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R352_LLMNRNBNSResponderToolIndicatorRule : ActiveDirectoryWindowsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R352",
            Name: "LLMNR NBNS Responder Tool Indicator",
            Category: "ActiveDirectoryWindows",
            Description: "Detects LLMNR NBNS Responder Tool Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R352.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R352",
            Name = "LLMNR NBNS Responder Tool Indicator",
            Category = "ActiveDirectoryWindows",
            Description = "Detects LLMNR NBNS Responder Tool Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Identity, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "windows_protocol_context" },
            EvidenceFields = new[] { "ad.protocol", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "LLMNR NBNS Responder Tool Indicator requires concrete ActiveDirectoryWindows telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Domain controller administration, vulnerability scanning, GPO operations, and backup tooling can resemble some Windows/AD behaviors." },
            TextIndicators = new[] { "llmnr", "nbns", "responder", "poisoning", "name query" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = new[] { "responder", "inveigh" },
            ProtocolIndicators = new[] { "llmnr", "nbns" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 5355, 137 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+activedirectorywindows+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R352 evidence-gated sample", "negative R352 descriptor-only sample", "negative R352 missing telemetry sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R352_LLMNRNBNSResponderToolIndicatorRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // LLMNR/NBNS is normal name resolution; a port, protocol label,
            // or an Info string mentioning Responder is not tool attribution.
            // A concrete process attribution is required before normal
            // confidence, approval and corroboration gates are considered.
            var record = context.Record;
            var process = record.ProcessName ?? string.Empty;
            var separator = process.LastIndexOfAny(new[] { '/', '\\' });
            if (separator >= 0)
                process = process[(separator + 1)..];
            // Substring matching misclassifies "responder-monitor.exe" and
            // log descriptions as execution of the named tooling.
            if (!process.Equals("responder", StringComparison.OrdinalIgnoreCase)
                && !process.Equals("responder.py", StringComparison.OrdinalIgnoreCase)
                && !process.Equals("inveigh", StringComparison.OrdinalIgnoreCase)
                && !process.Equals("inveigh.exe", StringComparison.OrdinalIgnoreCase)
                && !process.Equals("inveigh.ps1", StringComparison.OrdinalIgnoreCase))
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "RESPONDER_PROCESS_NOT_ATTRIBUTED",
                    "A Responder or Inveigh process attribution is required; name-resolution traffic alone is insufficient.");
            if ((!record.IsTcp && !record.IsUdp) || (record.IsTcp && record.IsUdp))
                return NoMatch(RuleNoMatchReasonCategory.MissingTelemetry,
                    "NAME_RESOLUTION_TRANSPORT_NOT_ATTRIBUTED",
                    "Exactly one observed transport must be attributed.");
            var application = record.ApplicationProtocol ?? string.Empty;
            if (!application.Equals("LLMNR", StringComparison.OrdinalIgnoreCase)
                && !application.Equals("NBNS", StringComparison.OrdinalIgnoreCase))
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "NAME_RESOLUTION_PROTOCOL_NOT_ATTRIBUTED",
                    "A trusted LLMNR/NBNS application classification is required.");
            return EvaluateSpec(context, Spec);
        }
    }
}
