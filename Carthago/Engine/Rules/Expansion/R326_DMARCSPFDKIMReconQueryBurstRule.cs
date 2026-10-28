// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R326_DMARCSPFDKIMReconQueryBurstRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R326_DMARCSPFDKIMReconQueryBurstRule : EmailCollaborationPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R326",
            Name: "DMARC SPF DKIM Recon Query Burst",
            Category: "EmailCollaboration",
            Description: "Detects DMARC SPF DKIM Recon Query Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R326.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R326",
            Name = "DMARC SPF DKIM Recon Query Burst",
            Category = "EmailCollaboration",
            Description = "Detects DMARC SPF DKIM Recon Query Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Low,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Dns },
            RequiredFields = new[] { "source", "destination_or_host", "mail_or_collaboration_context" },
            EvidenceFields = new[] { "mail.protocol", "http.path", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "DMARC SPF DKIM Recon Query Burst requires concrete EmailCollaboration telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Mail migrations, eDiscovery exports, DLP tooling, and sanctioned collaboration automations can match these patterns." },
            TextIndicators = new[] { "dmarc", "spf", "dkim", "_dmarc", "selector1._domainkey", "recon" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "dns" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 53 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 74,
            WindowThreshold = 5,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+emailcollaboration+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R326 evidence-gated sample", "negative R326 descriptor-only sample", "negative R326 missing telemetry sample" },
            RequireDns = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R326_DMARCSPFDKIMReconQueryBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "DNS_MAIL_POLICY_AUDIT_UNAVAILABLE",
                "DNS policy lookups do not establish unauthorized reconnaissance. Require independently verified source context.");
        }
    }
}
