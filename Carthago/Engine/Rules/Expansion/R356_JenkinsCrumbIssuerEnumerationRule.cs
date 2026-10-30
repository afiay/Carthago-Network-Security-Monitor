// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R356_JenkinsCrumbIssuerEnumerationRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R356_JenkinsCrumbIssuerEnumerationRule : DevOpsSupplyChainPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R356",
            Name: "Jenkins Crumb Issuer Enumeration",
            Category: "DevOpsSupplyChain",
            Description: "Detects Jenkins Crumb Issuer Enumeration only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R356.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R356",
            Name = "Jenkins Crumb Issuer Enumeration",
            Category = "DevOpsSupplyChain",
            Description = "Detects Jenkins Crumb Issuer Enumeration only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Medium,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.DevOpsAudit, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_host", "devops_or_secret_context" },
            EvidenceFields = new[] { "devops.host", "http.path", "token.pattern", "matched_conditions" },
            PositiveConditions = new[] { "Jenkins Crumb Issuer Enumeration requires concrete DevOpsSupplyChain telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "CI/CD jobs, package mirrors, vulnerability scanners, and authorized secret-management automations can trigger these rules." },
            TextIndicators = new[] { "jenkins", "crumbissuer", "crumb", "/crumbIssuer/api" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "/crumbIssuer", "/crumbIssuer/api" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 74,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+devopssupplychain+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R356 evidence-gated sample", "negative R356 descriptor-only sample", "negative R356 missing telemetry sample" },
            RequireHttp = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R356_JenkinsCrumbIssuerEnumerationRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!DevOpsHttpEvidence.HasParsedRequest(r))
                return NoMatch(RuleNoMatchReasonCategory.MissingTelemetry, "JENKINS_CRUMB_HTTP_REQUEST_MISSING", "Parsed TCP/HTTP request required.");
            var path = DevOpsHttpEvidence.OriginPath(r.HttpUri);
            if (path == null)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, "JENKINS_CRUMB_TARGET_UNTRUSTED", "Origin-form request target required.");
            if (!string.Equals(r.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase)
                || (!path.EndsWith("/crumbIssuer/api/json", StringComparison.OrdinalIgnoreCase)
                    && !path.EndsWith("/crumbIssuer/api/xml", StringComparison.OrdinalIgnoreCase)))
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, "JENKINS_CRUMB_ENDPOINT_NOT_OBSERVED", "Only an observed GET to the crumb API is eligible.");
            return EvaluateSpec(context, Spec);
        }
    }
}
