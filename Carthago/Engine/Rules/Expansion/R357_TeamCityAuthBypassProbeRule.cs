// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R357_TeamCityAuthBypassProbeRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R357_TeamCityAuthBypassProbeRule : DevOpsSupplyChainPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R357",
            Name: "TeamCity Auth Bypass Probe",
            Category: "DevOpsSupplyChain",
            Description: "Detects TeamCity Auth Bypass Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R357.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R357",
            Name = "TeamCity Auth Bypass Probe",
            Category = "DevOpsSupplyChain",
            Description = "Detects TeamCity Auth Bypass Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.DevOpsAudit, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_host", "devops_or_secret_context" },
            EvidenceFields = new[] { "devops.host", "http.path", "token.pattern", "matched_conditions" },
            PositiveConditions = new[] { "TeamCity Auth Bypass Probe requires concrete DevOpsSupplyChain telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "CI/CD jobs, package mirrors, vulnerability scanners, and authorized secret-management automations can trigger these rules." },
            TextIndicators = new[] { "teamcity", "auth bypass", "/app/rest", "/admin/diagnostic", "cve" },
            HostIndicators = new[] { "teamcity" },
            PathIndicators = new[] { "/app/rest", "/admin/diagnostic", "/app/rest/users" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+devopssupplychain+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R357 evidence-gated sample", "negative R357 descriptor-only sample", "negative R357 missing telemetry sample" },
            RequireHttp = true,
            RequireInboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R357_TeamCityAuthBypassProbeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!DevOpsHttpEvidence.HasParsedRequest(r))
                return NoMatch(RuleNoMatchReasonCategory.MissingTelemetry, "TEAMCITY_HTTP_REQUEST_MISSING", "Parsed TCP/HTTP request required.");
            var path = DevOpsHttpEvidence.OriginPath(r.HttpUri);
            if (path == null)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, "TEAMCITY_TARGET_UNTRUSTED", "Origin-form request target required.");
            if (!string.Equals(r.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(r.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, "TEAMCITY_METHOD_NOT_ELIGIBLE", "Only GET/POST request shapes are eligible.");
            var target = r.HttpUri!;
            var relevant = path.Contains("/app/rest/", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith("/admin/diagnostic", StringComparison.OrdinalIgnoreCase);
            var bypassShape = target.Contains("..;", StringComparison.Ordinal)
                || target.Contains("?jsp=/app/rest/", StringComparison.OrdinalIgnoreCase)
                || target.Contains("&jsp=/app/rest/", StringComparison.OrdinalIgnoreCase)
                || target.Contains("?jsp=/admin/diagnostic", StringComparison.OrdinalIgnoreCase)
                || target.Contains("&jsp=/admin/diagnostic", StringComparison.OrdinalIgnoreCase);
            if (!relevant || !bypassShape)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, "TEAMCITY_BYPASS_SHAPE_NOT_OBSERVED", "A REST/admin path and specific bypass-shaped request target are required.");
            // Probe-shaped HTTP alone cannot establish an authorization bypass outcome.
            return EvaluateSpec(context, Spec);
        }
    }
}
