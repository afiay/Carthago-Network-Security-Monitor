// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R355_JenkinsScriptConsoleProbeRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R355_JenkinsScriptConsoleProbeRule : DevOpsSupplyChainPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R355",
            Name: "Jenkins Script Console Probe",
            Category: "DevOpsSupplyChain",
            Description: "Detects Jenkins Script Console Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R355.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R355",
            Name = "Jenkins Script Console Probe",
            Category = "DevOpsSupplyChain",
            Description = "Detects Jenkins Script Console Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.DevOpsAudit, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_host", "devops_or_secret_context" },
            EvidenceFields = new[] { "devops.host", "http.path", "token.pattern", "matched_conditions" },
            PositiveConditions = new[] { "Jenkins Script Console Probe requires concrete DevOpsSupplyChain telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "CI/CD jobs, package mirrors, vulnerability scanners, and authorized secret-management automations can trigger these rules." },
            TextIndicators = new[] { "jenkins", "script console", "/scriptText", "groovy" },
            HostIndicators = new[] { "jenkins" },
            PathIndicators = new[] { "/script", "/scriptText" },
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
            RequiredTests = new[] { "positive R355 evidence-gated sample", "negative R355 descriptor-only sample", "negative R355 missing telemetry sample" },
            RequireHttp = true,
            RequireInboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R355_JenkinsScriptConsoleProbeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // A descriptive Info field, process name or generic Jenkins hostname
            // cannot establish a script-console HTTP probe. Require a parsed
            // request method and an exact console endpoint path.
            var record = context.Record;
            if (!record.IsTcp || record.IsUdp
                || !string.Equals(record.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase))
                return NoMatch(RuleNoMatchReasonCategory.MissingTelemetry,
                    "JENKINS_HTTP_PROTOCOL_NOT_ATTRIBUTED",
                    "A parser-attributed TCP HTTP request is required.");
            var method = record.HttpMethod;
            var uri = record.HttpUri;
            if (string.IsNullOrWhiteSpace(method) || string.IsNullOrWhiteSpace(uri))
                return NoMatch(RuleNoMatchReasonCategory.MissingTelemetry,
                    "JENKINS_HTTP_REQUEST_NOT_OBSERVED",
                    "A parsed HTTP request method and URI are required.");

            if (!string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase))
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "JENKINS_UNEXPECTED_HTTP_METHOD",
                    "Only observed GET or POST requests are eligible for this probe rule.");

            // PacketHandler provides origin-form request targets. Reject
            // absolute-form or authority-relative targets whose authority
            // cannot be reconciled with the captured Host.
            var rawPath = uri.Split('?', '#')[0];
            if (!rawPath.StartsWith("/", StringComparison.Ordinal)
                || rawPath.StartsWith("//", StringComparison.Ordinal)
                || rawPath.Contains('\\'))
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "JENKINS_REQUEST_TARGET_UNTRUSTED",
                    "An origin-form Jenkins console request target is required.");
            var path = rawPath.TrimEnd('/');
            if (!path.EndsWith("/script", StringComparison.OrdinalIgnoreCase)
                && !path.EndsWith("/scriptText", StringComparison.OrdinalIgnoreCase))
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "JENKINS_CONSOLE_PATH_NOT_OBSERVED",
                    "A parsed Jenkins script-console endpoint is required.");

            return EvaluateSpec(context, Spec);
        }
    }
}
