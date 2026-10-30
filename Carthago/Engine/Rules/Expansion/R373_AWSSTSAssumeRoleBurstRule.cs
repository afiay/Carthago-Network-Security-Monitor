// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R373_AWSSTSAssumeRoleBurstRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R373_AWSSTSAssumeRoleBurstRule : CloudInfrastructurePrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R373",
            Name: "AWS STS AssumeRole Burst",
            Category: "CloudInfrastructure",
            Description: "Detects AWS STS AssumeRole Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R373.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R373",
            Name = "AWS STS AssumeRole Burst",
            Category = "CloudInfrastructure",
            Description = "Detects AWS STS AssumeRole Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.CloudAudit, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_cloud_host", "cloud_action_or_api_path" },
            EvidenceFields = new[] { "cloud.provider", "cloud.api", "http.path", "matched_conditions" },
            PositiveConditions = new[] { "AWS STS AssumeRole Burst requires observable CloudInfrastructure telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Approved infrastructure automation, CI/CD deploy jobs, cloud inventory tools, or cloud security scanners may perform similar API actions; approve known service accounts and management hosts." },
            TextIndicators = new[] { "aws sts assumerole burst", "aws", "sts", "assume", "role", "amazonaws", "iam", "s3", "ec2", "lambda", "cloudtrail", "guardduty" },
            HostIndicators = new[] { "amazonaws.com", "aws.amazon.com" },
            PathIndicators = new[] { "assumerole", "action=assumerole", "sts.amazonaws.com" },
            ProcessIndicators = new[] { "aws", "aws.exe", "az", "az.exe", "gcloud", "gsutil", "terraform", "cloudflared", "ngrok", "tailscale", "zerotier-one" },
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = new[] { "aws" },
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 82,
            WindowThreshold = 4,
            Window = TimeSpan.FromMinutes(10),
            Cooldown = TimeSpan.FromMinutes(30),
            DistinctBy = "source+destination+cloudinfrastructure+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedCloudAccounts", "ApprovedServiceAccounts", "ApprovedAutomationHosts", "AllowedCloudRegions" },
            RequiredTests = new[] { "positive R373 evidence-gated sample", "negative R373 descriptor-only sample", "negative R373 missing telemetry sample", "negative R373 approved-admin sample" },
            RequireCrossBoundary = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R373_AWSSTSAssumeRoleBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var rejection = CloudRequestPrecisionEvidence.Reject(context.Record, context.TimestampUtc, "R373");
            if (rejection != null)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, rejection,
                    "Rule-specific packet or authenticated audit evidence is unavailable.");
            return EvaluateSpec(context, Spec);
        }
    }
}
