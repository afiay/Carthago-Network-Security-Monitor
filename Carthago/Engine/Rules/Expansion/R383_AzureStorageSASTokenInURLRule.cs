// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R383_AzureStorageSASTokenInURLRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R383_AzureStorageSASTokenInURLRule : CloudInfrastructurePrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R383",
            Name: "Azure Storage SAS Token In URL",
            Category: "CloudInfrastructure",
            Description: "Detects Azure Storage SAS Token In URL only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R383.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R383",
            Name = "Azure Storage SAS Token In URL",
            Category = "CloudInfrastructure",
            Description = "Detects Azure Storage SAS Token In URL only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Critical,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.CloudAudit, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_cloud_host", "cloud_action_or_api_path" },
            EvidenceFields = new[] { "cloud.provider", "cloud.api", "http.path", "matched_conditions" },
            PositiveConditions = new[] { "Azure Storage SAS Token In URL requires observable CloudInfrastructure telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Approved infrastructure automation, CI/CD deploy jobs, cloud inventory tools, or cloud security scanners may perform similar API actions; approve known service accounts and management hosts." },
            TextIndicators = new[] { "azure storage sas token in url", "azure", "storage", "sas", "token", "url", "microsoftonline", "management.azure", "keyvault", "sas token", "imds" },
            HostIndicators = new[] { "management.azure.com", "login.microsoftonline.com", "vault.azure.net", "blob.core.windows.net" },
            PathIndicators = new[] { "sig=", "se=", "sp=", "sv=" },
            ProcessIndicators = new[] { "aws", "aws.exe", "az", "az.exe", "gcloud", "gsutil", "terraform", "cloudflared", "ngrok", "tailscale", "zerotier-one" },
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = new[] { "generic" },
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 82,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(15),
            Cooldown = TimeSpan.FromMinutes(30),
            DistinctBy = "source+destination+cloudinfrastructure+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedCloudAccounts", "ApprovedServiceAccounts", "ApprovedAutomationHosts", "AllowedCloudRegions" },
            RequiredTests = new[] { "positive R383 evidence-gated sample", "negative R383 descriptor-only sample", "negative R383 missing telemetry sample", "negative R383 approved-admin sample" },
            RequireHttp = true,
            RequireCrossBoundary = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R383_AzureStorageSASTokenInURLRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // SOURCE CANDIDATE — UNVERIFIED. Provider request shape alone
            // cannot establish authentication, success or malicious intent.
            var rejection = CloudProviderRequestEvidence.Reject(context.Record, context.TimestampUtc, "R383");
            if (rejection != null)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, rejection,
                    "Rule-specific packet evidence or trusted provider audit is unavailable.");
            return EvaluateSpec(context, Spec);
        }
    }
}
