// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R237_IotDefaultWebAdminAccessRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R237_IotDefaultWebAdminAccessRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R237",
            Name: "IoT Default Web Admin Access",
            Category: "IotOtAdvanced",
            Description: "Detects IoT/router/camera default admin web access attempts when default admin paths or credential tokens are present.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R237.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R237",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "http_uri_or_headers", "iot_or_appliance_context", "admin_path_or_default_credential" },
            evidenceFields: new[] { "http.path", "matched_conditions", "host" },
            positiveConditions: new[]
            {
                "The request must target a known default IoT/appliance web-admin path or expose default-admin credential tokens.",
                "The traffic should include IoT, router, camera, gateway, printer, or embedded device context.",
                "Generic /admin traffic should not be enough by itself."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic web application admin paths with no IoT/appliance context.",
                "Do not alert on documentation or static assets containing default credential examples."
            },
            minimumConfidence: 82,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host+path",
            falsePositives: new[] { "Initial device setup, lab rebuilds, and approved vulnerability scans may legitimately test default web-admin paths." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedScanners", "ApprovedSetupHosts" },
            requiredTests: new[] { "positive default router admin credential sample", "negative generic web admin sample" });

        public R237_IotDefaultWebAdminAccessRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var text = Text(record);
            var deviceContext = ContainsAnyValue(text, "router", "camera", "printer", "gateway", "embedded", "iot", "luci", "boa", "webcm", "goform", "hikvision", "dahua", "axis", "mikrotik", "ubiquiti", "unifi")
                                || IsCameraLikeProcess(record.ProcessName)
                                || IsHubLikeProcess(record.ProcessName);
            var adminIndicator = HasDefaultWebAdminPath(record) || HasDefaultAdminCredential(record);
            if (!adminIndicator || !deviceContext)
                return NoMatch();

            var credentialEvidence = HasDefaultAdminCredential(record);
            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", credentialEvidence ? "iot_context,default_admin_path,default_credential_token" : "iot_context,default_admin_path", "rule"),
                new("http.path", string.IsNullOrWhiteSpace(record.HttpUri) ? "/" : record.HttpUri!, "http"),
                new("host", BestHost(record), "http")
            };
            evidence.AddRange(AnalystContext(
                "A request targeted IoT/appliance default web-admin surfaces or default credential tokens.",
                "Severity is High because default web-admin paths and credentials are common initial-access and device-takeover paths for embedded devices.",
                "Approved setup hosts and vulnerability scanners may match during controlled onboarding or assessment windows.",
                "Confirm whether the source is approved for device setup or vulnerability scanning.",
                "Review whether the target still accepts default credentials or exposes unauthenticated admin pages."));

            return MatchIot(
                context,
                SeverityLevel.High,
                "IoT default web admin access indicator observed",
                "IotDefaultAdmin",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "iot-appliance-context");
                    confidence.AddEvidence(0.28, "default-admin-path");
                    if (credentialEvidence) confidence.AddEvidence(0.18, "default-credential-token");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{record.HttpUri}:default-admin");
        }
    }
}
