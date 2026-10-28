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

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch236240Evidence.AdminRequest(r)
                || _observations.Observe(r.Source, r.Destination, r.Id, context.TimestampUtc,
                    TimeSpan.FromMinutes(10), false) == 0) return NoMatch();
            return MatchIot(context, SeverityLevel.High,
                "IoT default web-admin route requested", "IotDefaultAdmin",
                new[] {
                    new DetectionEvidenceItem("matched_conditions", "parsed_http,anchored_admin_route,device_process", "rule"),
                    new DetectionEvidenceItem("http.path", "[REDACTED]", "http") },
                c => { c.AddEvidence(0.38, "parsed-cleartext-http");
                    c.AddEvidence(0.30, "anchored-admin-route");
                    c.AddCorrelation(0.18, "attributed-device-process"); },
                cooldownKey: r.Source + ":" + r.Destination + ":device-admin");
        }
    }
}
