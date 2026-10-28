// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R233_PrinterAdminProtocolExternalAccessRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R233_PrinterAdminProtocolExternalAccessRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R233",
            Name: "Printer Admin Protocol External Access",
            Category: "IotOtAdvanced",
            Description: "Detects printer administration protocols exposed across an external or unexpected boundary only when printer-admin protocol semantics are present.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R233.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R233",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            requiredFields: new[] { "source", "destination_or_host", "printer_admin_context" },
            evidenceFields: new[] { "network.destinationPort", "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "Traffic must carry concrete printer administration context such as IPP, JetDirect/PJL, CUPS, or printer admin paths.",
                "The communication must cross an external or unexpected segment boundary.",
                "Port-only matches without printer semantics should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on normal internal print jobs with no admin semantics.",
                "Do not alert on documentation pages or generic printer text without network printer context."
            },
            minimumConfidence: 78,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination+printer_protocol",
            falsePositives: new[] { "Managed print servers, cloud printing gateways, or vendor maintenance systems may legitimately touch printer admin protocols." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedPrintServers", "ApprovedPrinterSubnets" },
            requiredTests: new[] { "positive external pjl printer admin sample", "negative internal normal print job sample" });

        public R233_PrinterAdminProtocolExternalAccessRule() : base(Rule, Profile) { }

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch231235Evidence.PrinterAdmin(r)
                || _observations.Observe(r.Source, r.Destination, r.Id, context.TimestampUtc,
                    TimeSpan.FromMinutes(10), false) == 0) return NoMatch();
            return MatchIot(context, SeverityLevel.Medium, "Cleartext printer admin HTTP request crossed boundary",
                "PrinterAdmin", new[] {
                    new DetectionEvidenceItem("matched_conditions", "parsed_http_admin_path,tcp_631,boundary", "rule"),
                    new DetectionEvidenceItem("http.path", "[REDACTED]", "http") },
                confidence => { confidence.AddEvidence(0.30, "parsed-printer-admin-path");
                    confidence.AddEvidence(0.24, "tcp-631");
                    confidence.AddEvidence(0.18, "boundary"); },
                cooldownKey: r.Source + ":" + r.Destination + ":printer-admin");
        }
    }
}
