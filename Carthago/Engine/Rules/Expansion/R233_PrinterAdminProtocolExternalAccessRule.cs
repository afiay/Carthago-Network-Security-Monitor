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

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsPrinterAdminContext(record) || !HasPrinterAdminSemantics(record) || !IsUnexpectedSegmentCrossing(record))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "printer_admin_context,admin_semantics,unexpected_boundary", "rule"),
                new("network.destinationPort", (record.DestinationPort ?? 0).ToString(System.Globalization.CultureInfo.InvariantCulture), "flow"),
                new("http.path", string.IsNullOrWhiteSpace(record.HttpUri) ? "/" : record.HttpUri!, "http")
            };
            evidence.AddRange(AnalystContext(
                "Printer administration protocol semantics were observed across an external or unexpected network boundary.",
                "Severity is Medium because exposed IPP, JetDirect, PJL, or CUPS administration can enable printer inventory, job theft, configuration changes, or lateral movement support.",
                "Approved print servers and managed vendor maintenance paths can match; tune them explicitly instead of broadening the rule.",
                "Verify whether the source is an approved print server or management station.",
                "Review the printer for configuration changes, new jobs, and unexpected PJL/CUPS administrative commands."));

            return MatchIot(
                context,
                SeverityLevel.Medium,
                "Printer administration protocol crossed an unexpected boundary",
                "PrinterAdmin",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "printer-admin-context");
                    confidence.AddEvidence(0.24, "admin-semantics");
                    confidence.AddEvidence(0.18, "unexpected-boundary");
                },
                cooldownKey: $"{record.Source}:{record.Destination}:{record.DestinationPort}:printer-admin");
        }
    }
}
