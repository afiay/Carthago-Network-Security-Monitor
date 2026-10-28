// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R249_SmbUploadToExternalHostRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R249_SmbUploadToExternalHostRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R249", "SMB Upload To External Host", "ExfiltrationAdvanced", "Detects SMB write/upload behavior crossing to an external target, avoiding generic port-445 noise.", SeverityLevel.Critical, "Rules.R249.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R249", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Payload }, new[] { "source", "external_destination", "smb_context", "write_semantics" }, new[] { "network.destinationPort", "matched_conditions", "flow.bytes" }, new[] { "Traffic must cross internal-to-external.", "SMB/CIFS context must be present.", "SMB write/create/upload semantics must be visible." }, new[] { "Do not alert on internal file shares.", "Do not alert on blocked scans with no SMB write semantics." }, 86, 1, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(45), "source+destination+smb", new[] { "Rare partner SMB file exchange could match, but external SMB should normally be exceptional." }, new[] { "Mode", "ApprovedPartnerSmbHosts", "CooldownSeconds" }, new[] { "positive external SMB write sample", "negative internal SMB file share sample" });
        public R249_SmbUploadToExternalHostRule() : base(Rule, Profile) { }
        private readonly NetworkBatch156165ReplayGuard _replay = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch246250Evidence.SmbWrite(record)
                || !_replay.Observe(record, context.TimestampUtc)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "parsed_smb2_write_request,external_destination", "rule"),
                new("smb.transfer_status", "write_request_only_unverified", "rule")
            };
            evidence.AddRange(AnalystContext("A captured SMB2 WRITE request targeted an external host.",
                "The request does not prove that a server accepted or committed the write.",
                "Approved partner SMB traffic may exist.",
                "Corroborate SMB response and endpoint file-operation telemetry."));
            return MatchExfiltration(context, SeverityLevel.Critical,
                "External SMB2 write request observed", "SmbExternalUpload", evidence,
                c => { c.AddEvidence(0.30, "parsed-smb2-write-request"); c.AddEvidence(0.24, "external-smb-target"); c.AddEvidence(0.14, "unusual-protocol-boundary"); },
                cooldownKey: record.Source + ":" + record.Destination + ":smb-write");

        }
    }
}
