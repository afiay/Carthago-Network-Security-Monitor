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
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsOutboundExternal(record) || !IsSmbContext(record) || !HasSmbWriteSemantics(record)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>(TransferEvidence(record, "smb_context,write_semantics,external_destination"));
            evidence.AddRange(AnalystContext("SMB write/upload semantics crossed from an internal source to an external target.", "Severity is Critical because SMB exposure or external SMB writes are uncommon and can indicate data theft or misrouted file sharing.", "Approved partner SMB flows are rare; tune them narrowly if they exist.", "Block or review external SMB reachability.", "Identify the share/path and source process if endpoint telemetry is available."));
            return MatchExfiltration(context, SeverityLevel.Critical, "SMB write/upload to external host", "SmbExternalUpload", evidence, c => { c.AddEvidence(0.30, "smb-write-semantics"); c.AddEvidence(0.24, "external-smb-target"); c.AddEvidence(0.14, "unusual-protocol-boundary"); }, cooldownKey: CooldownIdentity(record, "smb-upload"));
        }
    }
}
