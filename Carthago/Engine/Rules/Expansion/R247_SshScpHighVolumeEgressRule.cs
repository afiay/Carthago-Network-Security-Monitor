// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R247_SshScpHighVolumeEgressRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R247_SshScpHighVolumeEgressRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R247", "SSH SCP High Volume Egress", "ExfiltrationAdvanced", "Detects high-volume SSH/SCP/SFTP egress from internal hosts to external targets with process or protocol evidence.", SeverityLevel.High, "Rules.R247.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R247", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process }, new[] { "source", "external_destination", "ssh_scp_context", "bytes" }, new[] { "network.destinationPort", "flow.bytes", "process.name", "matched_conditions" }, new[] { "Traffic must be internal-to-external.", "SSH/SCP/SFTP context must be visible through port, protocol, service, process, or text evidence.", "Volume must exceed the high-egress threshold." }, new[] { "Do not alert on low-volume admin SSH.", "Do not alert on approved backup/replication identities." }, 82, 1, TimeSpan.FromMinutes(20), TimeSpan.FromMinutes(30), "source+destination+ssh", new[] { "Legitimate SFTP exports, offsite backup, and admin file transfer can match." }, new[] { "Mode", "HighVolumeBytes", "ApprovedSftpServers", "ApprovedAdminHosts" }, new[] { "positive high-volume scp sample", "negative low-volume ssh admin sample" });
        public R247_SshScpHighVolumeEgressRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var bytes = AddBytesWindow($"R247:{record.Source}:{record.Destination}:ssh", context.TimestampUtc, TransferBytes(record), TimeSpan.FromMinutes(20));
            if (!IsOutboundExternal(record) || !IsSshScpOrSftpContext(record) || bytes < 150 * 1024 * 1024 || IsLikelyApprovedSyncOrBackup(record)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>(TransferEvidence(record, "ssh_scp_context,external_egress,high_volume_window")) { new("flow.windowBytes", bytes.ToString(System.Globalization.CultureInfo.InvariantCulture), "flow") };
            evidence.AddRange(AnalystContext("An internal host produced high-volume SSH/SCP/SFTP egress to an external target.", "Severity is High because encrypted SSH file-transfer channels are common for quiet exfiltration.", "Approved SFTP exports and backup replication can match; tune by identity, source, and destination.", "Confirm whether the source normally performs external SFTP/SCP transfers.", "Review command/process evidence and transferred volume window."));
            return MatchExfiltration(context, SeverityLevel.High, "High-volume SSH/SCP/SFTP egress", "SshScpHighVolumeEgress", evidence, c => { c.AddEvidence(0.26, "ssh-scp-context"); c.AddEvidence(0.24, "high-volume-window"); c.AddEvidence(0.16, "external-destination"); }, count: 1, window: TimeSpan.FromMinutes(20), cooldownKey: CooldownIdentity(record, "ssh-scp-volume"));
        }
    }
}
