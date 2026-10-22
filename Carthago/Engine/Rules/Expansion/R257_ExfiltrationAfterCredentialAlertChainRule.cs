// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R257_ExfiltrationAfterCredentialAlertChainRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R257_ExfiltrationAfterCredentialAlertChainRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R257", "Exfiltration After Credential Alert Chain", "ExfiltrationAdvanced", "Detects exfiltration-like egress when the same record/source carries credential-compromise context or recent credential-alert indicators.", SeverityLevel.Critical, "Rules.R257.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R257", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Identity, RuleTelemetryKind.Payload }, new[] { "source", "credential_alert_indicator", "external_egress", "exfil_indicator" }, new[] { "matched_conditions", "flow.bytes", "file_or_path.indicator" }, new[] { "Credential-compromise context must be present in observable telemetry or upstream alert text.", "External egress must be upload-like, bulk, archive-like, sensitive-file-like, or encoded.", "Rule should not infer a chain from source identity alone." }, new[] { "Do not alert on credential alerts without egress.", "Do not alert on egress without credential-compromise context." }, 88, 1, TimeSpan.FromHours(2), TimeSpan.FromHours(1), "source+credential_chain+destination", new[] { "Incident notes or test data containing credential keywords can match if fed into traffic info fields." }, new[] { "Mode", "ChainWindow", "MinimumBytes", "CredentialRuleIds", "CooldownSeconds" }, new[] { "positive credential alert followed by archive upload sample", "negative credential alert without egress sample" });
        public R257_ExfiltrationAfterCredentialAlertChainRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasCredentialAlertChainIndicator(record) || !IsOutboundExternal(record)) return NoMatch();
            var hasBlob = HasBase64BlobInRequest(record, out _);
            var exfilSupport = IsUploadLike(record) || IsLargeOutboundTransfer(record, 25 * 1024 * 1024) || LooksLikeArchiveTransfer(record) || LooksLikeSensitiveFileTransfer(record) || LooksLikeDatabaseDumpTransfer(record) || hasBlob;
            if (!exfilSupport) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>(TransferEvidence(record, "credential_compromise_context,external_egress,exfil_support"));
            evidence.AddRange(AnalystContext("Credential-compromise context and exfiltration-like egress were observed for the same source context.", "Severity is Critical because credential compromise followed by data movement is a strong incident chain.", "Only as reliable as the upstream credential context. Avoid feeding generic notes into Info without source tagging.", "Contain or isolate the source while validating the egress destination.", "Rotate credentials associated with the source/user if unauthorized.", "Search for staging and archive creation before the egress."));
            return MatchExfiltration(context, SeverityLevel.Critical, "Exfiltration-like egress after credential-compromise context", "CredentialToExfilChain", evidence, c => { c.AddEvidence(0.30, "credential-compromise-context"); c.AddEvidence(0.26, "exfiltration-support"); c.AddEvidence(0.18, "external-egress"); }, cooldownKey: CooldownIdentity(record, "credential-exfil-chain"));
        }
    }
}
