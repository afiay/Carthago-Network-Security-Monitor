// SPDX-License-Identifier: MIT
// File: Engine/RuleEngine.Suppressions.cs
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services.RuleTuning;
using Carthago.Services.Diagnostics;

namespace Carthago.Services
{
    public static partial class RuleEngine
    {
        private static readonly RuleSuppressionPolicyEvaluator _suppressionPolicyEvaluator = new();

        private static RuleSuppressionDecision ApplySuppressionPolicy(DetectionEvent evt, RuleDescriptor descriptor, TrafficRecord record, DateTime timestampUtc)
        {
            var decision = _suppressionPolicyEvaluator.Evaluate(evt, record, descriptor, timestampUtc);
            if (!decision.Matched)
                return decision;

            EvidenceBuilder.AppendEvidence(evt, "suppressionPolicy.policyId", decision.PolicyId ?? "unknown", "suppression-policy");
            EvidenceBuilder.AppendEvidence(evt, "suppressionPolicy.scope", decision.Scope?.ToString() ?? "unknown", "suppression-policy");
            EvidenceBuilder.AppendEvidence(evt, "suppressionPolicy.matchValue", decision.MatchValue ?? "unknown", "suppression-policy");
            EvidenceBuilder.AppendEvidence(evt, "suppressionPolicy.action", decision.Action.ToString(), "suppression-policy");
            EvidenceBuilder.AppendEvidence(evt, "suppressionPolicy.reason", decision.Reason, "suppression-policy");
            if (!string.IsNullOrWhiteSpace(decision.CreatedBy))
                EvidenceBuilder.AppendEvidence(evt, "suppressionPolicy.createdBy", decision.CreatedBy!, "suppression-policy");
            if (!string.IsNullOrWhiteSpace(decision.TicketReference))
                EvidenceBuilder.AppendEvidence(evt, "suppressionPolicy.ticket", decision.TicketReference!, "suppression-policy");
            if (decision.ExpiresUtc.HasValue)
                EvidenceBuilder.AppendEvidence(evt, "suppressionPolicy.expiresUtc", decision.ExpiresUtc.Value.ToString("O"), "suppression-policy");

            evt.SuppressionStatus = decision.Action switch
            {
                RuleSuppressionAction.Shadow => DetectionSuppressionStatus.Shadowed,
                RuleSuppressionAction.Suppress => DetectionSuppressionStatus.Suppressed,
                _ => evt.SuppressionStatus
            };

            RuleSuppressionAuditStore.Record(decision, timestampUtc);
            RuleRuntimeTelemetryStore.RecordTuningDecision(
                evt.RuleId,
                timestampUtc,
                $"SuppressionPolicy:{decision.Action}:{decision.PolicyId}");
            return decision;
        }
    }
}
