// SPDX-License-Identifier: MIT
// File: Engine/RuleEngine.NoiseBudget.cs
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services.RuleTuning;

namespace Carthago.Services
{
    public static partial class RuleEngine
    {
        private static readonly RuleNoiseBudgetEvaluator _noiseBudgetEvaluator = new();

        private static RuleNoiseBudgetDecision ApplyNoiseBudget(DetectionEvent evt, RuleDescriptor descriptor, RuleTuningDecision tuningDecision, DateTime timestampUtc)
        {
            var decision = _noiseBudgetEvaluator.Evaluate(evt, descriptor, tuningDecision, timestampUtc);
            EvidenceBuilder.AppendEvidence(evt, "noiseBudget.disposition", decision.Disposition.ToString(), "noise-budget");
            EvidenceBuilder.AppendEvidence(evt, "noiseBudget.reason", decision.Reason, "noise-budget");
            EvidenceBuilder.AppendEvidence(evt, "noiseBudget.recommendation", decision.Recommendation, "noise-budget");

            evt.SuppressionStatus = decision.Disposition switch
            {
                RuleNoiseBudgetDisposition.Allowed => evt.SuppressionStatus,
                RuleNoiseBudgetDisposition.Bypassed => evt.SuppressionStatus,
                RuleNoiseBudgetDisposition.WarningOnly => evt.SuppressionStatus == DetectionSuppressionStatus.None ? DetectionSuppressionStatus.Shadowed : evt.SuppressionStatus,
                RuleNoiseBudgetDisposition.Shadowed => DetectionSuppressionStatus.Shadowed,
                RuleNoiseBudgetDisposition.Suppressed => DetectionSuppressionStatus.Suppressed,
                _ => evt.SuppressionStatus
            };

            return decision;
        }
    }
}
