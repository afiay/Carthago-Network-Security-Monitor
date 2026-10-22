// SPDX-License-Identifier: MIT
// File: Services/RuleTuning/RuleFeedbackAdvisor.cs
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Tuning;
using Carthago.Services.Feedback;

namespace Carthago.Services.RuleTuning
{
    public sealed record RuleFeedbackSummary(
        string RuleId,
        int FalsePositiveCount,
        int TruePositiveCount,
        int ExpectedActivityCount,
        int SuppressSimilarCount);

    public sealed record RuleFeedbackRecommendation(
        string RuleId,
        RuleMode RecommendedMode,
        double RiskContributionMultiplier,
        string Message,
        int? RecommendedThreshold = null);

    public sealed class RuleFeedbackAdvisor
    {
        private readonly DetectionFeedbackStore _store;

        public RuleFeedbackAdvisor(DetectionFeedbackStore? store = null)
            => _store = store ?? DetectionFeedbackStore.Current;

        public async Task<RuleFeedbackSummary> SummarizeAsync(string ruleId, CancellationToken cancellationToken = default)
        {
            var falsePositives = 0;
            var truePositives = 0;
            var expectedActivity = 0;
            var suppressSimilar = 0;

            await foreach (var feedback in _store.ReadAllAsync(cancellationToken))
            {
                if (!string.Equals(feedback.RuleId, ruleId, StringComparison.OrdinalIgnoreCase))
                    continue;

                switch (feedback.Verdict)
                {
                    case DetectionFeedbackVerdict.FalsePositive:
                        falsePositives++;
                        break;
                    case DetectionFeedbackVerdict.TruePositive:
                        truePositives++;
                        break;
                    case DetectionFeedbackVerdict.ExpectedActivity:
                        expectedActivity++;
                        break;
                    case DetectionFeedbackVerdict.SuppressSimilar:
                        suppressSimilar++;
                        break;
                }
            }

            return new RuleFeedbackSummary(ruleId, falsePositives, truePositives, expectedActivity, suppressSimilar);
        }

        public RuleFeedbackRecommendation Recommend(RuleTuningDecision tuningDecision, RuleFeedbackSummary summary)
        {
            if (tuningDecision == null) throw new ArgumentNullException(nameof(tuningDecision));
            if (summary == null) throw new ArgumentNullException(nameof(summary));

            var mode = tuningDecision.DefaultMode;
            var multiplier = 1.0;
            var message = "Feedback is neutral; keep the current profile-driven mode and continue collecting evidence.";
            int? threshold = null;

            if (summary.FalsePositiveCount >= 3 && summary.FalsePositiveCount > Math.Max(1, summary.TruePositiveCount))
            {
                multiplier = summary.ExpectedActivityCount > 0 ? 0.70 : 0.75;
                mode = mode == RuleMode.Disabled ? RuleMode.Disabled : RuleMode.Shadow;
                threshold = 1;
                message = tuningDecision.RuleId switch
                {
                    "R148" => "R148 is noisy for dynamic DNS in this environment; keep it in Shadow or add allowed domains.",
                    "R113" => "R113 repeatedly fires for an approved MQTT broker; keep it in Shadow or add the broker to Approved.MqttBrokers.",
                    _ => $"{tuningDecision.RuleId} has repeated false positives; keep it in Shadow and tune thresholds or allowlists before promoting it again."
                };
            }
            else if (summary.ExpectedActivityCount >= 2)
            {
                multiplier = 0.85;
                mode = mode == RuleMode.Disabled ? RuleMode.Disabled : RuleMode.Shadow;
                message = tuningDecision.RuleId switch
                {
                    "R113" => "R113 is repeatedly marked expected; add the broker to Approved.MqttBrokers so it stops paging analysts.",
                    _ => $"{tuningDecision.RuleId} is repeatedly marked expected activity; add an allowlist or leave it in Shadow for this profile."
                };
            }
            else if (summary.TruePositiveCount >= 2 && summary.TruePositiveCount >= summary.FalsePositiveCount)
            {
                multiplier = 1.10;
                mode = tuningDecision.DefaultMode == RuleMode.Disabled ? RuleMode.Shadow : RuleMode.Alert;
                message = tuningDecision.RuleId switch
                {
                    "R102" => "R102 produced repeated high-confidence true positives; keep Alert enabled for this profile.",
                    "R485" => "R485 fires in the OT segment and has been marked true positive; promote or keep it at Alert for OTSegment.",
                    _ => $"{tuningDecision.RuleId} has repeated true positives; keep Alert enabled and review whether thresholds can be tightened without losing coverage."
                };
            }

            if (mode == RuleMode.Disabled && tuningDecision.DefaultMode != RuleMode.Disabled)
                mode = RuleMode.Shadow;

            return new RuleFeedbackRecommendation(summary.RuleId, mode, multiplier, message, threshold);
        }
    }
}
