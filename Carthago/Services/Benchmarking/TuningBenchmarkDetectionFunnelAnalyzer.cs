// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/TuningBenchmarkDetectionFunnelAnalyzer.cs
using System;
using System.Collections.Generic;
using System.Linq;

namespace Carthago.Services.Benchmarking
{
    /// <summary>
    /// Three separate, auditable stages of an offline replay:
    /// 1) expected malicious rule recognized by its detector;
    /// 2) recognized match accepted or constrained by the selected profile;
    /// 3) a simulated alert recorded by the replay's policy evaluator.
    ///
    /// Matching in Shadow mode is never an alert. Neither a detection match
    /// nor an alert-eligible decision is proof of malicious production traffic.
    /// </summary>
    public static class TuningBenchmarkDetectionFunnelAnalyzer
    {
        public static Dictionary<string, TuningBenchmarkDetectionFunnel> Analyze(TuningBenchmarkReport report)
        {
            if (report == null) throw new ArgumentNullException(nameof(report));

            var profiles = report.ProfileResults.Keys
                .Concat(report.SampleResults.SelectMany(static sample => sample.Profiles.Keys))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static profile => profile, StringComparer.OrdinalIgnoreCase);

            var result = new Dictionary<string, TuningBenchmarkDetectionFunnel>(StringComparer.OrdinalIgnoreCase);
            foreach (var profileName in profiles)
            {
                var funnel = new TuningBenchmarkDetectionFunnel { ProfileName = profileName };
                var eligibleEmitted = 0;
                foreach (var sample in report.SampleResults)
                {
                    sample.Profiles.TryGetValue(profileName, out var profile);

                    if (sample.Classification == ReplaySampleClassification.Benign)
                    {
                        funnel.BenignRawRuleMatches += sample.ActualMatches
                            .Distinct(StringComparer.OrdinalIgnoreCase).Count();
                        if (profile != null)
                            funnel.BenignSimulatedAlerts += profile.AlertRuleIds
                                .Distinct(StringComparer.OrdinalIgnoreCase).Count();
                        continue;
                    }

                    var matched = new HashSet<string>(
                        sample.ActualMatches, StringComparer.OrdinalIgnoreCase);
                    var alerts = new HashSet<string>(
                        profile?.AlertRuleIds ?? Enumerable.Empty<string>(), StringComparer.OrdinalIgnoreCase);

                    foreach (var expectedRule in sample.ExpectedMatches
                        .Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        funnel.ExpectedMaliciousRules++;
                        if (!matched.Contains(expectedRule))
                        {
                            funnel.DetectorMisses++;
                            // Unexpected alerts must not be counted as detector
                            // recognition; flag a contradiction in replay results.
                            if (alerts.Contains(expectedRule))
                                funnel.AlertDecisionMismatches++;
                            continue;
                        }

                        funnel.RecognizedByDetector++;
                        var decision = profile?.RuleDecisions.FirstOrDefault(item =>
                            string.Equals(item.RuleId, expectedRule, StringComparison.OrdinalIgnoreCase));
                        var alerted = alerts.Contains(expectedRule);
                        if (alerted)
                            funnel.SimulatedAlerted++;

                        if (decision == null)
                        {
                            funnel.MissingPolicyDecisions++;
                            if (alerted)
                                funnel.AlertDecisionMismatches++;
                            continue;
                        }

                        if (string.Equals(decision.EffectiveMode, "Alert", StringComparison.OrdinalIgnoreCase))
                        {
                            funnel.PolicyEligibleRules++;
                            if (alerted)
                                eligibleEmitted++;
                            else
                                funnel.EligibleButNotAlerted++;
                        }
                        else if (string.Equals(decision.EffectiveMode, "Shadow", StringComparison.OrdinalIgnoreCase))
                        {
                            if (alerted)
                                funnel.AlertDecisionMismatches++;
                            else
                                funnel.PolicyShadowed++;
                        }
                        else if (string.Equals(decision.EffectiveMode, "Disabled", StringComparison.OrdinalIgnoreCase)
                            || string.Equals(decision.EffectiveMode, "Suppressed", StringComparison.OrdinalIgnoreCase))
                        {
                            if (alerted)
                                funnel.AlertDecisionMismatches++;
                            else
                                funnel.PolicyDisabled++;
                        }
                        else
                        {
                            funnel.MissingPolicyDecisions++;
                            if (alerted)
                                funnel.AlertDecisionMismatches++;
                        }
                    }
                }

                funnel.DetectorRecognitionRate = Ratio(funnel.RecognizedByDetector, funnel.ExpectedMaliciousRules);
                funnel.AlertLevelRecall = Ratio(funnel.SimulatedAlerted, funnel.ExpectedMaliciousRules);
                funnel.EligibleAlertEmissionRate = Ratio(eligibleEmitted, funnel.PolicyEligibleRules);
                result.Add(profileName, funnel);
            }

            return result;
        }

        private static double? Ratio(int numerator, int denominator)
            => denominator == 0 ? null : (double)numerator / denominator;
    }
}
