// SPDX-License-Identifier: MIT
// File: Services/RuleTuning/RuleNoiseBudgetEvaluator.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;

namespace Carthago.Services.RuleTuning
{
    public sealed record RuleNoiseBudgetSnapshot(
        string RuleId,
        int AlertCountLastHour,
        int HostAlertCountLastHour,
        int ShadowCountLastHour,
        RuleNoiseBudgetDecision? LastDecision);

    public sealed class RuleNoiseBudgetEvaluator
    {
        private readonly RuleNoiseBudgetStore _store;
        private readonly ConcurrentDictionary<string, List<DateTime>> _ruleAlertTimes = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, List<DateTime>> _hostAlertTimes = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, List<DateTime>> _ruleShadowTimes = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, RuleNoiseBudgetDecision> _lastDecisions = new(StringComparer.OrdinalIgnoreCase);

        public RuleNoiseBudgetEvaluator(RuleNoiseBudgetStore? store = null)
            => _store = store ?? new RuleNoiseBudgetStore();

        public RuleNoiseBudgetDecision Evaluate(DetectionEvent evt, RuleDescriptor descriptor, RuleTuningDecision tuningDecision, DateTime timestampUtc)
        {
            var budget = _store.GetBudget(descriptor.RuleId, descriptor.Category, tuningDecision.Tier);
            var sourceKey = string.IsNullOrWhiteSpace(evt.SourceIp) ? "unknown-source" : evt.SourceIp!;
            var windowStart = timestampUtc.AddHours(-1);

            if (tuningDecision.EffectiveMode != RuleMode.Alert || evt.SuppressionStatus != DetectionSuppressionStatus.None)
            {
                var shadowCount = AddAndCount(_ruleShadowTimes, descriptor.RuleId, timestampUtc, windowStart);
                RuleNoiseBudgetDecision warningDecision;
                if (shadowCount > budget.MaxShadowEventsPerRulePerHour)
                {
                    warningDecision = new RuleNoiseBudgetDecision(
                        RuleNoiseBudgetDisposition.WarningOnly,
                        $"Shadow volume for {descriptor.RuleId} exceeded {budget.MaxShadowEventsPerRulePerHour} events in the last hour.",
                        ObservedRuleCount: Count(_ruleAlertTimes, descriptor.RuleId, windowStart),
                        ObservedHostCount: Count(_hostAlertTimes, BuildHostKey(descriptor.RuleId, sourceKey), windowStart),
                        WindowStartUtc: windowStart,
                        Recommendation: "Keep journaling, but review thresholds, allowlists, or leave the rule in Shadow until tuned.",
                        DiagnosticsWarning: true);
                    _lastDecisions[descriptor.RuleId] = warningDecision;
                    return warningDecision;
                }

                warningDecision = new RuleNoiseBudgetDecision(
                    RuleNoiseBudgetDisposition.Allowed,
                    "Event remained non-paging after tuning and was still journaled.",
                    ObservedRuleCount: Count(_ruleAlertTimes, descriptor.RuleId, windowStart),
                    ObservedHostCount: Count(_hostAlertTimes, BuildHostKey(descriptor.RuleId, sourceKey), windowStart),
                    WindowStartUtc: windowStart,
                    Recommendation: "No additional noise action required.");
                _lastDecisions[descriptor.RuleId] = warningDecision;
                return warningDecision;
            }

            if (budget.AllowCriticalBypass && evt.Severity == SeverityLevel.Critical)
            {
                var bypassDecision = new RuleNoiseBudgetDecision(
                    RuleNoiseBudgetDisposition.Bypassed,
                    "Critical event bypassed the noise budget by policy.",
                    ObservedRuleCount: AddAndCount(_ruleAlertTimes, descriptor.RuleId, timestampUtc, windowStart),
                    ObservedHostCount: AddAndCount(_hostAlertTimes, BuildHostKey(descriptor.RuleId, sourceKey), timestampUtc, windowStart),
                    WindowStartUtc: windowStart,
                    Recommendation: "Maintain paging for critical high-fidelity detections while monitoring rule volume.");
                _lastDecisions[descriptor.RuleId] = bypassDecision;
                return bypassDecision;
            }

            var ruleCount = AddAndCount(_ruleAlertTimes, descriptor.RuleId, timestampUtc, windowStart);
            var hostCount = AddAndCount(_hostAlertTimes, BuildHostKey(descriptor.RuleId, sourceKey), timestampUtc, windowStart);
            var shadowCountAfterBackoff = Count(_ruleShadowTimes, descriptor.RuleId, windowStart);

            if (budget.MaxAlertsPerRulePerHour <= 0 || budget.MaxAlertsPerHostPerRulePerHour <= 0)
            {
                var disabledDecision = ShadowOrSuppress(descriptor.RuleId, budget, ruleCount, hostCount, timestampUtc, windowStart, shadowCountAfterBackoff, "Rule is configured for shadow-first budget handling in this environment.");
                _lastDecisions[descriptor.RuleId] = disabledDecision;
                return disabledDecision;
            }

            if (ruleCount > budget.MaxAlertsPerRulePerHour || hostCount > budget.MaxAlertsPerHostPerRulePerHour)
            {
                var noisyDecision = ShadowOrSuppress(descriptor.RuleId, budget, ruleCount, hostCount, timestampUtc, windowStart, shadowCountAfterBackoff, "Noise budget exceeded for rule or host.");
                _lastDecisions[descriptor.RuleId] = noisyDecision;
                return noisyDecision;
            }

            var allowedDecision = new RuleNoiseBudgetDecision(
                RuleNoiseBudgetDisposition.Allowed,
                "Alert remained within the configured noise budget.",
                ruleCount,
                hostCount,
                windowStart,
                "No demotion recommended.");
            _lastDecisions[descriptor.RuleId] = allowedDecision;
            return allowedDecision;
        }

        public RuleNoiseBudgetSnapshot Snapshot(string ruleId, string? sourceIp = null, DateTime? nowUtc = null)
        {
            var now = nowUtc ?? DateTime.UtcNow;
            var windowStart = now.AddHours(-1);
            var hostKey = BuildHostKey(ruleId, string.IsNullOrWhiteSpace(sourceIp) ? "unknown-source" : sourceIp!);
            _lastDecisions.TryGetValue(ruleId, out var decision);
            return new RuleNoiseBudgetSnapshot(
                ruleId,
                Count(_ruleAlertTimes, ruleId, windowStart),
                Count(_hostAlertTimes, hostKey, windowStart),
                Count(_ruleShadowTimes, ruleId, windowStart),
                decision);
        }

        public void Reset()
        {
            _ruleAlertTimes.Clear();
            _hostAlertTimes.Clear();
            _ruleShadowTimes.Clear();
            _lastDecisions.Clear();
        }

        private RuleNoiseBudgetDecision ShadowOrSuppress(string ruleId, RuleNoiseBudget budget, int ruleCount, int hostCount, DateTime timestampUtc, DateTime windowStartUtc, int currentShadowCount, string reason)
        {
            var nextShadowCount = AddAndCount(_ruleShadowTimes, ruleId, timestampUtc, windowStartUtc);
            if (budget.BackoffEnabled && nextShadowCount <= budget.MaxShadowEventsPerRulePerHour)
            {
                return new RuleNoiseBudgetDecision(
                    RuleNoiseBudgetDisposition.Shadowed,
                    reason,
                    ruleCount,
                    hostCount,
                    windowStartUtc,
                    "Demote to Shadow while the rule is noisy; consider thresholds, allowlists, or baseline requirements before promoting back to Alert.");
            }

            return new RuleNoiseBudgetDecision(
                RuleNoiseBudgetDisposition.Suppressed,
                reason,
                ruleCount,
                hostCount,
                windowStartUtc,
                "Suppress analyst paging until the hourly budget resets, but keep the detections durable in the journal.",
                DiagnosticsWarning: currentShadowCount >= budget.MaxShadowEventsPerRulePerHour);
        }

        private static int AddAndCount(ConcurrentDictionary<string, List<DateTime>> store, string key, DateTime timestampUtc, DateTime windowStartUtc)
        {
            var list = store.GetOrAdd(key, _ => new List<DateTime>());
            lock (list)
            {
                list.Add(timestampUtc);
                list.RemoveAll(entry => entry < windowStartUtc);
                return list.Count;
            }
        }

        private static int Count(ConcurrentDictionary<string, List<DateTime>> store, string key, DateTime windowStartUtc)
        {
            if (!store.TryGetValue(key, out var list))
                return 0;

            lock (list)
            {
                list.RemoveAll(entry => entry < windowStartUtc);
                return list.Count;
            }
        }

        private static string BuildHostKey(string ruleId, string sourceIp)
            => $"{ruleId}:{sourceIp}";
    }
}
