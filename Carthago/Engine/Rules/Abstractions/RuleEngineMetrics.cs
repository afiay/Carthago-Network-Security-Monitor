// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/RuleEngineMetrics.cs
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Linq;

namespace Carthago.Services
{
    public static class RuleMetricNames
    {
        public const string RuleEvaluatedTotal = "rule_evaluated_total";
        public const string RuleMatchedTotal = "rule_matched_total";
        public const string RuleSuppressedTotal = "rule_suppressed_total";
        public const string RuleShadowedTotal = "rule_shadowed_total";
        public const string RuleEmittedTotal = "rule_emitted_total";
        public const string RulePersistedTotal = "rule_persisted_total";
        public const string RuleSinkFailedTotal = "rule_sink_failed_total";
        public const string RuleFailedTotal = "rule_failed_total";
        public const string RuleSkippedDisabledTotal = "rule_skipped_disabled_total";
        public const string JournalWriteFailedTotal = "journal_write_failed_total";
        public const string DetectionOutboxPendingTotal = "detection_outbox_pending_total";
    }

    public static class RuleEngineMetrics
    {
        private static readonly ConcurrentDictionary<string, long> _counters = new();

        public static void Increment(string? ruleId, string metricName, long amount = 1)
        {
            var key = string.IsNullOrWhiteSpace(ruleId) ? metricName : $"{ruleId}:{metricName}";
            _counters.AddOrUpdate(key, amount, (_, current) => current + amount);
        }

        public static long Get(string? ruleId, string metricName)
        {
            var key = string.IsNullOrWhiteSpace(ruleId) ? metricName : $"{ruleId}:{metricName}";
            return _counters.TryGetValue(key, out var value) ? value : 0;
        }

        public static void Reset(string? ruleId = null, string? metricName = null)
        {
            if (ruleId == null && metricName == null)
            {
                _counters.Clear();
                return;
            }

            foreach (var key in _counters.Keys.ToArray())
            {
                if (ruleId != null && !key.StartsWith($"{ruleId}:", System.StringComparison.OrdinalIgnoreCase))
                    continue;

                if (metricName != null)
                {
                    var suffix = ruleId == null ? metricName : $":{metricName}";
                    if (!key.EndsWith(suffix, System.StringComparison.OrdinalIgnoreCase))
                        continue;
                }

                _counters.TryRemove(key, out _);
            }
        }

        public static IReadOnlyDictionary<string, long> Snapshot() => _counters.ToArray().ToDictionary(kv => kv.Key, kv => kv.Value);
    }
}
