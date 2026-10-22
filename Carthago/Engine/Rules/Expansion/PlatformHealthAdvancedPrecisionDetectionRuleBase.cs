// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/PlatformHealthAdvancedPrecisionDetectionRuleBase.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Precision base for platform-health detections.
    ///
    /// These rules intentionally require explicit platform-health telemetry. They do not infer
    /// platform failures from ordinary network packets, because that would create noisy and
    /// untestable detections. A match should represent a concrete health signal produced by
    /// the detection pipeline, parser, journal, baseline store, content-pack loader, replay
    /// benchmark, or rule-governance subsystem.
    /// </summary>
    public abstract class PlatformHealthAdvancedPrecisionDetectionRuleBase : PrecisionTelemetryDetectionRuleBase
    {
        private static readonly ConcurrentDictionary<string, List<DateTime>> TimeWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> DistinctWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, DateTime> CooldownWindows = new(StringComparer.OrdinalIgnoreCase);

        private static readonly string[] PlatformHealthAnchors =
        {
            "carthago", "platform health", "health event", "pipeline health", "detector health",
            "detection engine", "rule engine", "sensor health", "journal", "outbox", "content pack",
            "baseline store", "feedback store", "telemetry coverage", "parser error", "replay benchmark"
        };

        protected PlatformHealthAdvancedPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }

        protected RuleEvaluationResult NoMatch()
            => RuleEvaluationResult.NoMatch(Descriptor.RuleId);

        protected static RulePrecisionProfile CreatePlatformHealthProfile(
            string ruleId,
            RulePrecisionMaturity maturity,
            RuleRuntimeMode defaultMode,
            IReadOnlyCollection<RuleTelemetryKind> requiredTelemetry,
            IReadOnlyCollection<string> requiredFields,
            IReadOnlyCollection<string> evidenceFields,
            IReadOnlyCollection<string> positiveConditions,
            IReadOnlyCollection<string> negativeConditions,
            int minimumConfidence,
            int? threshold,
            TimeSpan? window,
            TimeSpan? cooldown,
            string? distinctBy,
            IReadOnlyCollection<string> falsePositives,
            IReadOnlyCollection<string> tuningKnobs,
            IReadOnlyCollection<string> requiredTests)
        {
            return new RulePrecisionProfile(
                ruleId,
                maturity,
                defaultMode,
                new HashSet<RuleTelemetryKind>(requiredTelemetry),
                new HashSet<string>(requiredFields, StringComparer.OrdinalIgnoreCase),
                new HashSet<string>(new[] { "platform.component", "platform.event_type", "platform.error_code", "platform.metric", "platform.count" }, StringComparer.OrdinalIgnoreCase),
                new HashSet<string>(evidenceFields, StringComparer.OrdinalIgnoreCase),
                positiveConditions.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                negativeConditions.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                minimumConfidence,
                threshold,
                window,
                cooldown,
                distinctBy,
                falsePositives.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                tuningKnobs.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                Array.Empty<string>(),
                requiredTests.Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
        }

        protected RuleEvaluationResult MatchPlatformHealth(
            RuleEvaluationContext context,
            SeverityLevel severity,
            string summary,
            string detectionFamily,
            IEnumerable<DetectionEvidenceItem> evidenceItems,
            Action<ConfidenceBuilder> configureConfidence,
            int count = 1,
            TimeSpan? window = null,
            string? cooldownKey = null)
        {
            var record = context.Record;
            var component = Component(record);
            var items = new List<DetectionEvidenceItem>
            {
                new("platform.family", detectionFamily, "platform-health"),
                new("platform.component", component, "platform-health")
            };

            if (!string.IsNullOrWhiteSpace(record.Source))
                items.Add(new DetectionEvidenceItem("event.source", record.Source!, "platform-health"));
            if (!string.IsNullOrWhiteSpace(record.Destination))
                items.Add(new DetectionEvidenceItem("event.destination", record.Destination!, "platform-health"));
            if (!string.IsNullOrWhiteSpace(record.ApplicationProtocol))
                items.Add(new DetectionEvidenceItem("event.applicationProtocol", record.ApplicationProtocol!, "platform-health"));
            if (!string.IsNullOrWhiteSpace(record.ApplicationService))
                items.Add(new DetectionEvidenceItem("event.applicationService", record.ApplicationService!, "platform-health"));
            if (!string.IsNullOrWhiteSpace(record.ProcessName))
                items.Add(new DetectionEvidenceItem("process.name", record.ProcessName!, "process"));
            if (!string.IsNullOrWhiteSpace(record.Info))
                items.Add(new DetectionEvidenceItem("event.info", ShortText(record.Info!, 240), "platform-health"));

            if (evidenceItems != null)
                items.AddRange(evidenceItems);

            var evt = CreateDetectionEvent(
                context,
                severity,
                summary,
                items,
                configureConfidence,
                count,
                window.HasValue ? (int)window.Value.TotalSeconds : 0);

            var effectiveCooldownKey = string.IsNullOrWhiteSpace(cooldownKey) ? null : $"{Descriptor.RuleId}:{cooldownKey}";
            var cooldown = PrecisionProfile.Cooldown ?? TimeSpan.Zero;
            if (effectiveCooldownKey != null
                && cooldown > TimeSpan.Zero
                && IsSuppressedByCooldown(effectiveCooldownKey, context.TimestampUtc, cooldown, out var remaining))
            {
                SuppressForCooldown(evt, $"Rule-owned cooldown active for {remaining.TotalSeconds:F0}s.");
                EvidenceBuilder.AppendEvidence(evt, "suppression.remainingSeconds", Math.Ceiling(remaining.TotalSeconds).ToString(CultureInfo.InvariantCulture), "rule");
            }

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        protected static IEnumerable<DetectionEvidenceItem> AnalystContext(
            string whyMatched,
            string severityReason,
            string falsePositiveNotes,
            params string[] recommendedActions)
        {
            var items = new List<DetectionEvidenceItem>();
            if (!string.IsNullOrWhiteSpace(whyMatched))
                items.Add(new DetectionEvidenceItem("analyst.whyMatched", whyMatched.Trim(), "rule"));
            if (!string.IsNullOrWhiteSpace(severityReason))
                items.Add(new DetectionEvidenceItem("analyst.severityReason", severityReason.Trim(), "rule"));
            if (!string.IsNullOrWhiteSpace(falsePositiveNotes))
                items.Add(new DetectionEvidenceItem("analyst.falsePositives", falsePositiveNotes.Trim(), "rule"));

            for (var index = 0; index < recommendedActions.Length; index++)
            {
                if (!string.IsNullOrWhiteSpace(recommendedActions[index]))
                    items.Add(new DetectionEvidenceItem($"response.recommended.{index + 1}", recommendedActions[index].Trim(), "rule"));
            }

            return items;
        }

        protected static bool IsPlatformHealthRecord(TrafficRecord record)
        {
            var text = Text(record);
            if (ContainsAny(text, PlatformHealthAnchors))
                return true;

            return ContainsAny(record.ApplicationProtocol, "platform-health", "carthago-health")
                   || ContainsAny(record.ApplicationService, "platform-health", "carthago-health")
                   || ContainsAny(record.ProcessName, "carthago", "detector", "sensor", "rule-engine", "parser");
        }

        protected static string Text(TrafficRecord record)
            => string.Join(" ", new[]
            {
                record.Info,
                record.Protocol,
                record.ApplicationProtocol,
                record.ApplicationService,
                record.HttpMethod,
                record.HttpHost,
                record.HttpUri,
                record.HttpUserAgent,
                record.HttpRequestHeaders,
                record.Sni,
                record.ProcessName,
                record.DnsQname,
                record.Destination,
                record.Source
            }.Where(static value => !string.IsNullOrWhiteSpace(value))!);

        protected static string Component(TrafficRecord record)
        {
            var text = Text(record);
            if (ContainsAny(text, "outbox")) return "outbox";
            if (ContainsAny(text, "parser")) return "parser";
            if (ContainsAny(text, "geoip", "geo ip")) return "geoip";
            if (ContainsAny(text, "reputation")) return "reputation";
            if (ContainsAny(text, "baseline")) return "baseline-store";
            if (ContainsAny(text, "feedback")) return "feedback-store";
            if (ContainsAny(text, "content pack", "content-pack")) return "content-pack";
            if (ContainsAny(text, "replay benchmark", "benchmark")) return "replay-benchmark";
            if (ContainsAny(text, "suppression")) return "suppression";
            if (ContainsAny(text, "rule config", "profile drift", "configuration drift")) return "rule-config";
            if (ContainsAny(text, "field coverage", "telemetry coverage")) return "telemetry-coverage";
            if (ContainsAny(text, "rule engine", "detection engine")) return "rule-engine";
            return "platform";
        }

        protected static bool HasAll(string text, params string[] needles)
            => needles.All(needle => ContainsAny(text, needle));

        protected static bool ContainsAny(string? value, params string[] needles)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            foreach (var needle in needles)
            {
                if (!string.IsNullOrWhiteSpace(needle)
                    && value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        protected static string ShortText(string value, int maxLength = 180)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            var trimmed = value.Trim();
            return trimmed.Length <= maxLength ? trimmed : trimmed[..maxLength] + "...";
        }

        protected static int CountWindowEvents(string key, DateTime timestampUtc, TimeSpan window)
        {
            var cutoff = timestampUtc - window;
            var list = TimeWindows.GetOrAdd(key, static _ => new List<DateTime>());
            lock (list)
            {
                list.RemoveAll(item => item < cutoff);
                list.Add(timestampUtc);
                return list.Count;
            }
        }

        protected static int CountDistinctValues(string key, string value, DateTime timestampUtc, TimeSpan window)
        {
            if (string.IsNullOrWhiteSpace(value))
                return 0;

            var cutoff = timestampUtc - window;
            var set = DistinctWindows.GetOrAdd(key, static _ => new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase));
            foreach (var pair in set.ToArray())
            {
                if (pair.Value < cutoff)
                    set.TryRemove(pair.Key, out _);
            }

            set[value] = timestampUtc;
            return set.Count;
        }

        protected static string RuleKey(TrafficRecord record)
        {
            var text = Text(record);
            var marker = ExtractAfterAny(text, "ruleid=", "rule_id=", "rule:", "rule ");
            return string.IsNullOrWhiteSpace(marker) ? "unknown-rule" : marker;
        }

        protected static string MetricKey(TrafficRecord record)
        {
            var text = Text(record);
            var marker = ExtractAfterAny(text, "metric=", "field=", "store=", "component=");
            return string.IsNullOrWhiteSpace(marker) ? Component(record) : marker;
        }

        protected static string ExtractAfterAny(string text, params string[] markers)
        {
            if (string.IsNullOrWhiteSpace(text))
                return string.Empty;

            foreach (var marker in markers)
            {
                var index = text.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                if (index < 0)
                    continue;

                var start = index + marker.Length;
                var end = start;
                while (end < text.Length && (char.IsLetterOrDigit(text[end]) || text[end] == '-' || text[end] == '_' || text[end] == '.'))
                    end++;

                if (end > start)
                    return text[start..end].Trim();
            }

            return string.Empty;
        }

        protected static IEnumerable<DetectionEvidenceItem> MatchedConditions(params string[] conditions)
        {
            yield return new DetectionEvidenceItem("matched_conditions", string.Join(",", conditions.Where(static value => !string.IsNullOrWhiteSpace(value))), "rule");
        }


        public static void ResetSharedStateForReplay()
        {
            TimeWindows.Clear();
            DistinctWindows.Clear();
            CooldownWindows.Clear();
        }

        protected static bool IsSuppressedByCooldown(string key, DateTime now, TimeSpan cooldown, out TimeSpan remaining)
        {
            remaining = TimeSpan.Zero;
            if (cooldown <= TimeSpan.Zero)
                return false;

            if (CooldownWindows.TryGetValue(key, out var lastSeen))
            {
                var elapsed = now - lastSeen;
                if (elapsed < cooldown)
                {
                    remaining = cooldown - elapsed;
                    return true;
                }
            }

            CooldownWindows[key] = now;
            return false;
        }
    }
}
