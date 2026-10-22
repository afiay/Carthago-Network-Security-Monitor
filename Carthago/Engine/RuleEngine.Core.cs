// SPDX-License-Identifier: MIT
// File: Engine/RuleEngine.Core.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using Carthago.Engine.ContentPacks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Execution;
using Carthago.Engine.Rules.Health;
using Carthago.Models;
using Carthago.Services.Diagnostics;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Services
{
    /// <summary>
    /// Public API, helpers, suppression, cleanup, correlation, logging.
    /// NOTE: This file intentionally contains NO defaults, NO RuleCfg, and
    /// NO LoadConfig/StartConfigWatcher/_cfg/_json declarations.
    /// Those live exclusively in RuleEngine.Config.cs (same partial class).
    /// </summary>
    public static partial class RuleEngine
    {
        // ===== Global runtime state (shared across partials) =====
        private static readonly ConcurrentDictionary<SupprKey, DateTime> _lastAlertAt = new();
        private static readonly ConcurrentDictionary<string, DateTime> _lastSeenSrc = new(StringComparer.Ordinal);
        private static readonly Lazy<IReadOnlyList<IDetectionRule>> _rules = new(() => RuleRegistry.CreateDefaultRules());
        private static readonly ContentPackRegistry _contentPackRegistry = new();
        private static readonly RuleCandidateSelector _candidateSelector = new();
        private static readonly AsyncLocal<string?> _suppressedRuleId = new();
        private static RuleEvaluationTrace? _lastTrace;

        // Correlation state (by (src[+pid]) -> recent rule hits)
        private static readonly ConcurrentDictionary<string, List<(string RuleId, DateTime Ts)>> _entityHits =
            new(StringComparer.Ordinal);

        private const int CorrelationWindowSeconds = 300; // 5 minutes

        // ---- Light diagnostics (counters only) ----
        private static long _evalCalls;
        private static long _emittedEvents;
        private static DateTime _lastDiagPrint = DateTime.MinValue;
        private static DateTime _lastDetectionAt = DateTime.MinValue;
        private static bool DiagEnabled { get; set; } = false;

        // ---- Helpers (null/format) ----
        private static string NS(string? s) => string.IsNullOrWhiteSpace(s) ? "unknown" : s;
        private static string NP(string? s) => s ?? "N/A";

        // ---- Sensitivity scaling ----
        private static int ScaleCount(int baseVal, Sensitivity s) => Math.Max(1, (int)Math.Round(baseVal / s.Factor()));
        private static long ScaleBytes(long baseVal, Sensitivity s) => Math.Max(1, (long)Math.Round(baseVal / s.Factor()));
        private static double ScaleFloat(double baseVal, Sensitivity s) => Math.Max(0.0001, baseVal / s.Factor());

        // ===== Public API =====
        public static RuleEvaluationTrace? LastEvaluationTrace => _lastTrace;

        private static IReadOnlyList<IDetectionRule> GetActiveRules(RuleEvaluationTrace trace)
        {
            IEnumerable<string> configuredRuleIds = _cfg.Rules == null
                ? Array.Empty<string>()
                : _cfg.Rules.Keys;
            var activation = _contentPackRegistry.CreateActivation(new ContentPackActivationOptions
            {
                ConfiguredRuleIds = configuredRuleIds
            });

            foreach (var skippedRuleId in activation.SkippedConfiguredRuleIds)
            {
                if (!trace.SkippedRuleIds.Contains(skippedRuleId, StringComparer.OrdinalIgnoreCase))
                    trace.SkippedRuleIds.Add(skippedRuleId);

                trace.SelectorReasonsByRuleId[skippedRuleId] = "Configured content-pack rule skipped because its pack is not enabled.";
            }

            if (activation.ActiveRules.Count == 0)
                return _rules.Value;

            return _rules.Value.Concat(activation.ActiveRules)
                .OrderBy(static rule => rule.Descriptor.RuleId, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        private static RuleMode ResolveConfiguredRuleMode(IDetectionRule rule, TrafficRecord record, double confidenceScore = 1.0)
        {
            if (rule is IContentPackRule contentPackRule)
                return ResolveContentPackConfiguredMode(contentPackRule, record, confidenceScore);

            return GetRuleMode(rule.Descriptor.RuleId, rule.Descriptor.EnabledByDefault);
        }

        private static RuleMode ResolveContentPackConfiguredMode(IContentPackRule rule, TrafficRecord record, double confidenceScore)
        {
            var enabledOverride = TryGetRuleEnabledOverride(rule.Descriptor.RuleId);
            if (enabledOverride == false)
                return RuleMode.Disabled;

            var explicitMode = TryGetRuleModeOverride(rule.Descriptor.RuleId);
            if (explicitMode.HasValue)
                return explicitMode.Value;

            var telemetry = RuleTelemetryValidator.Validate(rule, record);
            return _contentPackRegistry.ResolvePackRuleMode(
                rule.PackId,
                rule.Descriptor.RuleId,
                _cfg.Profile,
                confidenceScore,
                telemetry.CanRunSafely,
                ApprovedAssetRegistry.Current.Options);
        }

        public static List<DetectionEvent> Evaluate(TrafficRecord record, Sensitivity sensitivity)
        {
            var results = new List<DetectionEvent>(capacity: 8);
            if (record == null) return results;

            var now = DateTime.UtcNow;
            RuleTelemetryCoverageStore.ObserveRecord(record, now);
            var healthSnapshot = RuleEngineHealthState.Snapshot(now);
            RuleEngineHealthState.RecordEvaluationStart(now);
            var context = new RuleEvaluationContext(record, sensitivity, now, healthSnapshot);
            var trace = new RuleEvaluationTrace
            {
                PacketId = record.Id.ToString("N"),
                FlowId = BuildFlowId(record),
                TimestampUtc = now
            };
            _lastTrace = trace;

            try
            {
                Interlocked.Increment(ref _evalCalls);

                if (DiagEnabled)
                {
                    if (string.IsNullOrWhiteSpace(record.Source))
                        Console.WriteLine("[RuleEngine/diag] Record has empty Source; some rules will skip.");
                    if (string.IsNullOrWhiteSpace(record.Protocol) && string.IsNullOrWhiteSpace(record.Info))
                        Console.WriteLine("[RuleEngine/diag] Record has no Protocol and empty Info; HTTP/DNS heuristics may miss.");
                }

                Touch(record.Source, now);
                TryLearnFromRecord(record);

                if ((now - _lastCleanup).TotalSeconds >= (_cfg.CleanupIntervalSeconds ?? CleanupIntervalSeconds))
                {
                    Cleanup(now);
                    _lastCleanup = now;
                }

                var executionPlan = _candidateSelector.CreatePlan(GetActiveRules(trace), record);
                trace.RulesConsideredCount = executionPlan.ConsideredCount;
                trace.RulesSelectedCount = executionPlan.SelectedCount;

                foreach (var planEntry in executionPlan.Entries)
                {
                    var rule = planEntry.Rule;
                    var descriptor = rule.Descriptor;
                    trace.SelectorReasonsByRuleId[descriptor.RuleId] = planEntry.Reason;

                    var ruleMode = ResolveConfiguredRuleMode(rule, record);
                    RuleEvaluationResult ruleResult;
                    TimeSpan? evaluationDuration = null;
                    var missingTelemetryForRule = false;
                    try
                    {
                        if (ruleMode == RuleMode.Disabled)
                        {
                            ruleResult = RuleEvaluationResult.SkippedDisabled(descriptor.RuleId);
                        }
                        else if (!planEntry.ShouldEvaluate)
                        {
                            trace.SelectorSkippedRuleIds.Add(descriptor.RuleId);
                            missingTelemetryForRule = planEntry.Reason.Contains("telemetry", StringComparison.OrdinalIgnoreCase);
                            RuleRuntimeTelemetryStore.RecordSelectorSkipped(
                                descriptor.RuleId,
                                now,
                                missingTelemetryForRule);
                            RuleRuntimeStatsStore.RecordSelectorSkipped(descriptor.RuleId, now, missingTelemetryForRule);
                            var selectorNoMatchReason = RuleNoMatchReason.Create(
                                descriptor.RuleId,
                                missingTelemetryForRule ? RuleNoMatchReasonCategory.MissingTelemetry : RuleNoMatchReasonCategory.SelectorSkipped,
                                missingTelemetryForRule ? "SELECTOR_MISSING_TELEMETRY" : "SELECTOR_SKIPPED",
                                planEntry.Reason,
                                now,
                                new Dictionary<string, string>
                                {
                                    ["selector.reason"] = planEntry.Reason,
                                    ["selector.shouldEvaluate"] = planEntry.ShouldEvaluate.ToString()
                                });
                            RecordNoMatchReason(trace, descriptor.RuleId, selectorNoMatchReason);
                            if (missingTelemetryForRule)
                                trace.MissingTelemetryByRuleId[descriptor.RuleId] = new List<string> { planEntry.Reason };
                            continue;
                        }
                        else
                        {
                            trace.SelectedRuleIds.Add(descriptor.RuleId);
                            RuleRuntimeTelemetryStore.RecordSelectorSelected(descriptor.RuleId, now);
                            var telemetry = RuleTelemetryValidator.Validate(rule, record);
                            missingTelemetryForRule = !telemetry.CanRunSafely || telemetry.MissingRequiredTelemetry.Count > 0;
                            if (telemetry.Warnings.Count > 0)
                            {
                                trace.TelemetryWarnings.AddRange(telemetry.Warnings);
                                if (telemetry.MissingRequiredTelemetry.Count > 0)
                                    trace.MissingTelemetryByRuleId[descriptor.RuleId] = telemetry.MissingRequiredTelemetry.ToList();
                            }

                            var stopwatch = Stopwatch.StartNew();
                            try
                            {
                                ruleResult = telemetry.CanRunSafely
                                    ? rule.EvaluateAsync(context).AsTask().GetAwaiter().GetResult()
                                    : RuleEvaluationResult.NoMatch(
                                        descriptor.RuleId,
                                        RuleNoMatchReasonCategory.MissingTelemetry,
                                        "MISSING_REQUIRED_TELEMETRY",
                                        telemetry.MissingRequiredTelemetry.Count > 0
                                            ? "Rule did not evaluate because required telemetry is missing: " + string.Join(", ", telemetry.MissingRequiredTelemetry)
                                            : "Rule did not evaluate because required telemetry validation failed.",
                                        telemetry.MissingRequiredTelemetry
                                            .Select((field, index) => new KeyValuePair<string, string>("missing." + index, field))
                                            .ToDictionary(static pair => pair.Key, static pair => pair.Value, StringComparer.OrdinalIgnoreCase));
                            }
                            finally
                            {
                                stopwatch.Stop();
                                evaluationDuration = stopwatch.Elapsed;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        ruleResult = RuleEvaluationResult.FailedRule(descriptor.RuleId, ex);
                    }

                    RuleRuntimeStatsStore.RecordResult(
                        descriptor.RuleId,
                        ruleResult,
                        now,
                        evaluationDuration,
                        missingTelemetryForRule,
                        IsCooldownSuppressed(ruleResult));
                    ApplyRuleResult(ruleResult, rule, descriptor, record, sensitivity, now, trace, results, ruleMode);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] Evaluate exception: {ex}");
            }
            finally
            {
                if (DiagEnabled)
                {
                    var now2 = DateTime.UtcNow;
                    if ((now2 - _lastDiagPrint).TotalSeconds >= 5)
                    {
                        var eval = Interlocked.Read(ref _evalCalls);
                        var outEv = Interlocked.Read(ref _emittedEvents);
                        var sinceLast = (_lastDetectionAt == DateTime.MinValue) ? "never" : $"{(now2 - _lastDetectionAt).TotalSeconds:F0}s ago";
                        Console.WriteLine($"[RuleEngine/diag] evaluateCalls={eval}, detections={outEv}, lastDetection={sinceLast}");
                        _lastDiagPrint = now2;
                    }
                }
            }

            return results;
        }

        private static void RecordNoMatchReason(RuleEvaluationTrace trace, string ruleId, RuleNoMatchReason reason)
        {
            if (reason == null || string.IsNullOrWhiteSpace(ruleId))
                return;

            RuleNoMatchReasonStore.Record(ruleId, reason);
            if (!trace.NoMatchReasonsByRuleId.TryGetValue(ruleId, out var reasons))
            {
                reasons = new List<RuleNoMatchReason>();
                trace.NoMatchReasonsByRuleId[ruleId] = reasons;
            }

            reasons.Add(reason);
        }

        private static void RecordNoMatchReasons(RuleEvaluationTrace trace, string ruleId, RuleEvaluationResult result, DateTime timestampUtc)
        {
            if (result == null || string.IsNullOrWhiteSpace(ruleId))
                return;

            var reasons = result.NoMatchReasons;
            if (reasons == null || reasons.Count == 0)
            {
                if ((result.Evaluated && !result.Matched && !result.Failed) || result.Skipped)
                {
                    var category = result.Skipped ? RuleNoMatchReasonCategory.Disabled : RuleNoMatchReasonCategory.InsufficientEvidence;
                    var code = result.Skipped ? "RULE_SKIPPED" : "INSUFFICIENT_EVIDENCE";
                    var message = result.Skipped
                        ? "Rule was skipped before evaluation."
                        : "Rule evaluated successfully but did not meet its evidence gates.";
                    RecordNoMatchReason(trace, ruleId, RuleNoMatchReason.Create(ruleId, category, code, message, timestampUtc));
                }

                return;
            }

            foreach (var reason in reasons)
            {
                RecordNoMatchReason(trace, ruleId, reason with { RuleId = ruleId, TimestampUtc = timestampUtc });
            }
        }

        private static void ApplyRuleResult(
            RuleEvaluationResult ruleResult,
            IDetectionRule rule,
            RuleDescriptor descriptor,
            TrafficRecord record,
            Sensitivity sensitivity,
            DateTime now,
            RuleEvaluationTrace trace,
            List<DetectionEvent> results,
            RuleMode ruleMode)
        {
            var ruleId = string.IsNullOrWhiteSpace(ruleResult.RuleId) ? descriptor.RuleId : ruleResult.RuleId;

            if (ruleResult.Skipped)
            {
                trace.SkippedRuleIds.Add(ruleId);
                RecordNoMatchReasons(trace, ruleId, ruleResult, now);
                RuleEngineMetrics.Increment(ruleId, RuleMetricNames.RuleSkippedDisabledTotal);
                return;
            }

            if (ruleResult.Evaluated)
            {
                trace.EvaluatedRuleIds.Add(ruleId);
                RuleEngineMetrics.Increment(ruleId, RuleMetricNames.RuleEvaluatedTotal);
                RuleRuntimeTelemetryStore.RecordEvaluated(ruleId, now);
            }

            if (ruleResult.Failed)
            {
                trace.FailedRuleIds.Add(ruleId);
                RuleEngineMetrics.Increment(ruleId, RuleMetricNames.RuleFailedTotal);
                RuleRuntimeTelemetryStore.RecordFailure(ruleId, now, ruleResult.FailureMessage);
                Console.Error.WriteLine($"[RuleEngine] Rule {ruleId} failed: {ruleResult.FailureMessage}");
                return;
            }

            if (ruleResult.Evaluated && !ruleResult.Matched)
            {
                RecordNoMatchReasons(trace, ruleId, ruleResult, now);
            }

            if (ruleResult.Matched)
            {
                trace.MatchedRuleIds.Add(ruleId);
                RuleEngineMetrics.Increment(ruleId, RuleMetricNames.RuleMatchedTotal);
            }

            if (ruleResult.Suppressed)
            {
                trace.SuppressedRuleIds.Add(ruleId);
                RuleEngineMetrics.Increment(ruleId, RuleMetricNames.RuleSuppressedTotal);
                return;
            }

            foreach (var evt in ruleResult.Events ?? Array.Empty<DetectionEvent>())
            {
                if (evt == null) continue;
                PrepareDetectionEvent(evt, descriptor, record, sensitivity, now);
                var tuningDecision = ResolveRuntimeTuningDecision(rule, evt, record, ruleMode);
                ApplyTuningDecisionToEvent(evt, tuningDecision);
                ApplyNoiseBudget(evt, descriptor, tuningDecision, now);
                ApplySuppressionPolicy(evt, descriptor, record, now);
                var effectiveMode = evt.SuppressionStatus switch
                {
                    DetectionSuppressionStatus.None => tuningDecision.EffectiveMode,
                    DetectionSuppressionStatus.Shadowed => RuleMode.Shadow,
                    DetectionSuppressionStatus.Suppressed => RuleMode.Disabled,
                    _ => tuningDecision.EffectiveMode
                };

                var writeResult = DetectionJournal.Current.AppendAsync(evt).GetAwaiter().GetResult();
                if (!writeResult.Succeeded)
                {
                    trace.FailedToPersistEventIds.Add(evt.EventId);
                    evt.DeliveryStatus = DetectionDeliveryStatus.FailedToPersist;
                    evt.PersistenceError = writeResult.ErrorMessage;
                    RuleRuntimeTelemetryStore.RecordFailure(ruleId, now, writeResult.ErrorMessage);
                }
                else
                {
                    trace.PersistedEventIds.Add(evt.EventId);
                    evt.DeliveryStatus = DetectionDeliveryStatus.Persisted;
                    RuleEngineMetrics.Increment(ruleId, RuleMetricNames.RulePersistedTotal);
                    RuleRuntimeTelemetryStore.RecordPersisted(ruleId, now, evt.ConfidenceScore);
                }

                RuleRuntimeTelemetryStore.RecordMatched(ruleId, now, evt.ConfidenceScore);

                if (evt.SuppressionStatus == DetectionSuppressionStatus.Shadowed || effectiveMode == RuleMode.Shadow)
                {
                    trace.ShadowedRuleIds.Add(evt.RuleId);
                    RuleEngineMetrics.Increment(ruleId, RuleMetricNames.RuleShadowedTotal);
                    continue;
                }

                if (evt.SuppressionStatus == DetectionSuppressionStatus.Suppressed || effectiveMode == RuleMode.Disabled)
                {
                    trace.SuppressedRuleIds.Add(evt.RuleId);
                    RuleEngineMetrics.Increment(ruleId, RuleMetricNames.RuleSuppressedTotal);
                    continue;
                }

                NoteHit(evt, record.ProcessId, now);
                LogDetection(evt);
                results.Add(evt);
                trace.EmittedRuleIds.Add(evt.RuleId);
                _lastDetectionAt = now;
                Interlocked.Increment(ref _emittedEvents);
                RuleEngineMetrics.Increment(ruleId, RuleMetricNames.RuleEmittedTotal);
            }
        }

        private static bool IsCooldownSuppressed(RuleEvaluationResult result)
        {
            if (result?.Events == null)
                return false;

            foreach (var evt in result.Events)
            {
                var evidence = evt?.Evidence;
                if (!string.IsNullOrWhiteSpace(evidence) && evidence.IndexOf("cooldown", StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;

                var items = evt?.StructuredEvidence?.Items;
                if (items == null)
                    continue;

                foreach (var item in items)
                {
                    if ((item.Key?.IndexOf("cooldown", StringComparison.OrdinalIgnoreCase) ?? -1) >= 0
                        || (item.Value?.IndexOf("cooldown", StringComparison.OrdinalIgnoreCase) ?? -1) >= 0)
                        return true;
                }
            }

            return false;
        }


        private static void PrepareDetectionEvent(DetectionEvent evt, RuleDescriptor descriptor, TrafficRecord record, Sensitivity sensitivity, DateTime now)
        {
            if (string.IsNullOrWhiteSpace(evt.EventId)) evt.EventId = Guid.NewGuid().ToString("N");
            evt.TimestampUtc = now;
            evt.RuleId = string.IsNullOrWhiteSpace(evt.RuleId) ? descriptor.RuleId : evt.RuleId;
            evt.RuleName = string.IsNullOrWhiteSpace(evt.RuleName) ? descriptor.Name : evt.RuleName;
            evt.SensitivityAtTrigger = sensitivity;
            evt.PacketId ??= record.Id.ToString("N");
            evt.FlowId ??= BuildFlowId(record);
            evt.SuppressionStatus = evt.SuppressionStatus == DetectionSuppressionStatus.Shadowed
                ? DetectionSuppressionStatus.Shadowed
                : DetectionSuppressionStatus.None;
            evt.SourcePort ??= record.SourcePort;
            EnrichDetection(evt, record);

            var intelligence = RuleIntelligenceFactory.CreateDefault(descriptor);
            evt.RuleMaturityAtDetection = intelligence.Maturity.ToString();
            evt.RuleRevisionAtDetection = intelligence.Revision;
            EvidenceBuilder.EnsureStructuredEvidence(evt);
            DetectionEvidenceEnricher.ApplyEnvironmentAndTelemetryEvidence(evt, descriptor, record);
            if (evt.ConfidenceScore <= 0)
                ConfidenceBuilder.ApplyDefault(evt, descriptor, intelligence);
        }

        internal static RuleEvaluationResult EvaluateExistingRule(string ruleId, RuleDescriptor descriptor, RuleEvaluationContext context)
        {
            _suppressedRuleId.Value = null;
            var now = context.TimestampUtc;
            var record = context.Record;
            var sensitivity = context.Sensitivity;

            bool matched;
            DetectionEvent? evt = null;
            switch (ruleId)
            {
                case "R001": matched = DetectPortScan(now, record, sensitivity, out evt); break;
                case "R002": matched = DetectFlood(now, record, sensitivity, out evt); break;
                case "R003": matched = DetectThreatFeedHit(now, record, out evt); break;
                case "R004": matched = DetectBruteForce(now, record, sensitivity, out evt); break;
                case "R005": matched = DetectSuspiciousProtocol(now, record, out evt); break;
                case "R006": matched = DetectDnsAnomaly(now, record, sensitivity, out evt); break;
                case "R007": matched = DetectBeaconing(now, record, sensitivity, out evt); break;
                case "R008": matched = DetectExfiltration(now, record, sensitivity, out evt); break;
                case "R009": matched = DetectVpnProxy(now, record, out evt); break;
                case "R010": matched = DetectBlacklistedCountry(now, record, out evt); break;
                case "R011": matched = DetectDhcpAbuse(now, record, sensitivity, out evt); break;
                case "R012": matched = DetectSuspiciousTls(now, record, out evt); break;
                case "R013": matched = DetectUncommonPorts(now, record, out evt); break;
                case "R014": matched = DetectCleartextCreds(now, record, out evt); break;
                case "R015": matched = DetectArpSpoofing(now, record, out evt); break;
                case "R016": matched = DetectReputation(now, record, sensitivity, out evt); break;
                case "R017": matched = DetectHostSweep(now, record, sensitivity, out evt); break;
                case "R018": matched = DetectHttpIpNoHost(now, record, out evt); break;
                case "R019": matched = DetectHttpUriAnomaly(now, record, sensitivity, out evt); break;
                case "R020": matched = DetectSmtpEgress25(now, record, out evt); break;
                case "R021": matched = DetectIcmpTunnel(now, record, sensitivity, out evt); break;
                case "R022": matched = DetectDnsNxSpike(now, record, sensitivity, out evt); break;
                case "R023": matched = DetectTlsNoSniToIp(now, record, out evt); break;
                case "R024": matched = DetectRareTlsFingerprint(now, record, out evt); break;
                case "R025": matched = DetectTlsCertExpiry(now, record, out evt); break;
                case "R026": matched = DetectSmbToInternet(now, record, out evt); break;
                case "R027": matched = DetectAdminEgress(now, record, out evt); break;
                case "R028": matched = DetectExternalDnsDirect(now, record, out evt); break;
                case "R029": matched = DetectQuicAnomaly(now, record, out evt); break;
                case "R030": matched = DetectAdminLateralSweep(now, record, out evt); break;
                case "R031": matched = DetectDnsTxtSpike(now, record, out evt); break;
                case "R032": matched = DetectSuspiciousUserAgent(now, record, out evt); break;
                case "R033": matched = DetectIcmpOversized(now, record, out evt); break;
                case "R034": matched = DetectDoHHeuristic(now, record, out evt); break;
                case "R035": matched = DetectRareSshFingerprint(now, record, out evt); break;
                case "R036": matched = DetectPairExfiltration(now, record, out evt); break;
                case "R037": matched = DetectJa4DriftPerSni(now, record, out evt); break;
                case "R038": matched = DetectEncryptedDnsBootstrap(now, record, out evt); break;
                case "R039": matched = DetectAsnNoveltySensitive(now, record, out evt); break;
                case "R040": matched = DetectEncryptedLowAndSlow(now, record, out evt); break;
                case "R041": matched = DetectJa4FanoutSweep(now, record, out evt); break;
                case "R042": matched = DetectUncommonQuicAlpn(now, record, out evt); break;
                case "R043": matched = DetectSniHostMismatch(now, record, out evt); break;
                case "R044": matched = DetectHttpMethodAnomaly(now, record, out evt); break;
                case "R045": matched = DetectSparseHttpPost(now, record, out evt); break;
                case "R046": matched = DetectUnauthorizedVpnEgress(now, record, out evt); break;
                case "R047": matched = DetectHttpBasicAuthToIp(now, record, out evt); break;
                case "R048": matched = DetectAlternateDoHPatterns(now, record, out evt); break;
                case "R049": matched = DetectSuspiciousSniShape(now, record, out evt); break;
                default: return RuleEvaluationResult.FailedRule(ruleId, $"No legacy detector binding exists for {ruleId}.");
            }

            if (!matched)
            {
                if (string.Equals(_suppressedRuleId.Value, ruleId, StringComparison.OrdinalIgnoreCase))
                    return RuleEvaluationResult.SuppressedMatch(ruleId);
                return RuleEvaluationResult.NoMatch(ruleId);
            }

            return evt == null ? RuleEvaluationResult.NoMatch(ruleId) : RuleEvaluationResult.Match(ruleId, evt);
        }

        private static bool IsRuleEnabledById(string ruleId, bool defaultValue)
        {
            var explicitOverride = TryGetRuleEnabledOverride(ruleId);
            if (explicitOverride.HasValue) return explicitOverride.Value;

            return ruleId switch
            {
            "R001" => IsEnabled(_cfg.EnablePortScan, defaultValue),
            "R002" => IsEnabled(_cfg.EnableFlood, defaultValue),
            "R003" => IsEnabled(_cfg.EnableThreatFeed, defaultValue),
            "R004" => IsEnabled(_cfg.EnableBruteForce, defaultValue),
            "R005" => IsEnabled(_cfg.EnableSuspiciousProtocol, defaultValue),
            "R006" => IsEnabled(_cfg.EnableDns, defaultValue),
            "R007" => IsEnabled(_cfg.EnableBeaconing, defaultValue),
            "R008" => IsEnabled(_cfg.EnableExfiltration, defaultValue),
            "R009" => IsEnabled(_cfg.EnableVpnProxy, defaultValue),
            "R010" => IsEnabled(_cfg.EnableGeoip, defaultValue),
            "R011" => IsEnabled(_cfg.EnableDhcp, defaultValue),
            "R012" => IsEnabled(_cfg.EnableTlsInspection, defaultValue),
            "R013" => IsEnabled(_cfg.EnableUncommonPorts, defaultValue),
            "R014" => IsEnabled(_cfg.EnableCleartextCredentials, defaultValue),
            "R015" => IsEnabled(_cfg.EnableArpSpoofing, defaultValue),
            "R016" => IsEnabled(_cfg.EnableReputation, defaultValue),
            "R017" => IsEnabled(_cfg.EnableHostSweep, defaultValue),
            "R018" => IsEnabled(_cfg.EnableHttpIpNoHost, defaultValue),
            "R019" => IsEnabled(_cfg.EnableHttpUriAnomaly, defaultValue),
            "R020" => IsEnabled(_cfg.EnableSmtpEgress25, defaultValue),
            "R021" => IsEnabled(_cfg.EnableIcmpTunnel, defaultValue),
            "R022" => IsEnabled(_cfg.EnableDnsNxDomainSpike, defaultValue),
            "R023" => IsEnabled(_cfg.EnableTlsNoSniToIp, defaultValue),
            "R024" => IsEnabled(_cfg.EnableRareTlsFingerprint, defaultValue),
            "R025" => IsEnabled(_cfg.EnableTlsCertExpiry, defaultValue),
            "R026" => IsEnabled(_cfg.EnableSmbToInternet, defaultValue),
            "R027" => IsEnabled(_cfg.EnableAdminEgress, defaultValue),
            "R028" => IsEnabled(_cfg.EnableExternalDnsDirect, defaultValue),
            "R029" => IsEnabled(_cfg.EnableQuicAnomaly, defaultValue),
            "R030" => IsEnabled(_cfg.EnableAdminLateralSweep, defaultValue),
            "R031" => IsEnabled(_cfg.EnableDnsTxtSpike, defaultValue),
            "R032" => IsEnabled(_cfg.EnableSuspiciousUserAgent, defaultValue),
            "R033" => IsEnabled(_cfg.EnableIcmpOversized, defaultValue),
            "R034" => IsEnabled(_cfg.EnableDoH, defaultValue),
            "R035" => IsEnabled(_cfg.EnableRareSshFingerprint, defaultValue),
            "R036" => IsEnabled(_cfg.EnablePairExfiltration, defaultValue),
            "R037" => IsEnabled(_cfg.EnableJa4DriftPerSni, defaultValue),
            "R038" => IsEnabled(_cfg.EnableEncryptedDnsBootstrap, defaultValue),
            "R039" => IsEnabled(_cfg.EnableAsnNoveltySensitive, defaultValue),
            "R040" => IsEnabled(_cfg.EnableEncryptedLowAndSlow, defaultValue),
            "R041" => IsEnabled(_cfg.EnableJa4FanoutSweep, defaultValue),
            "R042" => IsEnabled(_cfg.EnableUncommonQuicAlpn, defaultValue),
            "R043" => IsEnabled(_cfg.EnableSniHostMismatch, defaultValue),
            "R044" => IsEnabled(_cfg.EnableHttpMethodAnomaly, defaultValue),
            "R045" => IsEnabled(_cfg.EnableSparseHttpPost, defaultValue),
            "R046" => IsEnabled(_cfg.EnableUnauthorizedVpnEgress, defaultValue),
            "R047" => IsEnabled(_cfg.EnableHttpBasicAuthToIp, defaultValue),
            "R048" => IsEnabled(_cfg.EnableAlternateDoHPatterns, defaultValue),
            "R049" => IsEnabled(_cfg.EnableSuspiciousSniShape, defaultValue),
                _ => defaultValue
            };
        }

        private static string BuildFlowId(TrafficRecord record) => string.Join("|",
            record.Source ?? "unknown-src",
            record.SourcePort?.ToString() ?? "*",
            record.Destination ?? "unknown-dst",
            record.DestinationPort?.ToString() ?? "*",
            record.Protocol ?? "unknown-proto");

        public static void ReportCaptureDrops(long count) => RuleEngineHealthState.ReportCaptureDrops(count);
        public static void ReportThreatFeedUpdated(DateTime timestampUtc) => RuleEngineHealthState.ReportThreatFeedUpdated(timestampUtc);

        public static void Cleanup(DateTime now)
        {
            try
            {
                int ttlMin = _cfg.StateTtlMinutes ?? StateTtlMinutes;
                var cutoff = now.AddMinutes(-ttlMin);

                foreach (var kv in _lastSeenSrc.ToArray())
                {
                    if (kv.Value >= cutoff) continue;

                    _sourceToPorts.TryRemove(kv.Key, out _);
                    _packetTimes.TryRemove(kv.Key, out _);
                    _dnsQueries.TryRemove(kv.Key, out _);
                    _exfilBytes.TryRemove(kv.Key, out _);
                    _floodStats.TryRemove(kv.Key, out _);

                    _lastSeenSrc.TryRemove(kv.Key, out _);
                }

                foreach (var k in _beaconing.Keys.Where(k => !_lastSeenSrc.ContainsKey(k.Src)).ToList())
                    _beaconing.TryRemove(k, out _);
                foreach (var k in _authAttempts.Keys.Where(k => !_lastSeenSrc.ContainsKey(k.Src)).ToList())
                    _authAttempts.TryRemove(k, out _);

                foreach (var ip in _arpTable.Keys.Where(ip => !_lastSeenSrc.ContainsKey(ip)).ToList())
                    _arpTable.TryRemove(ip, out _);

                if (_dhcpActivity.TryGetValue("DHCP", out var dhcpList))
                    TrimAndCount(dhcpList, now, _cfg.DhcpWindowSeconds ?? DhcpWindowSeconds);

                // Evict old cooldown keys to cap growth
                int cooldown = _cfg.AlertCooldownSeconds ?? AlertCooldownSecondsDefault;
                if (cooldown > 0)
                {
                    var c = now.AddSeconds(-cooldown * 2);
                    foreach (var kv in _lastAlertAt.ToArray())
                        if (kv.Value < c) _lastAlertAt.TryRemove(kv.Key, out _);
                }

                // Extra cleanup for new state
                foreach (var key in _hostSweeps.Keys.Where(k => !_lastSeenSrc.ContainsKey(k.Src)).ToList())
                    _hostSweeps.TryRemove(key, out _);

                foreach (var key in _icmpTimes.Keys.Where(k => !_lastSeenSrc.ContainsKey(k)).ToList())
                {
                    _icmpTimes.TryRemove(key, out _);
                    _icmpBytes.TryRemove(key, out _);
                }

                foreach (var key in _nxdomain.Keys.Where(k => !_lastSeenSrc.ContainsKey(k)).ToList())
                    _nxdomain.TryRemove(key, out _);

                // --- Strategy detectors state cleanup ---

                // R037: per-SNI JA4 drift map
                // Remove stale JA4 entries per SNI, then drop empty SNI buckets
                foreach (var sni in _sniJa4Drift.Keys.ToList())
                {
                    if (_sniJa4Drift.TryGetValue(sni, out var inner))
                    {
                        // Drop JA4 entries not seen within TTL
                        foreach (var kv in inner.ToList())
                        {
                            if (kv.Value.LastSeen < cutoff)
                                inner.TryRemove(kv.Key, out _);
                        }

                        if (inner.IsEmpty)
                            _sniJa4Drift.TryRemove(sni, out _);
                    }
                }

                // R038: QUIC high-entropy SNI & DoH surge windows (per-source)
                foreach (var src in _quicHiEntropyBySrc.Keys.Where(k => !_lastSeenSrc.ContainsKey(k)).ToList())
                    _quicHiEntropyBySrc.TryRemove(src, out _);
                foreach (var src in _dohBySrc.Keys.Where(k => !_lastSeenSrc.ContainsKey(k)).ToList())
                    _dohBySrc.TryRemove(src, out _);

                // R039: ASN novelty sets
                foreach (var kv in _asnSeenAnywhere.ToList())
                {
                    if (kv.Value.LastSeen < cutoff)
                        _asnSeenAnywhere.TryRemove(kv.Key, out _);
                }
                foreach (var kv in _asnSeenOnSensitive.ToList())
                {
                    if (kv.Value < cutoff)
                        _asnSeenOnSensitive.TryRemove(kv.Key, out _);
                }

                // R040: long-lived low-throughput encrypted flows
                foreach (var kv in _encFlow.ToArray())
                {
                    var fs = kv.Value;
                    if (fs.Last < cutoff)
                        _encFlow.TryRemove(kv.Key, out _);
                }

                // R041: JA4 fan-out sweep state (per (src,ja4)); drop when src aged out
                foreach (var key in _ja4SniFanout.Keys.Where(k => !_lastSeenSrc.ContainsKey(k.Src)).ToList())
                    _ja4SniFanout.TryRemove(key, out _);

                // R042: QUIC ALPN rarity map
                foreach (var kv in _quicAlpnCounts.ToArray())
                {
                    if (kv.Value.Last < cutoff)
                        _quicAlpnCounts.TryRemove(kv.Key, out _);
                }

                // R043: cached TLS SNI per (src,dst)
                foreach (var kv in _tlsSniByFlow.ToArray())
                {
                    if (kv.Value.Ts < cutoff || !_lastSeenSrc.ContainsKey(kv.Key.Src))
                        _tlsSniByFlow.TryRemove(kv.Key, out _);
                }

                // R048: alternate DoH patterns per source
                foreach (var src in _altDohSeenBySrc.Keys.Where(k => !_lastSeenSrc.ContainsKey(k)).ToList())
                    _altDohSeenBySrc.TryRemove(src, out _);
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] Cleanup error: {ex}"); }
        }

        private static void Touch(string? src, DateTime now)
        {
            if (!string.IsNullOrEmpty(src))
                _lastSeenSrc[src] = now;
        }

        private static void EnrichDetection(DetectionEvent evt, TrafficRecord record)
        {
            evt.SourceIp ??= record.Source;
            evt.DestinationIp ??= record.Destination;
            evt.DestinationPort ??= record.DestinationPort;
            evt.Protocol ??= record.Protocol;
            evt.ProcessName ??= record.ProcessName;
            evt.Country ??= FirstNonEmpty(record.DstCountryIso2, record.DstCountry, record.WhoisCountry);
            evt.Asn ??= record.WhoisASN;
            evt.DestinationHost ??= FirstNonEmpty(record.DnsQname, record.HttpHost, record.Sni);
            evt.Ja4 ??= FirstNonEmpty(record.Ja4, record.Ja4S, record.Ja4T, record.Ja4SSH);
            evt.Hassh ??= record.Hassh;
            evt.QuicAlpn ??= record.QuicAlpn;
            evt.QuicConnectionIdHash ??= record.QuicConnectionIdHash;
        }

        private static string? FirstNonEmpty(params string?[] values)
        {
            foreach (var value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    return value.Trim();
            }

            return null;
        }

        private static int TrimAndCount(List<DateTime> list, DateTime now, int windowSeconds)
        {
            var cutoff = now.AddSeconds(-windowSeconds);
            int write = 0;
            for (int read = 0; read < list.Count; read++)
            {
                if (list[read] >= cutoff) list[write++] = list[read];
            }
            if (write != list.Count) list.RemoveRange(write, list.Count - write);
            return list.Count;
        }

        private static bool SuppressRepeat(DateTime now, string ruleId, string src, string? dst, int? dstPort)
        {
            int cooldown = _cfg.AlertCooldownSeconds ?? AlertCooldownSecondsDefault;
            if (cooldown <= 0) return false;

            var key = new SupprKey(ruleId, src, dst, dstPort);
            var last = _lastAlertAt.GetOrAdd(key, _ => DateTime.MinValue);
            if ((now - last).TotalSeconds < cooldown)
            {
                _suppressedRuleId.Value = ruleId;
                return true;
            }
            _lastAlertAt[key] = now;
            return false;
        }

        private static bool IsPrivateIp(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            if (!IPAddress.TryParse(ip, out var addr)) return false;

            if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var b = addr.GetAddressBytes();
                return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168);
            }

            if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                var s = addr.ToString().ToLowerInvariant();
                return addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal || s.StartsWith("fc") || s.StartsWith("fd");
            }
            return false;
        }

        private static double ShannonEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0.0;
            var counts = new Dictionary<char, int>();
            foreach (var c in s) counts[c] = counts.TryGetValue(c, out var n) ? n + 1 : 1;
            double len = s.Length, ent = 0.0;
            foreach (var n in counts.Values)
            {
                double p = n / len;
                ent += -p * Math.Log(p, 2);
            }
            return ent;
        }

        private static bool AutocorrSpike(List<double> intervals, int maxLags)
        {
            if (intervals.Count < 3) return false;
            double mean = intervals.Average();
            double variance = intervals.Select(x => (x - mean) * (x - mean)).Sum();
            if (variance <= 0) return false;

            int lags = Math.Min(maxLags, Math.Max(1, intervals.Count / 3));
            for (int lag = 1; lag <= lags; lag++)
            {
                double num = 0;
                for (int i = 0; i < intervals.Count - lag; i++)
                    num += (intervals[i] - mean) * (intervals[i + lag] - mean);
                double rho = num / variance;
                if (rho > 0.7) return true;
            }
            return false;
        }

        private static string ExtractTlsFlag(string info)
        {
            if (info.IndexOf("ExpiredCert", StringComparison.OrdinalIgnoreCase) >= 0) return "ExpiredCert";
            if (info.IndexOf("InvalidCert", StringComparison.OrdinalIgnoreCase) >= 0) return "InvalidCert";
            if (info.IndexOf("SelfSigned", StringComparison.OrdinalIgnoreCase) >= 0) return "SelfSigned";
            return "SuspiciousCert";
        }

        private static void NoteHit(DetectionEvent evt, int? processId, DateTime now)
        {
            try
            {
                var pidPart = processId.HasValue && processId.Value > 0 ? $":pid={processId.Value}" : string.Empty;
                var entityKey = $"{evt.SourceIp ?? "unknown"}{pidPart}";

                var list = _entityHits.GetOrAdd(entityKey, _ => new List<(string, DateTime)>(capacity: 8));
                lock (list)
                {
                    list.Add((evt.RuleId, now));
                    var cutoff = now.AddSeconds(-CorrelationWindowSeconds);
                    int write = 0;
                    for (int i = 0; i < list.Count; i++)
                        if (list[i].Item2 >= cutoff) list[write++] = list[i];
                    if (write != list.Count) list.RemoveRange(write, list.Count - write);

                    var distinctRules = list.Select(x => x.Item1).Distinct().Count();
                    if (distinctRules >= 2 && evt.Severity < SeverityLevel.Critical)
                        evt.Severity = SeverityLevel.Critical;
                    else if (evt.Severity == SeverityLevel.Low && distinctRules >= 2)
                        evt.Severity = SeverityLevel.High;
                }
            }
            catch { /* best-effort */ }
        }

        private static bool IsEnabled(bool? toggle, bool defaultValue) => toggle ?? defaultValue;

        private static void LogDetection(DetectionEvent evt)
        {
            try
            {
                var payload = new
                {
                    ts = evt.Timestamp,
                    rule = evt.RuleId,
                    severity = evt.Severity.ToString(),
                    src = evt.SourceIp,
                    dst = evt.DestinationIp,
                    dport = evt.DestinationPort,
                    proto = evt.Protocol,
                    desc = evt.Description,
                    count = evt.Count,
                    window = evt.WindowSeconds,
                    sensitivity = evt.SensitivityAtTrigger.ToString()
                };
                Console.WriteLine(JsonSerializer.Serialize(payload, _json)); // _json is declared in Config.cs
            }
            catch
            {
                Console.WriteLine($"[{evt.Severity}] {evt.RuleId} {evt.Description} src={evt.SourceIp} dst={evt.DestinationIp}:{evt.DestinationPort} proto={evt.Protocol} count={evt.Count}/{evt.WindowSeconds}s");
            }
        }

        private readonly record struct SupprKey(string RuleId, string Src, string? Dst, int? DstPort);

        // ======== Learning & inference ========
        private static void TryLearnFromRecord(TrafficRecord r)
        {
            try
            {
                if (r.DestinationPort is null) return;
                if (string.IsNullOrWhiteSpace(r.ApplicationService)) return;

                var hints = BuildHints(r);
                PortServiceResolver.LearnObservation(hints, r.ApplicationService!);
            }
            catch { /* best-effort, never throw */ }
        }

        private static PortServiceResolver.Hints BuildHints(TrafficRecord r)
        {
            string info = r.Info ?? string.Empty;

            bool isHttpLike = info.StartsWith("GET ", StringComparison.OrdinalIgnoreCase)
                           || info.StartsWith("POST ", StringComparison.OrdinalIgnoreCase)
                           || info.Contains("HTTP/1.", StringComparison.OrdinalIgnoreCase)
                           || string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase);

            bool isTls = (r.DestinationPort == 443)
                      || info.Contains("TLS", StringComparison.OrdinalIgnoreCase)
                      || info.Contains("ALPN", StringComparison.OrdinalIgnoreCase);

            bool isQuic = info.Contains("QUIC", StringComparison.OrdinalIgnoreCase)
                       || (r.DestinationPort == 443 && info.Contains("h3", StringComparison.OrdinalIgnoreCase));

            string? alpn = null;
            var idx = info.IndexOf("ALPN", StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                var slice = info.Substring(idx, Math.Min(24, Math.Max(0, info.Length - idx)));
                var m = System.Text.RegularExpressions.Regex.Match(slice, @"ALPN[:=\s](?<v>[A-Za-z0-9/\.\-]+)");
                if (m.Success) alpn = m.Groups["v"].Value;
            }

            bool sshLike = info.StartsWith("SSH-", StringComparison.OrdinalIgnoreCase);
            bool smtpLike = info.StartsWith("220 ", StringComparison.Ordinal) || info.IndexOf("HELO", StringComparison.OrdinalIgnoreCase) >= 0 || info.IndexOf("EHLO", StringComparison.OrdinalIgnoreCase) >= 0;
            bool rdpLike = info.IndexOf("Cookie: mstshash", StringComparison.OrdinalIgnoreCase) >= 0;
            bool sipLike = info.StartsWith("SIP/2.0", StringComparison.OrdinalIgnoreCase) || info.IndexOf("INVITE ", StringComparison.OrdinalIgnoreCase) >= 0;
            bool dnsLike = string.Equals(r.Protocol, "DNS", StringComparison.OrdinalIgnoreCase)
                           || (string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase) && r.DestinationPort == 53);

            string? sni = null;
            var hs = System.Text.RegularExpressions.Regex.Match(info, @"\bSNI[:=\s](?<h>[A-Za-z0-9\.\-]+)");
            if (hs.Success) sni = hs.Groups["h"].Value;

            return new PortServiceResolver.Hints(
                Port: r.DestinationPort,
                Protocol: r.Protocol,
                IsTls: isTls,
                IsQuic: isQuic,
                Alpn: alpn,
                Banner: sshLike ? "SSH-2.0" : (smtpLike ? "SMTP" : null),
                DnsLike: dnsLike,
                SipLike: sipLike,
                RdpLike: rdpLike,
                SmtpLike: smtpLike,
                SshLike: sshLike,
                HttpLike: isHttpLike,
                PrimaryHostOrSni: sni
            );
        }
    }
}
