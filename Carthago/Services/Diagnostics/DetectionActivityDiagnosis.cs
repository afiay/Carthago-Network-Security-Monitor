// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Read-only interpretation of process-local counters.
using System;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Health;

namespace Carthago.Services.Diagnostics
{
    /// <summary>
    /// A diagnostic of observed runtime activity, NEVER an accuracy or rule-validation grade.
    /// State reflects cumulative in-process counters and current policy, not a synchronized
    /// packet-by-packet transaction or a guarantee that a user saw an alert.
    /// </summary>
    public enum RuleActivityState
    {
        NotObserved,
        TelemetryUnobserved,
        SkippedBeforeEvaluation,
        EvaluatedNoMatch,
        MatchedNotEmitted,
        Emitted,
        ExecutionFailures,
        CurrentlyDisabled
    }

    public sealed record RuleActivityDiagnosis(
        RuleActivityState State,
        string Label,
        string Explanation,
        string NextCheck);

    public static class DetectionActivityDiagnosis
    {
        public static RuleActivityDiagnosis ForRule(
            RuleRuntimeStats runtime,
            RuleMode currentMode,
            RuleNoMatchStats noMatches,
            int unobservedRequiredTelemetryKinds,
            long shadowed,
            long suppressed,
            long emitted)
        {
            ArgumentNullException.ThrowIfNull(runtime);
            ArgumentNullException.ThrowIfNull(noMatches);

            var reason = noMatches.DominantReason;
            var reasonText = reason is null
                ? "No no-match reason recorded."
                : $"Most recorded no-match reason: {reason.Code} ({reason.Count:N0} observations).";
            var missingTelemetry = unobservedRequiredTelemetryKinds > 0 || noMatches.MissingTelemetryCount > 0;

            // Current policy takes precedence over past historical activity. Disabled
            // does not erase matches previously recorded in the same process.
            if (currentMode == RuleMode.Disabled)
                return new(RuleActivityState.CurrentlyDisabled, "Disabled",
                    "The rule is currently disabled. Earlier counters can still be present.",
                    "Check the authorized rule policy; do not change mode to force a match.");

            if (emitted > 0)
                return new(RuleActivityState.Emitted, "Emitted alert",
                    $"At least one alert was emitted in this process. Rule matches: {runtime.Matches:N0}; emitted: {emitted:N0}.",
                    "If Alerts is empty, check filters, session retention, and UI event delivery.");

            if (runtime.Matches > 0)
                return new(RuleActivityState.MatchedNotEmitted, "Matched, not emitted",
                    $"Matches: {runtime.Matches:N0}; shadowed: {shadowed:N0}; suppressed: {suppressed:N0}; emitted: 0 in sampled counters.",
                    shadowed > 0 || suppressed > 0
                        ? "Inspect shadow/suppression decisions and any journaled events before altering policy."
                        : "Inspect detection event production and post-policy handling; a matched result need not contain an emitted event.");

            if (runtime.Failed > 0)
                return new(RuleActivityState.ExecutionFailures, "Evaluation failures",
                    $"The rule recorded {runtime.Failed:N0} evaluation failure(s), with no recorded matches.",
                    "Inspect the rule's last failure and reproduce with a bounded positive/negative replay.");

            if (runtime.Evaluations > 0)
                return new(RuleActivityState.EvaluatedNoMatch, "Evaluated, no match",
                    $"The rule evaluated {runtime.Evaluations:N0} time(s) without a recorded match. {reasonText}",
                    missingTelemetry
                        ? "Inspect missing required fields and telemetry before reviewing evidence thresholds."
                        : "Compare known-positive and benign replay samples; normal traffic may correctly produce no match.");

            if (runtime.Skipped > 0)
                return new(RuleActivityState.SkippedBeforeEvaluation, "Skipped before evaluation",
                    $"The rule was skipped {runtime.Skipped:N0} time(s); no evaluation has been recorded. {reasonText}",
                    missingTelemetry
                        ? "Inspect missing required telemetry and the candidate-selector reason."
                        : "Inspect the selector's applicability criteria and current capture traffic.");

            if (unobservedRequiredTelemetryKinds > 0)
                return new(RuleActivityState.TelemetryUnobserved, "Telemetry not observed",
                    $"{unobservedRequiredTelemetryKinds:N0} required telemetry kind(s) not observed in the process; no evaluations recorded.",
                    "Check the capture interface, parsing/enrichment producers, and relevant telemetry requirements.");

            return new(RuleActivityState.NotObserved, "No runtime observations",
                "No rule evaluations or selector skips have been recorded in this process.",
                "Confirm capture and rule-engine calls are increasing, then inspect rule applicability.");
        }

        /// <summary>
        /// Compare two successful read-only refreshes. This is a delta of engine
        /// invocation counters, not proof of packet delivery, match, or accuracy.
        /// </summary>
        public static string ForProgress(long? previousEngineEvaluations, long currentEngineEvaluations)
        {
            if (!previousEngineEvaluations.HasValue)
                return "FIRST SNAPSHOT — Refresh again after capturing traffic to measure new engine evaluations.";

            if (currentEngineEvaluations < previousEngineEvaluations.Value)
                return "COUNTERS RESET OR CHANGED — Start a new baseline; snapshots are process-local.";

            if (currentEngineEvaluations == previousEngineEvaluations.Value)
                return "NO NEW ENGINE EVALUATIONS BETWEEN REFRESHES — Traffic may be idle or evaluation delayed; if capture was active, inspect enrichment workers and queue health.";

            return $"ENGINE EVALUATIONS INCREASED — {currentEngineEvaluations - previousEngineEvaluations.Value:N0} new calls between refreshes. This does not prove rule matches or accuracy.";
        }

        public static string ForPipeline(
            long engineRecordEvaluations,
            long ruleEvaluations,
            long ruleMatches,
            long shadowed,
            long suppressed,
            long emitted,
            long journalFailures)
        {
            if (engineRecordEvaluations <= 0)
                return "NO ENGINE EVALUATIONS RECORDED — Check capture-to-enrichment/evaluation routing. Live Traffic alone does not prove rule execution.";

            if (ruleEvaluations <= 0)
                return "ENGINE INVOKED; NO RULE EVALUATIONS — Inspect rule modes, selector skips and required telemetry.";

            if (ruleMatches <= 0)
                return "RULES EVALUATED; NO MATCHES RECORDED — Inspect per-rule no-match reasons. Benign traffic may correctly produce no alerts.";

            if (emitted <= 0)
                return shadowed > 0 || suppressed > 0
                    ? "MATCHES WITHOUT EMITTED ALERTS — Inspect shadow/suppression policy and journaled detections."
                    : "MATCHES WITHOUT EMITTED ALERTS — Inspect event generation and post-policy handling.";

            return journalFailures > 0
                ? "ALERTS EMITTED; JOURNAL FAILURES RECORDED — Check persistence and alert UI delivery."
                : "ALERTS EMITTED — If the alert view is empty, inspect filters, retention and UI delivery.";
        }
    }
}
