// SPDX-License-Identifier: MIT
// GA R531-R540 — SOURCE CANDIDATE — UNVERIFIED.
// Existing diagnostics are not authenticated TrafficRecord health events.
// Never promote mutable packet text, HTTP headers, process labels or claimed
// platform-health messages into verified local persistence/health outcomes.
namespace Carthago.Engine.Rules.Expansion
{
    internal static class PlatformHealthProducerEvidenceBoundary
    {
        internal static (string Code, string Detail)? GetMissingProducer(string ruleId)
            => ruleId switch
            {
                "R531" => ("JOURNAL_FREE_SPACE_TRUSTED_VOLUME_METRIC_UNAVAILABLE",
                    "Journal write-failure counters do not measure free space for the configured journal volume; trusted disk-capacity samples, path-to-volume mapping and configured thresholds are unavailable."),
                "R532" => ("OUTBOX_RETRY_ATTEMPT_AND_QUEUE_METRICS_UNAVAILABLE",
                    "Outbox append/backpressure counters are not authenticated per-sink retry attempts or a bounded retry-rate series; queue and maintenance context are unavailable."),
                "R533" => ("RULE_MATCH_VOLUME_CALIBRATED_BASELINE_UNAVAILABLE",
                    "Rule runtime match counts exist but no trusted per-rule baseline, exposure denominator, independent anomaly decision or approved replay window reaches this detector."),
                "R534" => ("RULE_SILENCE_EXPECTED_ACTIVITY_BASELINE_UNAVAILABLE",
                    "A last-match timestamp does not prove unexpected silence; expected eligible traffic, rule enablement, suppression and maintenance context are unavailable."),
                "R535" => ("TELEMETRY_FIELD_COVERAGE_COMPARABLE_SAMPLES_UNAVAILABLE",
                    "Telemetry coverage diagnostics do not provide trusted comparable per-field expected-versus-observed population samples to this rule."),
                "R536" => ("PARSER_FAILURE_RATE_TRUSTED_WINDOW_UNAVAILABLE",
                    "The parse_failures meter is a diagnostic counter, not a correlated per-parser event stream with a stable denominator, unique failures and bounded rate baseline."),
                "R537" => ("GEOIP_FAILURE_ELIGIBLE_LOOKUP_METRICS_UNAVAILABLE",
                    "GeoIP database availability and null lookup results cannot prove provider failures or a failure spike without eligible public-IP attempts and explicit outcomes."),
                "R538" => ("REPUTATION_FAILURE_ELIGIBLE_LOOKUP_METRICS_UNAVAILABLE",
                    "Unknown reputation and provider rate-limit hints cannot prove an abnormal failure rate without trusted attempted-lookup and outcome metrics."),
                "R539" => ("BASELINE_WRITE_FAILURE_TRUSTED_PERSISTENCE_OUTCOME_UNAVAILABLE",
                    "Baseline store state and generic exception prose are not a trusted correlated write-attempt and persistence-failure event reaching this detector."),
                "R540" => ("FEEDBACK_WRITE_FAILURE_TRUSTED_PERSISTENCE_OUTCOME_UNAVAILABLE",
                    "Feedback append exceptions and user-controlled notes are not authenticated store-write failure events reaching this detector."),
                _ => null
            };
    }
}
