// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/RulePrecisionRuntimeEvaluator.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Engine.Rules
{
    public sealed record RulePrecisionRuntimeDecision(
        string RuleId,
        RuleMode ProfileMode,
        RuleMode ConfiguredMode,
        RuleMode EffectiveMode,
        bool TelemetrySatisfied,
        bool EvidenceSatisfied,
        bool ConfidenceSatisfied,
        int ConfidencePercent,
        IReadOnlyList<string> ObservedEvidenceKinds,
        IReadOnlyList<string> MissingTelemetry,
        IReadOnlyList<string> MissingFields,
        IReadOnlyList<string> Reasons)
    {
        public bool AllowsAlert => EffectiveMode == RuleMode.Alert;
    }

    /// <summary>
    /// Runtime precision gate applied after a detector has produced a candidate event.
    /// It intentionally does not remove coverage: weak or incomplete detections remain journaled as
    /// Shadow/Suppressed depending on the rule profile, but they cannot page as high-confidence alerts.
    /// </summary>
    public static class RulePrecisionRuntimeEvaluator
    {
        public static RulePrecisionRuntimeDecision Evaluate(
            RuleDescriptor descriptor,
            DetectionEvent evt,
            TrafficRecord record,
            RuleMode configuredMode,
            string? runtimeProfileName,
            ApprovedAssetRegistry? approvedAssets = null)
        {
            if (descriptor == null) throw new ArgumentNullException(nameof(descriptor));
            if (evt == null) throw new ArgumentNullException(nameof(evt));

            var profile = RulePrecisionCatalog.GetProfile(descriptor);
            var profileMode = RulePrecisionCatalog.ToRuleMode(profile.DefaultMode);
            var effectiveMode = RulePrecisionCatalog.MostRestrictive(configuredMode, profileMode);
            var telemetry = RulePrecisionCatalog.Validate(descriptor.RuleId, record);
            var observedKinds = new HashSet<string>(ClassifyObservedEvidence(evt, record), StringComparer.OrdinalIgnoreCase);
            var reasons = new List<string>
            {
                $"precision profile={profile.Maturity}; defaultMode={profile.DefaultMode}; runtimeProfile={runtimeProfileName ?? "default"}"
            };

            if (profile.RequiredEnvironmentConfig.Count > 0)
                reasons.Add("environment config required: " + string.Join(", ", profile.RequiredEnvironmentConfig));

            if (!telemetry.CanEvaluate)
            {
                effectiveMode = RulePrecisionCatalog.MostRestrictive(effectiveMode, profile.DefaultMode == RuleRuntimeMode.Disabled ? RuleMode.Disabled : RuleMode.Shadow);
                if (telemetry.MissingTelemetry.Count > 0) reasons.Add("missing telemetry: " + string.Join(", ", telemetry.MissingTelemetry));
                if (telemetry.MissingFields.Count > 0) reasons.Add("missing fields: " + string.Join(", ", telemetry.MissingFields));
            }

            // A rounded display percentage must never authorize an alert
            // below the configured exact floor (e.g. 83.6% < 84%). Non-finite
            // scores are invalid and are treated as zero-confidence candidates.
            var normalizedConfidence = double.IsFinite(evt.ConfidenceScore)
                && evt.ConfidenceScore >= 0.0 && evt.ConfidenceScore <= 1.0
                ? evt.ConfidenceScore
                : 0.0;
            var confidencePercent = (int)Math.Round(normalizedConfidence * 100.0);
            var confidenceSatisfied = normalizedConfidence >= profile.MinimumConfidence / 100.0;
            if (!confidenceSatisfied)
            {
                effectiveMode = RulePrecisionCatalog.MostRestrictive(effectiveMode, RuleMode.Shadow);
                reasons.Add($"confidence {confidencePercent}% below precision floor {profile.MinimumConfidence}%");
            }

            var n = RuleNumber(descriptor.RuleId);
            var evidenceSatisfied = HasAlertableEvidence(profile, evt, observedKinds, record, out var evidenceReason);
            reasons.Add(evidenceReason);
            if (!evidenceSatisfied)
            {
                effectiveMode = RulePrecisionCatalog.MostRestrictive(effectiveMode, RuleMode.Shadow);
            }

            if (RequiresEnvironmentScope(profile) && !EnvironmentEvidencePresent(observedKinds, record, profile, approvedAssets))
            {
                effectiveMode = RulePrecisionCatalog.MostRestrictive(effectiveMode, RuleMode.Shadow);
                reasons.Add("environment-scoped rule lacks approved asset/segment/controller evidence; non-paging until configured");
            }

            if (n >= 123 && (evt.Severity is SeverityLevel.High or SeverityLevel.Critical))
            {
                var independentFamilies = CountIndependentEvidenceFamilies(observedKinds);
                if (independentFamilies < 2 && !observedKinds.Contains("threshold", StringComparer.OrdinalIgnoreCase) && !observedKinds.Contains("baseline", StringComparer.OrdinalIgnoreCase))
                {
                    effectiveMode = RulePrecisionCatalog.MostRestrictive(effectiveMode, RuleMode.Shadow);
                    reasons.Add("high/critical candidate has fewer than two independent evidence families and no threshold/baseline contract");
                }
            }

            return new RulePrecisionRuntimeDecision(
                descriptor.RuleId,
                profileMode,
                configuredMode,
                effectiveMode,
                telemetry.CanEvaluate,
                evidenceSatisfied,
                confidenceSatisfied,
                confidencePercent,
                observedKinds.OrderBy(static kind => kind, StringComparer.OrdinalIgnoreCase).ToArray(),
                telemetry.MissingTelemetry,
                telemetry.MissingFields,
                reasons.Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
        }

        public static IReadOnlySet<string> ClassifyObservedEvidence(DetectionEvent evt, TrafficRecord record)
        {
            var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (evt == null)
                return result;

            var evidence = string.Join(" ", new[]
            {
                evt.Evidence,
                evt.Description,
                evt.Summary,
                evt.Protocol,
                evt.DestinationHost,
                evt.ProcessName
            }.Where(static value => !string.IsNullOrWhiteSpace(value))!);

            foreach (var item in evt.StructuredEvidence?.Items ?? Array.Empty<DetectionEvidenceItem>())
            {
                var key = item.Key ?? string.Empty;
                var source = item.Source ?? string.Empty;
                var value = item.Value ?? string.Empty;
                AddFromToken(result, key);
                AddFromToken(result, source);
                AddFromToken(result, value);
            }

            AddFromToken(result, evidence);

            if (!string.IsNullOrWhiteSpace(record?.HttpMethod) ||
                !string.IsNullOrWhiteSpace(record?.HttpUri) ||
                !string.IsNullOrWhiteSpace(record?.HttpRequestHeaders) ||
                !string.IsNullOrWhiteSpace(record?.HttpUserAgent))
            {
                result.Add("http-request");
                result.Add("payload");
            }

            if (!string.IsNullOrWhiteSpace(record?.DnsQname))
                result.Add("dns");

            if (!string.IsNullOrWhiteSpace(record?.Sni) ||
                !string.IsNullOrWhiteSpace(record?.TlsVersion) ||
                !string.IsNullOrWhiteSpace(record?.Ja3) ||
                !string.IsNullOrWhiteSpace(record?.Ja4))
                result.Add("tls");

            if (!string.IsNullOrWhiteSpace(record?.ProcessName) || (record?.ProcessId ?? 0) > 0)
                result.Add("process");

            if (RulePrecisionCatalog.HasField("engine_health_signal", record))
                result.Add("engine-health");

            return result;
        }

        private static bool HasAlertableEvidence(
            RulePrecisionProfile profile,
            DetectionEvent evt,
            IReadOnlySet<string> observedKinds,
            TrafficRecord record,
            out string reason)
        {
            var n = RuleNumber(profile.RuleId);
            if (n < 123)
            {
                reason = "core/validated legacy precision preserved";
                return true;
            }

            if (profile.RequiredTelemetry.Contains(RuleTelemetryKind.EngineHealth))
            {
                var ok = observedKinds.Contains("engine-health", StringComparer.OrdinalIgnoreCase) || RulePrecisionCatalog.HasField("engine_health_signal", record);
                reason = ok ? "engine health signal present" : "engine health signal absent";
                return ok;
            }

            var weakOnly = observedKinds.Count == 0 ||
                           observedKinds.All(kind =>
                               string.Equals(kind, "text", StringComparison.OrdinalIgnoreCase) ||
                               string.Equals(kind, "host", StringComparison.OrdinalIgnoreCase) ||
                               string.Equals(kind, "port", StringComparison.OrdinalIgnoreCase) ||
                               string.Equals(kind, "protocol", StringComparison.OrdinalIgnoreCase) ||
                               string.Equals(kind, "direction", StringComparison.OrdinalIgnoreCase) ||
                               string.Equals(kind, "external-destination", StringComparison.OrdinalIgnoreCase));

            var hasContractEvidence =
                observedKinds.Contains("threshold", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("distinct", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("baseline", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("entropy", StringComparer.OrdinalIgnoreCase);

            var hasFieldEvidence =
                observedKinds.Contains("http-request", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("uri", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("header", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("user-agent", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("dns", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("tls", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("identity", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("cloud-devops", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("kubernetes", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("ot-ics", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("process", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("payload", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("service-command", StringComparer.OrdinalIgnoreCase) ||
                observedKinds.Contains("ot-protocol-payload", StringComparer.OrdinalIgnoreCase);

            var profileHasAggregation = profile.Threshold.HasValue || profile.Window.HasValue || !string.IsNullOrWhiteSpace(profile.DistinctBy);

            if (evt.Severity is SeverityLevel.High or SeverityLevel.Critical)
            {
                if (weakOnly && !hasContractEvidence && !profileHasAggregation)
                {
                    reason = "weak evidence only; high/critical alerts require field-level evidence or aggregation";
                    return false;
                }

                if (!hasFieldEvidence && !hasContractEvidence)
                {
                    reason = "no strong field evidence or aggregation evidence";
                    return false;
                }
            }

            reason = $"alertable evidence observed: {string.Join(",", observedKinds.OrderBy(static value => value, StringComparer.OrdinalIgnoreCase))}";
            return true;
        }

        private static bool RequiresEnvironmentScope(RulePrecisionProfile profile)
            => profile.RequiredTelemetry.Contains(RuleTelemetryKind.KubernetesAudit)
               || profile.RequiredTelemetry.Contains(RuleTelemetryKind.CloudAudit)
               || profile.RequiredTelemetry.Contains(RuleTelemetryKind.DevOpsAudit)
               || profile.RequiredTelemetry.Contains(RuleTelemetryKind.Directory)
               || profile.RequiredTelemetry.Contains(RuleTelemetryKind.OtIcsProtocol)
               || profile.RequiredEnvironmentConfig.Count > 0
               || profile.DefaultMode == RuleRuntimeMode.Disabled;

        private static bool EnvironmentEvidencePresent(IReadOnlySet<string> observedKinds, TrafficRecord record,
            RulePrecisionProfile profile, ApprovedAssetRegistry? approvedAssets)
            => (profile.RequiredTelemetry.Contains(RuleTelemetryKind.OtIcsProtocol)
                && approvedAssets != null
                && (approvedAssets.IsInApprovedOtSegment(record.Destination)
                    || approvedAssets.IsApprovedModbusController(record.Destination)
                    || approvedAssets.IsApprovedBacnetController(record.Destination)))
               || observedKinds.Contains("environment", StringComparer.OrdinalIgnoreCase)
               || observedKinds.Contains("approved-asset", StringComparer.OrdinalIgnoreCase)
               || observedKinds.Contains("baseline", StringComparer.OrdinalIgnoreCase)
               || !string.IsNullOrWhiteSpace(record?.ProcessName)
               || !string.IsNullOrWhiteSpace(record?.MacSource)
               || !string.IsNullOrWhiteSpace(record?.MacDestination);

        private static int CountIndependentEvidenceFamilies(IReadOnlySet<string> observedKinds)
        {
            var families = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kind in observedKinds)
            {
                if (kind is "text" or "host" or "port" or "protocol")
                    families.Add("weak-indicator");
                else if (kind is "direction" or "external-destination")
                    families.Add("direction");
                else if (kind is "uri" or "header" or "user-agent" or "http-request" or "payload")
                    families.Add("http-payload");
                else if (kind is "dns")
                    families.Add("dns");
                else if (kind is "tls")
                    families.Add("tls");
                else if (kind is "threshold" or "distinct" or "baseline" or "entropy")
                    families.Add("behavioral");
                else if (kind is "identity")
                    families.Add("identity");
                else if (kind is "cloud-devops" or "kubernetes")
                    families.Add("platform-audit");
                else if (kind is "ot-ics" or "ot-protocol-payload")
                    families.Add("ot-ics");
                else if (kind is "process" or "service-command")
                    families.Add("process-service");
                else if (kind is "engine-health")
                    families.Add("engine-health");
            }

            return families.Count;
        }

        private static void AddFromToken(HashSet<string> result, string? token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return;

            if (ContainsAny(token, "matched_text=")) result.Add("text");
            if (ContainsAny(token, "matched_host=")) result.Add("host");
            if (ContainsAny(token, "port=")) result.Add("port");
            if (ContainsAny(token, "protocol=") || ContainsAny(token, "transport=")) result.Add("protocol");
            if (ContainsAny(token, "telemetry=http", "http-request", "http.method", "http.uri", "uri=", "uri_length")) result.Add("http-request");
            if (ContainsAny(token, "header", "requestheaders")) result.Add("header");
            if (ContainsAny(token, "user-agent", "useragent")) result.Add("user-agent");
            if (ContainsAny(token, "dns_qname", "dns.qname", "dns=")) result.Add("dns");
            if (ContainsAny(token, "tls=", "sni", "ja3", "ja4", "certificate", "issuer")) result.Add("tls");
            if (ContainsAny(token, "count=", "threshold")) result.Add("threshold");
            if (ContainsAny(token, "distinct")) result.Add("distinct");
            if (ContainsAny(token, "baseline=")) result.Add("baseline");
            if (ContainsAny(token, "entropy")) result.Add("entropy");
            if (ContainsAny(token, "identity", "auth", "login", "kerberos", "ldap", "oauth", "saml")) result.Add("identity");
            if (ContainsAny(token, "cloud-devops", "cloudtrail", "github", "gitlab", "jenkins", "vault", "terraform")) result.Add("cloud-devops");
            if (ContainsAny(token, "kubernetes", "kubelet", "kubectl", "namespace", "pods", "serviceaccounts")) result.Add("kubernetes");
            if (ContainsAny(token, "ot-ics", "modbus", "bacnet", "mqtt", "dnp3", "opc", "s7comm", "coap")) result.Add("ot-ics");
            if (ContainsAny(token, "service-command", "admin", "config")) result.Add("service-command");
            if (ContainsAny(token, "ot-protocol-payload")) result.Add("ot-protocol-payload");
            if (ContainsAny(token, "process", "pid", "exe")) result.Add("process");
            if (ContainsAny(token, "engine-health", "engine health", "queue", "journal", "sink", "parser", "clock skew")) result.Add("engine-health");
            if (ContainsAny(token, "src_internal", "dst_external", "external-destination")) result.Add("direction");
        }

        private static bool ContainsAny(string text, params string[] needles)
        {
            foreach (var needle in needles)
            {
                if (!string.IsNullOrWhiteSpace(needle) && text.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        private static int RuleNumber(string? ruleId)
            => int.TryParse((ruleId ?? string.Empty).Trim().TrimStart('R', 'r'), out var n) ? n : 0;
    }
}
