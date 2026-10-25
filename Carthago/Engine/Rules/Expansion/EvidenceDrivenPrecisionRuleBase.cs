// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class EvidenceDrivenPrecisionRuleBase : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly ConcurrentDictionary<string, List<DateTime>> TimeWindows = new(StringComparer.OrdinalIgnoreCase);

        private static readonly Regex GitHubTokenRegex = new(@"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex GitLabTokenRegex = new(@"\bglpat-[A-Za-z0-9_\-]{20,}\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex AzureDevOpsPatRegex = new(@"\b[a-z0-9]{52}\b|\b[A-Za-z0-9_\-]{70,}\b", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        private static readonly Regex CircleCiTokenRegex = new(@"\b(?:circleci|circle-token|circle_token|Circle-Token)\b|\b[A-Fa-f0-9]{40}\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex NpmTokenRegex = new(@"\bnpm_[A-Za-z0-9]{24,}\b|//registry\.npmjs\.org/:_authToken=", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        private static readonly Regex VaultTokenRegex = new(@"\bhvs\.[A-Za-z0-9_\-]{20,}\b|\bhvb\.[A-Za-z0-9_\-]{20,}\b|\bs\.[A-Za-z0-9]{20,}\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex TerraformTokenRegex = new(@"\batlasv1\.[A-Za-z0-9_\-]{20,}\b|\bterraform[_\- ]?(?:cloud|token)\b", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        private static readonly Regex AwsAccessKeyRegex = new(@"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex GenericSecretRegex = new(@"(?i)\b(?:token|secret|password|passwd|apikey|api_key|authorization|bearer)\b.{0,32}[A-Za-z0-9_\-\./+=]{20,}", RegexOptions.Compiled | RegexOptions.CultureInvariant);

        protected EvidenceDrivenPrecisionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }

        protected sealed class PrecisionRuleSpec
        {
            public string RuleId { get; init; } = string.Empty;
            public string Name { get; init; } = string.Empty;
            public string Category { get; init; } = string.Empty;
            public string Description { get; init; } = string.Empty;
            public SeverityLevel Severity { get; init; } = SeverityLevel.Medium;
            public RulePrecisionMaturity Maturity { get; init; } = RulePrecisionMaturity.Validated;
            public RuleRuntimeMode RuntimeMode { get; init; } = RuleRuntimeMode.Alert;
            public RuleTelemetryKind[] RequiredTelemetry { get; init; } = Array.Empty<RuleTelemetryKind>();
            public string[] RequiredFields { get; init; } = Array.Empty<string>();
            public string[] EvidenceFields { get; init; } = Array.Empty<string>();
            public string[] PositiveConditions { get; init; } = Array.Empty<string>();
            public string[] NegativeConditions { get; init; } = Array.Empty<string>();
            public string[] FalsePositives { get; init; } = Array.Empty<string>();
            public string[] TuningKnobs { get; init; } = Array.Empty<string>();
            public string[] RequiredTests { get; init; } = Array.Empty<string>();
            public string[] TextIndicators { get; init; } = Array.Empty<string>();
            public string[] HostIndicators { get; init; } = Array.Empty<string>();
            public string[] PathIndicators { get; init; } = Array.Empty<string>();
            public string[] ProcessIndicators { get; init; } = Array.Empty<string>();
            public string[] ProtocolIndicators { get; init; } = Array.Empty<string>();
            public string[] Methods { get; init; } = Array.Empty<string>();
            public string[] TokenKinds { get; init; } = Array.Empty<string>();
            public int[] Ports { get; init; } = Array.Empty<int>();
            public long MinimumBytes { get; init; }
            public int MinimumSignals { get; init; } = 2;
            public int MinimumConfidence { get; init; } = 76;
            public double CorroboratedEvidenceWeight { get; init; }
            public int WindowThreshold { get; init; } = 1;
            public TimeSpan Window { get; init; } = TimeSpan.FromMinutes(20);
            public TimeSpan Cooldown { get; init; } = TimeSpan.FromMinutes(20);
            public string DistinctBy { get; init; } = "source+destination+behavior";
            public bool RequireHttp { get; init; }
            public bool RequireDns { get; init; }
            public bool RequireCleartext { get; init; }
            public bool RequireOutboundExternal { get; init; }
            public bool RequireInboundExternal { get; init; }
            public bool RequireCrossBoundary { get; init; }
            public bool SuppressLikelyBrowserOnly { get; init; }
        }

        protected static RulePrecisionProfile CreateEvidenceDrivenProfile(PrecisionRuleSpec spec)
            => CreateCloudDevProfile(
                spec.RuleId,
                spec.Maturity,
                spec.RuntimeMode,
                spec.RequiredTelemetry.Length == 0 ? new[] { RuleTelemetryKind.Flow } : spec.RequiredTelemetry,
                spec.RequiredFields.Length == 0 ? new[] { "source", "destination_or_host", "protocol_or_path_or_info" } : spec.RequiredFields,
                spec.EvidenceFields.Length == 0
                    ? new[] { "network.source", "network.destination", "matched_conditions", "rule.signalCount", "rule.windowCount" }
                    : spec.EvidenceFields,
                spec.PositiveConditions.Length == 0
                    ? new[]
                    {
                        "A concrete telemetry event contains protocol, host, path, port, process, byte, or token evidence for the named behavior.",
                        "The rule requires source/destination context and will not match descriptor text alone.",
                        "Burst rules must reach their time-window threshold before alerting."
                    }
                    : spec.PositiveConditions,
                spec.NegativeConditions.Length == 0
                    ? new[]
                    {
                        "Do not alert when only the rule name or category appears without packet, flow, HTTP, DNS, process, or identity evidence.",
                        "Do not alert when source/destination context is missing.",
                        "Do not alert on ordinary administrative traffic unless the rule-specific indicators are present."
                    }
                    : spec.NegativeConditions,
                spec.MinimumConfidence,
                spec.WindowThreshold,
                spec.Window,
                spec.Cooldown,
                spec.DistinctBy,
                spec.FalsePositives.Length == 0 ? new[] { "Legitimate administration, backup, migration, CI/CD, or cloud-management activity can resemble this behavior; tune approved sources and service accounts explicitly." } : spec.FalsePositives,
                spec.TuningKnobs.Length == 0 ? new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" } : spec.TuningKnobs,
                spec.RequiredTests.Length == 0 ? new[] { $"positive {spec.RuleId} concrete evidence sample", $"negative {spec.RuleId} descriptor-only sample", $"negative {spec.RuleId} missing telemetry sample" } : spec.RequiredTests);

        protected RuleEvaluationResult EvaluateSpec(RuleEvaluationContext context, PrecisionRuleSpec spec)
        {
            var record = context.Record;
            if (!HasCoreTelemetry(record))
                return NoMatch(RuleNoMatchReasonCategory.MissingTelemetry, "MISSING_CORE_TELEMETRY", "Source, destination/host, and protocol/behavior telemetry are required before this rule can evaluate.");

            if (spec.RequireHttp && !HasHttpContext(record))
                return NoMatch(RuleNoMatchReasonCategory.NotApplicableProtocol, "HTTP_CONTEXT_REQUIRED", "Rule requires HTTP method, URI, host, headers, or HTTP protocol context.");

            if (spec.RequireDns && !HasDnsContext(record))
                return NoMatch(RuleNoMatchReasonCategory.NotApplicableProtocol, "DNS_CONTEXT_REQUIRED", "Rule requires DNS question, qtype, resolver, or DNS protocol context.");

            if (spec.RequireCleartext && !IsCleartextHttp(record) && !IsCleartextCredentialProtocol(record))
                return NoMatch(RuleNoMatchReasonCategory.NotApplicableProtocol, "CLEARTEXT_CONTEXT_REQUIRED", "Rule requires cleartext HTTP or a cleartext credential-bearing protocol.");

            if (spec.RequireOutboundExternal && !IsOutboundExternalBoundary(record))
                return NoMatch(RuleNoMatchReasonCategory.BoundaryMismatch, "OUTBOUND_EXTERNAL_REQUIRED", "Rule requires an internal source communicating to an external destination.");

            if (spec.RequireInboundExternal && !IsInboundExternalBoundary(record))
                return NoMatch(RuleNoMatchReasonCategory.BoundaryMismatch, "INBOUND_EXTERNAL_REQUIRED", "Rule requires an external source communicating to an internal destination.");

            if (spec.RequireCrossBoundary && !IsCrossBoundary(record, out _, out _))
                return NoMatch(RuleNoMatchReasonCategory.BoundaryMismatch, "CROSS_BOUNDARY_REQUIRED", "Rule requires communication across an internal/external or trust boundary.");

            if (spec.MinimumBytes > 0 && TransferBytes(record) < spec.MinimumBytes)
                return NoMatch(RuleNoMatchReasonCategory.BelowThreshold, "MINIMUM_BYTES_NOT_MET", $"Observed transfer bytes are below the rule minimum of {spec.MinimumBytes}.");

            if (spec.SuppressLikelyBrowserOnly && IsLikelyBrowserProcess(record.ProcessName) && !ContainsAny(Text(record), "admin", "token", "export", "download", "api", "oauth", "consent", "forwarding"))
                return NoMatch(RuleNoMatchReasonCategory.AssetAllowed, "LIKELY_BROWSER_NO_HIGH_RISK_ACTION", "Likely browser traffic did not contain high-risk administrative, token, export, OAuth, or forwarding evidence.");

            var signalReasons = CollectSignals(record, spec).ToList();
            if (signalReasons.Count < Math.Max(1, spec.MinimumSignals))
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, "MINIMUM_SIGNAL_COUNT_NOT_MET", $"Rule requires at least {Math.Max(1, spec.MinimumSignals)} independent signal(s), but observed {signalReasons.Count}.");

            var windowKey = BuildWindowKey(record, spec);
            var count = spec.WindowThreshold <= 1 ? 1 : ObserveCount(windowKey, context.TimestampUtc, spec.Window);
            if (count < Math.Max(1, spec.WindowThreshold))
                return NoMatch(RuleNoMatchReasonCategory.BelowThreshold, "WINDOW_THRESHOLD_NOT_MET", $"Rule requires {Math.Max(1, spec.WindowThreshold)} event(s) in the configured window, but observed {count}.");

            var host = BestHost(record);
            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", signalReasons), "rule"),
                new("rule.signalCount", signalReasons.Count.ToString(CultureInfo.InvariantCulture), "rule"),
                new("rule.windowCount", count.ToString(CultureInfo.InvariantCulture), "rule")
            };

            if (!string.IsNullOrWhiteSpace(host))
                evidence.Add(new DetectionEvidenceItem("network.bestHost", host, "network"));
            if (!string.IsNullOrWhiteSpace(record.Source))
                evidence.Add(new DetectionEvidenceItem("network.source", record.Source!, "network"));
            if (!string.IsNullOrWhiteSpace(record.Destination))
                evidence.Add(new DetectionEvidenceItem("network.destination", record.Destination!, "network"));
            if (!string.IsNullOrWhiteSpace(record.ProcessName))
                evidence.Add(new DetectionEvidenceItem("process.name", record.ProcessName!, "process"));
            if (TransferBytes(record) > 0)
                evidence.Add(new DetectionEvidenceItem("flow.bytes", TransferBytes(record).ToString(CultureInfo.InvariantCulture), "flow"));

            evidence.AddRange(AnalystContext(
                $"{spec.Name} matched because concrete telemetry produced {signalReasons.Count} independent signal(s): {string.Join(", ", signalReasons.Take(6))}.",
                $"Severity is {spec.Severity} because the behavior belongs to the {spec.Category} rule family and can indicate compromise, abuse, or policy bypass when observed with these gates.",
                spec.FalsePositives.FirstOrDefault() ?? "Approved administrative or automation activity may resemble this event. Tune approved identities, sources, and destinations explicitly.",
                "Validate the source host, user or service account, and destination owner.",
                "Pivot on the same source and destination in the surrounding time window.",
                "Check for preceding credential, token, exfiltration, or lateral-movement detections before escalating."));

            return MatchCloudDev(
                context,
                spec.Severity,
                spec.Name,
                spec.Category,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "concrete-telemetry-gate");
                    confidence.AddEvidence(Math.Min(0.34, signalReasons.Count * 0.08), "independent-signals");
                    if (count >= Math.Max(1, spec.WindowThreshold))
                        confidence.AddEvidence(0.18, "window-threshold-met");
                    if (spec.RequireCrossBoundary || spec.RequireInboundExternal || spec.RequireOutboundExternal)
                        confidence.AddEvidence(0.12, "network-boundary-gate");
                    if (spec.TokenKinds.Length > 0)
                        confidence.AddEvidence(0.18, "secret-token-pattern");
                    if (spec.CorroboratedEvidenceWeight > 0)
                        confidence.AddEvidence(spec.CorroboratedEvidenceWeight, "rule-specific-corroboration");
                },
                count: count,
                window: spec.Window,
                cooldownKey: windowKey);
        }

        private static bool HasCoreTelemetry(TrafficRecord record)
        {
            var hasSource = !string.IsNullOrWhiteSpace(record.Source) || !string.IsNullOrWhiteSpace(record.SrcCountryIso2) || !string.IsNullOrWhiteSpace(record.SrcCountry);
            var hasDestination = !string.IsNullOrWhiteSpace(record.Destination) || !string.IsNullOrWhiteSpace(BestHost(record));
            var hasBehavior = HasAnyLocal(record.Protocol, record.ApplicationProtocol, record.ApplicationService, record.HttpMethod, record.HttpUri, record.HttpRequestHeaders, record.DnsQname, record.ProcessName, record.Info)
                              || record.SourcePort.HasValue
                              || record.DestinationPort.HasValue
                              || TransferBytes(record) > 0;
            return hasSource && (hasDestination || !string.IsNullOrWhiteSpace(record.ProcessName) || !string.IsNullOrWhiteSpace(record.Info)) && hasBehavior;
        }

        private static IEnumerable<string> CollectSignals(TrafficRecord record, PrecisionRuleSpec spec)
        {
            var text = Text(record);
            var path = HttpPath(record);
            var host = BestHost(record);

            var nameTokens = NameTokens(spec.Name).ToArray();
            if (nameTokens.Length > 0 && nameTokens.Count(token => ContainsAny(text, token) || ContainsAny(path, token) || ContainsAny(host, token)) >= Math.Min(2, nameTokens.Length))
                yield return "name-token-evidence";

            if (spec.TextIndicators.Length > 0 && ContainsAny(text, spec.TextIndicators))
                yield return "text-indicator";
            if (spec.HostIndicators.Length > 0 && (HostMatchesAny(host, spec.HostIndicators) || ContainsAny(host, spec.HostIndicators)))
                yield return "host-indicator";
            if (spec.PathIndicators.Length > 0 && ContainsAny(path + " " + record.HttpUri, spec.PathIndicators))
                yield return "path-indicator";
            if (spec.ProcessIndicators.Length > 0 && ContainsAny(record.ProcessName, spec.ProcessIndicators))
                yield return "process-indicator";
            if (spec.ProtocolIndicators.Length > 0 && ContainsAny(string.Join(" ", record.Protocol, record.ApplicationProtocol, record.ApplicationService), spec.ProtocolIndicators))
                yield return "protocol-indicator";
            if (spec.Methods.Length > 0 && HasMethod(record, spec.Methods))
                yield return "http-method";
            if (spec.Ports.Length > 0 && spec.Ports.Any(port => (record.SourcePort ?? -1) == port || (record.DestinationPort ?? -1) == port))
                yield return "network-port";
            if (spec.MinimumBytes > 0 && TransferBytes(record) >= spec.MinimumBytes)
                yield return "byte-threshold";
            if (spec.RequireCleartext && (IsCleartextHttp(record) || IsCleartextCredentialProtocol(record)))
                yield return "cleartext-gate";
            if ((spec.RequireOutboundExternal && IsOutboundExternalBoundary(record)) || (spec.RequireInboundExternal && IsInboundExternalBoundary(record)) || (spec.RequireCrossBoundary && IsCrossBoundary(record, out _, out _)))
                yield return "boundary-gate";
            if (spec.TokenKinds.Length > 0 && HasTokenPattern(record, spec.TokenKinds))
                yield return "token-pattern";
            if (spec.RequireHttp && HasHttpContext(record))
                yield return "http-context";
            if (spec.RequireDns && HasDnsContext(record))
                yield return "dns-context";
        }

        private static IEnumerable<string> NameTokens(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                yield break;

            foreach (var raw in Regex.Split(name.ToLowerInvariant(), @"[^a-z0-9]+"))
            {
                var token = raw.Trim();
                if (token.Length < 4)
                    continue;
                if (token is "rule" or "pattern" or "indicator" or "attempt" or "access" or "external" or "internal")
                    continue;
                yield return token;
            }
        }

        private static bool HasAnyLocal(params string?[] values)
            => values.Any(static value => !string.IsNullOrWhiteSpace(value));

        private static bool HasDnsContext(TrafficRecord record)
            => !string.IsNullOrWhiteSpace(record.DnsQname)
               || ContainsAny(record.Protocol, "dns")
               || ContainsAny(record.ApplicationProtocol, "dns")
               || ContainsAny(record.ApplicationService, "dns")
               || (record.SourcePort ?? -1) == 53
               || (record.DestinationPort ?? -1) == 53;

        private static bool IsOutboundExternalBoundary(TrafficRecord record)
            => IsInternalAddress(record.Source) && IsExternalAddress(FirstNonEmptyLocal(BestHost(record), record.Destination));

        private static bool IsInboundExternalBoundary(TrafficRecord record)
            => IsExternalAddress(record.Source) && IsInternalAddress(record.Destination);

        private static bool IsCleartextCredentialProtocol(TrafficRecord record)
        {
            var text = Text(record);
            return ((record.SourcePort ?? -1) == 21 || (record.DestinationPort ?? -1) == 21
                    || (record.SourcePort ?? -1) == 110 || (record.DestinationPort ?? -1) == 110
                    || (record.SourcePort ?? -1) == 143 || (record.DestinationPort ?? -1) == 143
                    || (record.SourcePort ?? -1) == 389 || (record.DestinationPort ?? -1) == 389)
                   && ContainsAny(text, "password", "login", "auth", "bind", "plain", "basic", "user");
        }

        private static bool HasTokenPattern(TrafficRecord record, IEnumerable<string> tokenKinds)
        {
            var text = Text(record);
            foreach (var tokenKind in tokenKinds)
            {
                if (string.Equals(tokenKind, "github", StringComparison.OrdinalIgnoreCase) && GitHubTokenRegex.IsMatch(text)) return true;
                if (string.Equals(tokenKind, "gitlab", StringComparison.OrdinalIgnoreCase) && GitLabTokenRegex.IsMatch(text)) return true;
                if (string.Equals(tokenKind, "azuredevops", StringComparison.OrdinalIgnoreCase) && AzureDevOpsPatRegex.IsMatch(text) && ContainsAny(text, "azure", "devops", "visualstudio", "pat")) return true;
                if (string.Equals(tokenKind, "circleci", StringComparison.OrdinalIgnoreCase) && CircleCiTokenRegex.IsMatch(text)) return true;
                if (string.Equals(tokenKind, "npm", StringComparison.OrdinalIgnoreCase) && NpmTokenRegex.IsMatch(text)) return true;
                if (string.Equals(tokenKind, "vault", StringComparison.OrdinalIgnoreCase) && VaultTokenRegex.IsMatch(text)) return true;
                if (string.Equals(tokenKind, "terraform", StringComparison.OrdinalIgnoreCase) && TerraformTokenRegex.IsMatch(text)) return true;
                if (string.Equals(tokenKind, "aws", StringComparison.OrdinalIgnoreCase) && AwsAccessKeyRegex.IsMatch(text)) return true;
                if (string.Equals(tokenKind, "generic", StringComparison.OrdinalIgnoreCase) && GenericSecretRegex.IsMatch(text)) return true;
            }

            return false;
        }

        private static string FirstNonEmptyLocal(params string?[] values)
            => values.FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

        private static string BuildWindowKey(TrafficRecord record, PrecisionRuleSpec spec)
            => string.Join(":", spec.RuleId, record.Source ?? "unknown", FirstNonEmptyLocal(BestHost(record), record.Destination), record.ProcessName ?? string.Empty, spec.Category);

        private static int ObserveCount(string key, DateTime now, TimeSpan window)
        {
            var list = TimeWindows.GetOrAdd(key, _ => new List<DateTime>());
            lock (list)
            {
                list.RemoveAll(timestamp => now - timestamp > window);
                list.Add(now);
                return list.Count;
            }
        }
    }
}
