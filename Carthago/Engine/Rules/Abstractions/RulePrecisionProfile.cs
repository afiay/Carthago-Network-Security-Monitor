// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/RulePrecisionProfile.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    public enum RulePrecisionMaturity
    {
        Experimental,
        Candidate,
        Validated,
        Core,
        Deprecated
    }

    public enum RuleRuntimeMode
    {
        Disabled,
        Shadow,
        Alert
    }

    public enum RuleTelemetryKind
    {
        Packet,
        Flow,
        Dns,
        Http,
        Mqtt,
        Tls,
        Ja3,
        Ja4,
        Sni,
        Payload,
        NormalizedPayload,
        ThreatIntel,
        AssetInventory,
        Identity,
        Authentication,
        GeoIp,
        Baseline,
        Process,
        CloudAudit,
        Directory,
        KubernetesAudit,
        Microsoft365Audit,
        DevOpsAudit,
        OtIcsProtocol,
        EngineHealth
    }

    public sealed record RulePrecisionProfile(
        string RuleId,
        RulePrecisionMaturity Maturity,
        RuleRuntimeMode DefaultMode,
        IReadOnlySet<RuleTelemetryKind> RequiredTelemetry,
        IReadOnlySet<string> RequiredFields,
        IReadOnlySet<string> OptionalEnrichmentFields,
        IReadOnlySet<string> EvidenceFields,
        IReadOnlyList<string> PositiveConditions,
        IReadOnlyList<string> NegativeConditions,
        int MinimumConfidence,
        int? Threshold,
        TimeSpan? Window,
        TimeSpan? Cooldown,
        string? DistinctBy,
        IReadOnlyList<string> FalsePositiveNotes,
        IReadOnlyList<string> TuningKnobs,
        IReadOnlyList<string> RequiredEnvironmentConfig,
        IReadOnlyList<string> RequiredTests);

    public sealed record RulePrecisionValidationResult(
        string RuleId,
        bool CanEvaluate,
        IReadOnlyList<string> MissingTelemetry,
        IReadOnlyList<string> MissingFields,
        IReadOnlyList<string> Warnings);

    public static class RulePrecisionCatalog
    {
        private static readonly TimeSpan DefaultWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan BurstWindow = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan LongWindow = TimeSpan.FromMinutes(30);
        private static readonly ConcurrentDictionary<string, RulePrecisionProfile> ProfileOverrides = new(StringComparer.OrdinalIgnoreCase);

        public static void RegisterProfileOverride(RulePrecisionProfile profile)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            ProfileOverrides.AddOrUpdate(profile.RuleId, profile, (_, _) => profile);
        }

        public static RulePrecisionProfile GetProfile(RuleDescriptor descriptor)
        {
            if (descriptor == null) throw new ArgumentNullException(nameof(descriptor));
            return GetProfile(descriptor.RuleId, descriptor.Category, descriptor.DefaultSeverity);
        }

        public static RulePrecisionProfile GetProfile(string ruleId, string? category = null, SeverityLevel defaultSeverity = SeverityLevel.Low)
        {
            if (!string.IsNullOrWhiteSpace(ruleId) && ProfileOverrides.TryGetValue(ruleId, out var profileOverride))
                return profileOverride;

            var n = RuleNumber(ruleId);
            category ??= string.Empty;

            var requiredTelemetry = new HashSet<RuleTelemetryKind>();
            var requiredFields = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var optionalEnrichment = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "process.name",
                "geo.country",
                "whois.asn",
                "reputation.score",
                "ja3",
                "ja4",
                "hassh"
            };
            var evidenceFields = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "source",
                "destination_or_host",
                "protocol_or_port",
                "matched_indicator",
                "precision_profile"
            };
            var positives = new List<string>();
            var negatives = new List<string>
            {
                "Do not alert from AnyText-only evidence.",
                "Do not alert from port-only or protocol-only evidence.",
                "Suppress or keep in Shadow when required telemetry/enrichment is absent."
            };
            var falsePositives = new List<string>
            {
                "Validate against asset role, maintenance window, scanners, approved services, and known automation before promoting to Alert."
            };
            var tuning = new List<string> { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "DistinctBy", "ApprovedAssets" };
            var env = new List<string>();
            var tests = new List<string>
            {
                "positive replay sample",
                "negative benign replay sample",
                "missing telemetry sample",
                "confidence floor sample"
            };

            RulePrecisionMaturity maturity;
            RuleRuntimeMode mode;
            int minimumConfidence;
            int? threshold = null;
            TimeSpan? window = null;
            TimeSpan? cooldown = TimeSpan.FromMinutes(5);
            string? distinctBy = null;

            if (n is >= 1 and <= 49)
            {
                maturity = RulePrecisionMaturity.Core;
                mode = RuleRuntimeMode.Alert;
                minimumConfidence = 65;
                requiredTelemetry.Add(RuleTelemetryKind.Packet);
                requiredTelemetry.Add(RuleTelemetryKind.Flow);
                requiredFields.Add("source");
                requiredFields.Add("destination_or_host");
                requiredFields.Add("protocol_or_port");
                positives.Add("Dedicated detector with stateful logic, suppression, and stronger telemetry assumptions.");
                negatives.Add("Do not weaken R001-R049 when applying precision-first defaults.");
                tests.Add("legacy detector preservation sample");
                return Build(ruleId, maturity, mode, requiredTelemetry, requiredFields, optionalEnrichment, evidenceFields, positives, negatives, minimumConfidence, threshold, window, cooldown, distinctBy, falsePositives, tuning, env, tests);
            }

            if (n is >= 50 and <= 56)
            {
                maturity = RulePrecisionMaturity.Validated;
                mode = RuleRuntimeMode.Alert;
                minimumConfidence = 60;
                requiredTelemetry.Add(RuleTelemetryKind.EngineHealth);
                requiredFields.Add("engine_health_signal");
                evidenceFields.Add("health.signal");
                positives.Add("Actual rule-engine or pipeline health state must be present.");
                tests.Add("engine health state sample");
                return Build(ruleId, maturity, mode, requiredTelemetry, requiredFields, optionalEnrichment, evidenceFields, positives, negatives, minimumConfidence, threshold, window, cooldown, distinctBy, falsePositives, tuning, env, tests);
            }

            maturity = n <= 122 ? RulePrecisionMaturity.Validated : (n <= 392 ? RulePrecisionMaturity.Candidate : RulePrecisionMaturity.Experimental);
            mode = n <= 122 ? RuleRuntimeMode.Alert : RuleRuntimeMode.Shadow;
            minimumConfidence = n <= 122 ? 65 : 75;
            requiredTelemetry.Add(RuleTelemetryKind.Packet);
            requiredTelemetry.Add(RuleTelemetryKind.Flow);
            requiredFields.Add("source");
            requiredFields.Add("destination_or_host");
            requiredFields.Add("protocol_or_port");
            positives.Add("Required telemetry family must match the rule family before textual indicators are evaluated.");

            switch (n)
            {
                case >= 57 and <= 66:
                    requiredTelemetry.Add(RuleTelemetryKind.AssetInventory);
                    requiredTelemetry.Add(RuleTelemetryKind.Baseline);
                    requiredFields.Add("asset_identity");
                    threshold = 2;
                    window = LongWindow;
                    distinctBy = "asset";
                    falsePositives.Add("DHCP churn, virtual interfaces, and first install/onboarding windows.");
                    break;

                case >= 67 and <= 72:
                    requiredTelemetry.Add(RuleTelemetryKind.Packet);
                    requiredFields.Add("ipv6_or_multicast");
                    mode = RuleRuntimeMode.Shadow;
                    env.Add("Profile must explicitly allow IPv6/multicast alerting.");
                    break;

                case >= 73 and <= 83:
                    requiredTelemetry.Add(RuleTelemetryKind.Identity);
                    requiredTelemetry.Add(RuleTelemetryKind.Authentication);
                    requiredFields.Add("identity_context");
                    threshold = 4;
                    window = DefaultWindow;
                    distinctBy = "destination";
                    break;

                case >= 84 and <= 93:
                    requiredTelemetry.Add(RuleTelemetryKind.Http);
                    requiredTelemetry.Add(RuleTelemetryKind.Payload);
                    requiredTelemetry.Add(RuleTelemetryKind.NormalizedPayload);
                    requiredFields.Add("http_any");
                    requiredFields.Add("payload_or_uri");
                    evidenceFields.Add("normalized.payload");
                    break;

                case >= 94 and <= 103:
                    requiredTelemetry.Add(RuleTelemetryKind.Dns);
                    requiredTelemetry.Add(RuleTelemetryKind.Baseline);
                    requiredFields.Add("dns_qname");
                    threshold = n is 102 or 103 ? 6 : 3;
                    window = n is 103 ? LongWindow : DefaultWindow;
                    distinctBy = n is 97 or 102 ? "subdomain" : "domain";
                    break;

                case >= 104 and <= 112:
                    requiredTelemetry.Add(RuleTelemetryKind.Http);
                    requiredTelemetry.Add(RuleTelemetryKind.Flow);
                    requiredFields.Add("http_upload_or_large_flow");
                    requiredFields.Add("saas_or_cloud_host");
                    threshold = n is 104 or 105 or 108 or 112 ? 2 : null;
                    window = DefaultWindow;
                    falsePositives.Add("Expected backup, synchronization, and approved SaaS export jobs.");
                    break;

                case >= 113 and <= 122:
                    requiredTelemetry.Add(RuleTelemetryKind.OtIcsProtocol);
                    requiredFields.Add("iot_or_ot_context");
                    // Keep the fallback precision profile alert-capable so profile tuning,
                    // not a missing runtime override registration, decides the final mode.
                    mode = RuleRuntimeMode.Alert;
                    env.Add("Approved IoT brokers/controllers/segments must be configured before production Alert mode.");
                    falsePositives.Add("Legitimate IoT broker, camera, hub, and field-bus traffic.");
                    break;

                case >= 123 and <= 137:
                    if (n is 133 or 134 or 135 or 136)
                        mode = RuleRuntimeMode.Alert;
                    if (n is not 124 and not 125 and not 126)
                    {
                        requiredTelemetry.Add(RuleTelemetryKind.Http);
                        requiredFields.Add("http_any");
                    }
                    requiredTelemetry.Add(RuleTelemetryKind.Identity);
                    requiredTelemetry.Add(RuleTelemetryKind.Authentication);
                    requiredFields.Add("identity_context");
                    threshold = n is 126 or 130 or 131 or 132 or 137 ? 3 : null;
                    window = n is 132 ? TimeSpan.FromMinutes(10) : DefaultWindow;
                    distinctBy = n is 132 ? "country" : "source_destination";
                    falsePositives.Add("IdP/VPN maintenance, password reset campaigns, SSO redirects, and vulnerability scanners.");
                    break;

                case >= 138 and <= 152:
                    if (n is 139 or 150)
                        mode = RuleRuntimeMode.Alert;
                    requiredTelemetry.Add(RuleTelemetryKind.Tls);
                    requiredFields.Add("tls_any");
                    if (n is 141 or 145 or 150 or 152)
                    {
                        requiredTelemetry.Add(RuleTelemetryKind.Ja3);
                        requiredTelemetry.Add(RuleTelemetryKind.Ja4);
                        requiredFields.Add("tls_fingerprint_or_sni");
                    }
                    threshold = n is 141 or 145 or 146 or 152 ? 3 : null;
                    window = n is 141 or 145 or 152 ? TimeSpan.FromMinutes(15) : DefaultWindow;
                    distinctBy = n is 152 ? "asn" : "host";
                    break;

                case >= 153 and <= 177:
                    if (n is 156 or 159 or 160 or 161 or 163 or 166 or 167 or 170 or 175 or 177)
                        mode = RuleRuntimeMode.Alert;
                    requiredTelemetry.Add(RuleTelemetryKind.Http);
                    requiredFields.Add("http_any");
                    requiredFields.Add("payload_or_uri");
                    if (n is 156 or 157 or 163 or 170 or 171 or 172 or 175 or 176 or 177)
                        requiredTelemetry.Add(RuleTelemetryKind.Payload);
                    threshold = n is 154 ? 5 : n is 155 or 169 ? 6 : null;
                    window = n is 154 ? TimeSpan.FromMinutes(2) : n is 155 ? TimeSpan.FromMinutes(3) : n is 169 ? TimeSpan.FromMinutes(10) : DefaultWindow;
                    distinctBy = n is 155 ? "uri" : null;
                    falsePositives.Add("API docs, management endpoints, backup portals, and sanctioned test tooling can resemble this traffic.");
                    break;

                case >= 178 and <= 197:
                    if (n is 178 or 182 or 189 or 195 or 197)
                        mode = RuleRuntimeMode.Alert;
                    if (n == 194)
                    {
                        requiredTelemetry.Add(RuleTelemetryKind.Http);
                        requiredTelemetry.Add(RuleTelemetryKind.Payload);
                        requiredFields.Add("http_any");
                        requiredFields.Add("payload_or_uri");
                    }
                    else if (n == 195)
                    {
                        requiredTelemetry.Add(RuleTelemetryKind.Tls);
                        requiredFields.Add("tls_any");
                    }
                    else
                    {
                        requiredTelemetry.Add(RuleTelemetryKind.Dns);
                        requiredFields.Add("dns_qname");
                    }
                    threshold = n is 181 ? 5 : n is 183 or 186 ? 8 : n is 188 ? 3 : n is 184 or 190 ? 6 : n is 196 ? 10 : null;
                    window = n is 190 ? TimeSpan.FromMinutes(5) : DefaultWindow;
                    distinctBy = n is 196 ? "root_domain" : n is 183 or 184 or 188 ? "host" : "query";
                    falsePositives.Add("Encrypted DNS, DNS research, PKI tooling, and split-horizon or failover DNS can resemble this traffic.");
                    break;

                case >= 198 and <= 217:
                    requiredTelemetry.Add(RuleTelemetryKind.Http);
                    requiredFields.Add("http_any");
                    if (n is 198 or 199 or 200 or 201 or 204 or 205 or 209 or 211 or 212 or 217)
                    {
                        requiredTelemetry.Add(RuleTelemetryKind.Payload);
                        requiredFields.Add("payload_or_uri");
                    }
                    if (n is 198 or 199 or 200 or 201 or 213 or 214 or 215 or 216 or 217)
                    {
                        requiredTelemetry.Add(RuleTelemetryKind.CloudAudit);
                        requiredFields.Add("cloud_context");
                    }
                    if (n is 202 or 203 or 204 or 205 or 206 or 207 or 208 or 209 or 210 or 211)
                    {
                        requiredTelemetry.Add(RuleTelemetryKind.DevOpsAudit);
                        requiredFields.Add("devops_or_cloud_context");
                    }
                    mode = n is 198 or 199 or 200 or 201 or 204 or 205 or 207 or 209 or 211 or 212 or 217
                        ? RuleRuntimeMode.Alert
                        : RuleRuntimeMode.Shadow;
                    threshold = n is 202 or 203 ? 6 : n is 213 ? 8 : null;
                    window = n is 202 or 203 or 213 ? TimeSpan.FromMinutes(10) : DefaultWindow;
                    distinctBy = n is 202 or 203 ? "artifact" : n is 213 ? "uri" : n is 206 or 207 or 208 or 210 ? "destination" : null;
                    falsePositives.Add("Approved cloud agents, CI/CD runners, enterprise registries, storage inventory jobs, and sanctioned collaboration integrations.");
                    break;

                case >= 218 and <= 222:
                    if (n is 218 or 219 or 220)
                    {
                        requiredTelemetry.Add(RuleTelemetryKind.Http);
                        requiredTelemetry.Add(RuleTelemetryKind.Payload);
                        requiredTelemetry.Add(RuleTelemetryKind.CloudAudit);
                        requiredFields.Add("http_any");
                        requiredFields.Add("payload_or_uri");
                        requiredFields.Add("cloud_context");
                    }
                    else
                    {
                        requiredTelemetry.Add(RuleTelemetryKind.Flow);
                        requiredTelemetry.Add(RuleTelemetryKind.Process);
                        requiredTelemetry.Add(RuleTelemetryKind.CloudAudit);
                        requiredFields.Add("destination_or_host");
                        requiredFields.Add("process_or_service");
                        requiredFields.Add("cloud_context");
                    }
                    mode = n is 218 or 219 or 220 or 222 ? RuleRuntimeMode.Alert : RuleRuntimeMode.Shadow;
                    threshold = n is 220 ? 5 : n is 221 ? 4 : n is 222 ? 3 : null;
                    window = n is 220 ? TimeSpan.FromMinutes(15) : n is 221 or 222 ? TimeSpan.FromMinutes(10) : DefaultWindow;
                    distinctBy = n is 220 or 221 or 222 ? "destination" : null;
                    falsePositives.Add("Approved collaboration bots, secure-transfer workflows, remote-support sessions, and sanctioned overlay agents.");
                    break;

                case >= 223 and <= 242:
                    requiredTelemetry.Add(RuleTelemetryKind.OtIcsProtocol);
                    requiredFields.Add("iot_or_ot_context");
                    mode = RuleRuntimeMode.Alert;
                    threshold = n is 226 or 231 or 232 or 241 or 242 ? 4 : null;
                    window = DefaultWindow;
                    env.Add("OTSegment profile plus approved OT segments/controllers.");
                    falsePositives.Add("Normal engineering workstation and controller operations inside approved OT segments.");
                    break;

                case >= 243 and <= 257:
                    requiredTelemetry.Add(RuleTelemetryKind.Flow);
                    requiredTelemetry.Add(RuleTelemetryKind.Http);
                    requiredFields.Add("http_upload_or_large_flow");
                    threshold = n is 254 or 255 ? 5 : 2;
                    window = DefaultWindow;
                    distinctBy = n is 251 or 254 ? "destination" : null;
                    falsePositives.Add("Backups, browser sync, developer uploads, and managed file transfer workflows.");
                    break;

                case >= 258 and <= 272:
                    requiredTelemetry.Add(RuleTelemetryKind.Tls);
                    requiredFields.Add("tunnel_or_proxy_context");
                    threshold = n is 264 or 270 or 271 ? 2 : null;
                    window = DefaultWindow;
                    falsePositives.Add("Approved VPN, privacy relay, remote-support, or security-monitoring tooling.");
                    break;

                case >= 273 and <= 292:
                    requiredTelemetry.Add(RuleTelemetryKind.Http);
                    requiredTelemetry.Add(RuleTelemetryKind.Identity);
                    requiredTelemetry.Add(RuleTelemetryKind.Authentication);
                    requiredFields.Add("http_any");
                    requiredFields.Add("identity_context");
                    threshold = n is 273 or 274 or 276 or 278 or 283 or 286 or 287 or 292 ? 3 : null;
                    window = DefaultWindow;
                    falsePositives.Add("Legitimate IdP enrollment, helpdesk reset, federation, and VPN workflows.");
                    break;

                case >= 293 and <= 312:
                    requiredTelemetry.Add(RuleTelemetryKind.KubernetesAudit);
                    requiredFields.Add("kubernetes_context");
                    mode = RuleRuntimeMode.Disabled;
                    threshold = n is 301 or 304 or 306 or 308 or 311 ? 3 : null;
                    window = DefaultWindow;
                    env.Add("Approved.KubernetesApiServers");
                    falsePositives.Add("Expected kubectl, CI/CD deployment, and cluster-admin activity.");
                    break;

                case >= 313 and <= 332:
                    requiredTelemetry.Add(RuleTelemetryKind.Microsoft365Audit);
                    requiredTelemetry.Add(RuleTelemetryKind.Identity);
                    requiredFields.Add("m365_context");
                    threshold = n is 313 or 314 or 315 or 323 or 326 or 331 ? 3 : null;
                    window = DefaultWindow;
                    falsePositives.Add("Expected mail export, admin center automation, and security product activity.");
                    break;

                case >= 333 and <= 352:
                    requiredTelemetry.Add(RuleTelemetryKind.Directory);
                    requiredTelemetry.Add(RuleTelemetryKind.Identity);
                    requiredFields.Add("directory_context");
                    mode = RuleRuntimeMode.Disabled;
                    threshold = n is 333 or 334 or 335 or 340 or 342 or 348 or 350 ? 3 : null;
                    window = DefaultWindow;
                    env.Add("Approved.DomainControllers");
                    falsePositives.Add("Domain controller replication, inventory scanners, and privileged admin maintenance.");
                    break;

                case >= 353 and <= 392:
                    requiredTelemetry.Add(RuleTelemetryKind.Http);
                    requiredTelemetry.Add(RuleTelemetryKind.DevOpsAudit);
                    requiredTelemetry.Add(RuleTelemetryKind.CloudAudit);
                    requiredFields.Add("http_any");
                    requiredFields.Add("devops_or_cloud_context");
                    mode = RuleRuntimeMode.Disabled;
                    threshold = n is 358 or 363 or 366 or 368 or 376 or 378 or 386 ? 5 : null;
                    window = DefaultWindow;
                    env.Add("Approved.CiCdServers or approved cloud automation identities.");
                    falsePositives.Add("Expected CI/CD, artifact, vault, package registry, and cloud automation activity.");
                    break;

                case >= 393 and <= 412:
                    requiredTelemetry.Add(RuleTelemetryKind.Payload);
                    requiredFields.Add("c2_context");
                    threshold = n is 412 ? 5 : null;
                    window = DefaultWindow;
                    falsePositives.Add("Security product labels, emulation labs, and threat-hunting replay samples.");
                    break;

                case >= 413 and <= 452:
                    requiredTelemetry.Add(RuleTelemetryKind.Flow);
                    requiredFields.Add("admin_or_service_context");
                    threshold = n is 452 ? 5 : null;
                    window = DefaultWindow;
                    falsePositives.Add("Internet-facing admin surfaces that are intentionally exposed but monitored.");
                    break;

                case >= 453 and <= 472:
                    requiredTelemetry.Add(RuleTelemetryKind.Packet);
                    requiredTelemetry.Add(RuleTelemetryKind.Flow);
                    requiredFields.Add("lan_discovery_or_remote_admin_context");
                    threshold = n is 453 or 456 or 460 or 461 or 463 or 470 or 499 ? 5 : null;
                    window = DefaultWindow;
                    falsePositives.Add("Normal LAN discovery, print/media discovery, and approved remote-support activity.");
                    break;

                case >= 473 and <= 492:
                    requiredTelemetry.Add(RuleTelemetryKind.OtIcsProtocol);
                    requiredFields.Add("iot_or_ot_context");
                    mode = RuleRuntimeMode.Alert;
                    threshold = n is 476 or 483 or 488 or 492 ? 4 : null;
                    window = DefaultWindow;
                    env.Add("OTSegment profile plus approved controllers/engineering workstations.");
                    falsePositives.Add("Approved engineering workstation activity and normal controller polling/write operations.");
                    break;

                case >= 493 and <= 512:
                    requiredTelemetry.Add(RuleTelemetryKind.Http);
                    requiredTelemetry.Add(RuleTelemetryKind.Payload);
                    requiredTelemetry.Add(RuleTelemetryKind.Flow);
                    requiredFields.Add("http_any");
                    requiredFields.Add("payload_or_uri");
                    threshold = n is 498 or 499 or 500 or 503 or 505 or 506 or 512 ? 3 : null;
                    window = DefaultWindow;
                    falsePositives.Add("Approved browser sync, backup, file-transfer, and remote desktop workflows.");
                    break;

                case >= 513 and <= 528:
                    requiredTelemetry.Add(RuleTelemetryKind.Tls);
                    requiredTelemetry.Add(RuleTelemetryKind.Process);
                    requiredFields.Add("tunnel_or_proxy_context");
                    threshold = n is 519 or 522 or 524 or 525 ? 3 : null;
                    window = DefaultWindow;
                    falsePositives.Add("Approved tunnels, VPN clients, EDR relay, reverse proxies, and remote support.");
                    break;

                case >= 529 and <= 544:
                    requiredTelemetry.Add(RuleTelemetryKind.EngineHealth);
                    requiredFields.Add("engine_health_signal");
                    mode = RuleRuntimeMode.Shadow;
                    threshold = n is 536 or 537 or 538 or 544 ? 5 : null;
                    window = DefaultWindow;
                    evidenceFields.Add("health.signal");
                    falsePositives.Add("Startup, maintenance, replay-test runs, and temporary sink/backend outages.");
                    break;
            }

            if (defaultSeverity is SeverityLevel.High or SeverityLevel.Critical && n >= 123)
            {
                positives.Add("High/Critical events require at least two independent evidence families or a threshold/distinct-window condition.");
                negatives.Add("Single keyword, host substring, generic protocol string, or port alone must return NoMatch.");
            }

            if (threshold.HasValue)
            {
                positives.Add($"Aggregate at least {threshold.Value} observations in the configured time window.");
                evidenceFields.Add("count");
            }

            if (!string.IsNullOrWhiteSpace(distinctBy))
            {
                positives.Add($"Distinct-count dimension: {distinctBy}.");
                evidenceFields.Add("distinct_by");
            }

            return Build(ruleId, maturity, mode, requiredTelemetry, requiredFields, optionalEnrichment, evidenceFields, positives, negatives, minimumConfidence, threshold, window, cooldown, distinctBy, falsePositives, tuning, env, tests);
        }

        public static RulePrecisionValidationResult Validate(string ruleId, TrafficRecord record)
        {
            var n = RuleNumber(ruleId);
            var profile = GetProfile(ruleId);

            // R050-R056 read the engine health snapshot from RuleEvaluationContext rather than packet text.
            // The profile still documents EngineHealth, but record-level validation must not block those detectors.
            if (n is >= 50 and <= 56)
                return new RulePrecisionValidationResult(profile.RuleId, true, Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>());

            var missingTelemetry = profile.RequiredTelemetry
                .Where(kind => !HasTelemetryKind(kind, record))
                .Select(kind => kind.ToString())
                .ToArray();

            var missingFields = profile.RequiredFields
                .Where(field => !HasField(field, record))
                .ToArray();

            var warnings = new List<string>();
            if (missingTelemetry.Length > 0)
                warnings.Add($"{profile.RuleId} precision profile missing telemetry: {string.Join(", ", missingTelemetry)}");
            if (missingFields.Length > 0)
                warnings.Add($"{profile.RuleId} precision profile missing fields: {string.Join(", ", missingFields)}");

            return new RulePrecisionValidationResult(
                profile.RuleId,
                missingTelemetry.Length == 0 && missingFields.Length == 0,
                missingTelemetry,
                missingFields,
                warnings);
        }

        public static RuleMode ToRuleMode(RuleRuntimeMode mode)
            => mode switch
            {
                RuleRuntimeMode.Alert => RuleMode.Alert,
                RuleRuntimeMode.Shadow => RuleMode.Shadow,
                RuleRuntimeMode.Disabled => RuleMode.Disabled,
                _ => RuleMode.Shadow
            };

        public static bool IsMoreRestrictive(RuleMode candidate, RuleMode reference)
            => Rank(candidate) < Rank(reference);

        public static RuleMode MostRestrictive(RuleMode left, RuleMode right)
            => Rank(left) <= Rank(right) ? left : right;

        public static bool HasRequiredRuntimeEvidence(
            string ruleId,
            SeverityLevel severity,
            int configuredThreshold,
            string? distinctField,
            IReadOnlyCollection<string> evidenceKinds,
            TrafficRecord record,
            out string reason)
        {
            reason = string.Empty;
            var normalizedEvidenceKinds = evidenceKinds ?? Array.Empty<string>();
            var n = RuleNumber(ruleId);
            if (n < 123) return true;

            var profile = GetProfile(ruleId);
            var hasThresholdContract = configuredThreshold > 0 || profile.Threshold.HasValue || !string.IsNullOrWhiteSpace(distinctField) || !string.IsNullOrWhiteSpace(profile.DistinctBy);
            var kindCount = normalizedEvidenceKinds.Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var hasStrongTelemetryFamily = profile.RequiredTelemetry.Any(kind => HasTelemetryKind(kind, record));
            var isHealth = profile.RequiredTelemetry.Contains(RuleTelemetryKind.EngineHealth);

            if (isHealth)
            {
                if (HasField("engine_health_signal", record))
                {
                    reason = "precision=engine-health-signal";
                    return true;
                }

                reason = "missing engine health signal";
                return false;
            }

            if (severity is SeverityLevel.High or SeverityLevel.Critical)
            {
                var hasStrongFieldEvidence = normalizedEvidenceKinds.Any(kind =>
                    string.Equals(kind, "http-request", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(kind, "uri", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(kind, "header", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(kind, "user-agent", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(kind, "dns", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(kind, "tls", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(kind, "entropy", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(kind, "baseline", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(kind, "threshold", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(kind, "distinct", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(kind, "ot-protocol-payload", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(kind, "service-command", StringComparison.OrdinalIgnoreCase));

                var weakOnly =
                    (!hasStrongFieldEvidence && !hasThresholdContract) ||
                    kindCount <= 1 ||
                    (normalizedEvidenceKinds.All(kind => string.Equals(kind, "text", StringComparison.OrdinalIgnoreCase)) && !hasThresholdContract) ||
                    (normalizedEvidenceKinds.All(kind => string.Equals(kind, "host", StringComparison.OrdinalIgnoreCase)) && !hasThresholdContract) ||
                    (normalizedEvidenceKinds.All(kind => string.Equals(kind, "port", StringComparison.OrdinalIgnoreCase)) && !hasThresholdContract) ||
                    (normalizedEvidenceKinds.All(kind => string.Equals(kind, "protocol", StringComparison.OrdinalIgnoreCase)) && !hasThresholdContract);

                if (weakOnly)
                {
                    reason = "weak evidence: high/critical expansion rules require field-level evidence, a threshold/distinct-window contract, or protocol payload evidence; text/host/port/protocol alone is not sufficient";
                    return false;
                }

                if (!hasStrongTelemetryFamily)
                {
                    reason = "missing required telemetry family";
                    return false;
                }
            }

            reason = $"precision={profile.Maturity}; mode={profile.DefaultMode}; min_confidence={profile.MinimumConfidence}";
            return true;
        }

        public static bool HasTelemetryKind(RuleTelemetryKind kind, TrafficRecord? record)
        {
            if (record == null) return false;

            return kind switch
            {
                RuleTelemetryKind.Packet => HasAny(record.Source, record.Destination, record.Protocol) || record.SourcePort.HasValue || record.DestinationPort.HasValue,
                RuleTelemetryKind.Flow => HasAny(record.Source, record.Destination) || record.Length > 0 || record.L4Len.HasValue,
                RuleTelemetryKind.Dns => HasAny(record.DnsQname, record.DnsQtype, record.DnsRcode, record.DnsAnswers),
                RuleTelemetryKind.Http => HasAny(record.HttpMethod, record.HttpHost, record.HttpUri, record.HttpUserAgent, record.HttpRequestHeaders),
                RuleTelemetryKind.Mqtt => HasAny(record.ApplicationProtocol, record.ApplicationService, record.Info) && ContainsAny(Text(record), "mqtt", "zigbee2mqtt", "mqtt topic", "publish", "subscribe", "retain", "last will"),
                RuleTelemetryKind.Tls => HasAny(record.Sni, record.TlsSni, record.TlsVersion, record.Alpn, record.Ja3, record.Ja4, record.Ja4S, record.Ja4X, record.CertIssuer, record.CertSubject),
                RuleTelemetryKind.Ja3 => HasAny(record.Ja3),
                RuleTelemetryKind.Ja4 => HasAny(record.Ja4, record.Ja4S, record.Ja4X, record.Ja4H, record.Ja4SSH, record.Ja4T, record.Ja4TS),
                RuleTelemetryKind.Sni => HasAny(record.Sni, record.TlsSni),
                RuleTelemetryKind.Payload => HasAny(record.Info, record.HttpUri, record.HttpRequestHeaders, record.HttpUserAgent),
                RuleTelemetryKind.NormalizedPayload => HasAny(record.Info, record.HttpUri, record.HttpRequestHeaders),
                RuleTelemetryKind.ThreatIntel => record.ReputationIsMalicious.HasValue || record.ReputationScore.HasValue || HasAny(record.WhoisASN, record.WhoisOrganization),
                RuleTelemetryKind.AssetInventory => HasAny(record.MacSource, record.MacDestination, record.Source, record.ProcessName),
                RuleTelemetryKind.Identity => HasField("identity_context", record),
                RuleTelemetryKind.Authentication => HasField("identity_context", record),
                RuleTelemetryKind.GeoIp => HasAny(record.SrcCountry, record.SrcCountryIso2, record.DstCountry, record.DstCountryIso2, record.WhoisCountry),
                RuleTelemetryKind.Baseline => true,
                RuleTelemetryKind.Process => HasAny(record.ProcessName) || record.ProcessId > 0 || HasAny(record.HttpUserAgent),
                RuleTelemetryKind.CloudAudit => HasField("cloud_context", record) || HasField("devops_or_cloud_context", record),
                RuleTelemetryKind.Directory => HasField("directory_context", record),
                RuleTelemetryKind.KubernetesAudit => HasField("kubernetes_context", record),
                RuleTelemetryKind.Microsoft365Audit => HasField("m365_context", record),
                RuleTelemetryKind.DevOpsAudit => HasField("devops_or_cloud_context", record),
                RuleTelemetryKind.OtIcsProtocol => HasField("iot_or_ot_context", record),
                RuleTelemetryKind.EngineHealth => HasField("engine_health_signal", record),
                _ => false
            };
        }

        public static bool HasField(string field, TrafficRecord? record)
        {
            if (record == null || string.IsNullOrWhiteSpace(field)) return false;
            var text = Text(record);
            var proto = ProtocolText(record);
            var host = HostText(record);

            return field.ToLowerInvariant() switch
            {
                "source" => HasAny(record.Source),
                "destination" => HasAny(record.Destination),
                "destination_or_host" => HasAny(record.Destination, record.HttpHost, record.Sni, record.DnsQname),
                "process.name" => HasAny(record.ProcessName),
                "device_authentication_attempt" => SensitiveTelemetryContracts.HasDefaultCredentialAuthenticationAttempt(record),
                "metadata_credential_request" => SensitiveTelemetryContracts.HasCredentialBearingMetadataRequest(record),
                "windows_protocol_context" => HasAny(record.Destination)
                    && Port(record, 5985, 5986)
                    && HasField("identity_context", record)
                    && HasTelemetryKind(RuleTelemetryKind.Process, record),
                "ot_asset_destination" => HasAny(record.Destination) && HasField("iot_or_ot_context", record),
                "ics_protocol_function" => HasField("iot_or_ot_context", record)
                    && ContainsAny(text, "writeproperty", "write property", "function 05", "function 06", "function 15", "function 16", "function 0x05", "function 0x06", "function 0x0f", "function 0x10", "readproperty", "read property", "devicecommunicationcontrol", "forwardopen", "setname", "start cpu", "stop cpu", "force listen", "read device identification"),
                "external_destination_or_resolver" => HasAny(record.Destination)
                    && HasAny(record.Sni, record.HttpHost, record.DnsQname)
                    && (HasField("tunnel_or_proxy_context", record) || HasField("cloud_context", record)),
                "tunnel_or_proxy_indicator" => HasField("tunnel_or_proxy_context", record),
                "devops_or_secret_context" => HasField("devops_or_cloud_context", record)
                    && (HasTelemetryKind(RuleTelemetryKind.Http, record) || HasTelemetryKind(RuleTelemetryKind.Process, record)),
                "kubernetes_or_container_context" => HasField("kubernetes_context", record)
                    && (HasTelemetryKind(RuleTelemetryKind.Http, record) || HasTelemetryKind(RuleTelemetryKind.Process, record)),
                "external_destination_or_upload_host" => HasAny(record.Destination, record.HttpHost)
                    && HasField("http_upload_or_large_flow", record)
                    && HasAny(record.HttpHost, record.Sni),
                "file_or_payload_indicator" => HasField("http_upload_or_large_flow", record)
                    && (ContainsAny(text, "upload", "archive", "multipart", "file=", "filename=", "export", "dump", "backup")
                        || Math.Max(record.Length, record.L4Len ?? 0) >= 500_000),
                "database_destination" => HasAny(record.Destination)
                    && Port(record, 3306, 5432, 6379, 9200, 11211, 27017, 7687, 5672, 4222)
                    && HasAny(record.ApplicationProtocol, record.ApplicationService, record.Info),
                "database_protocol_or_query_marker" => HasAny(record.Destination)
                    && ContainsAny(text, "redis", "config set", "postgres", "mysql", "mongodb", "memcached", "select ", "query", "export", "dump", "replication", "rabbitmq", "neo4j", "nats", "zookeeper", "auth "),
                "protocol_or_port" => HasAny(record.Protocol, record.ApplicationProtocol, record.ApplicationService) || record.SourcePort.HasValue || record.DestinationPort.HasValue,
                "asset_identity" => HasAny(record.MacSource, record.MacDestination, record.Source, record.ProcessName),
                "ipv6_or_multicast" => record.IpVersion == 6 || ContainsAny(text, "icmpv6", "router advertisement", "neighbor solicitation", "ff02", "multicast", "teredo", "6to4", "isatap"),
                "identity_context" => HasAny(record.ProcessName, record.HttpUserAgent, record.HttpRequestHeaders, record.HttpUri, record.Info) && ContainsAny(text, "login", "signin", "auth", "password", "saml", "oauth", "oidc", "mfa", "totp", "webauthn", "kerberos", "ldap", "ntlm", "winrm", "rdp", "smb", "psexec", "wmi", "vpn"),
                "http_any" => HasTelemetryKind(RuleTelemetryKind.Http, record),
                "payload_or_uri" => HasAny(record.Info, record.HttpUri, record.HttpRequestHeaders, record.HttpUserAgent),
                "dns_qname" => HasAny(record.DnsQname),
                "dns_qtype" => HasAny(record.DnsQtype),
                "dns_answers" => HasAny(record.DnsAnswers),
                "dns_rcode" => HasAny(record.DnsRcode),
                "dns_ttl" => record.DnsTtl.HasValue,
                "http_upload_or_large_flow" => string.Equals(record.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase) || string.Equals(record.HttpMethod, "PUT", StringComparison.OrdinalIgnoreCase) || string.Equals(record.HttpMethod, "PATCH", StringComparison.OrdinalIgnoreCase) || Math.Max(record.Length, record.L4Len ?? 0) >= 500_000 || ContainsAny(text, "upload", "post ", "multipart", "put "),
                "saas_or_cloud_host" => ContainsAny(host, "drive.google.com", "docs.google.com", "dropbox", "onedrive", "sharepoint", "box.com", "icloud", "mega.nz", "storage.googleapis.com", "blob.core.windows.net", "s3.amazonaws.com", "slack.com", "discord", "telegram", "pastebin", "transfer.sh", "github", "gitlab", "googleapis", "azure", "amazonaws"),
                // A router HTTP administration request is device context only when a real
                // default-credential authentication attempt was observed. A hostname or
                // free-form mention of a router alone must not qualify.
                "iot_or_ot_context" => (HasAny(record.HttpHost)
                    && ContainsAny(record.HttpHost!, "router", "gateway", "mikrotik", "netgear", "tplink", "ubiquiti")
                    && SensitiveTelemetryContracts.HasDefaultCredentialAuthenticationAttempt(record))
                    || ContainsAny(text, "mqtt", "modbus", "bacnet", "dnp3", "s7", "s7comm", "opc ua", "opcua", "profinet", "ethernet/ip", "ethernetip", "iec104", "iec 104", "iec61850", "goose", "mms", "coap", "zigbee", "rtsp", "onvif", "camera", "nvr", "telnet", "upnp")
                    || (Port(record, 23, 102, 502, 1883, 1900, 20000, 2404, 47808, 44818, 4840, 5683, 5684, 8883) && HasAny(record.ApplicationProtocol, record.ApplicationService, record.Info)),
                "tls_any" => HasTelemetryKind(RuleTelemetryKind.Tls, record),
                "tls_fingerprint_or_sni" => HasAny(record.Sni, record.TlsSni, record.Ja3, record.Ja4, record.Ja4S, record.Ja4X, record.Ja4H, record.Alpn) || ContainsAny(text, "ja3", "ja4", "sni", "certificate", "issuer", "subject"),
                "cloud_context" => ContainsAny(host, "amazonaws", "aws", "azure", "windows.net", "googleapis", "gcp", "metadata.google.internal", "169.254.169.254", "blob.core.windows.net", "storage.googleapis.com", "s3.amazonaws.com", "slack.com", "discord.com", "discordapp.com", "telegram.org", "pastebin.com", "transfer.sh", "file.io", "dropbox", "sharepoint", "onedrive") || ContainsAny(text, "cloudtrail", "guardduty", "assumerole", "x-amz", "metadata/identity", "computeMetadata", "serviceaccount", "cloud-platform", "webhook", "senddocument", "upload", "paste", "slack", "discord", "telegram"),
                "kubernetes_context" => ContainsAny(text, "kubernetes", "kubelet", "kubectl", "/api/v1", "/apis/apps", "namespaces", "pods", "serviceaccounts", "etcd", "container", "docker", "gcr.io", "acr.io")
                    || (Port(record, 2375, 2376, 2379, 2380, 6443, 10250, 10255) && HasAny(record.HttpUri, record.HttpHost, record.HttpRequestHeaders, record.Info)),
                "m365_context" => ContainsAny(host, "login.microsoftonline.com", "graph.microsoft.com", "office.com", "outlook.office", "sharepoint.com", "onmicrosoft.com", "microsoftonline") || ContainsAny(text, "office365", "microsoft 365", "m365", "exchange", "mailbox", "onedrive", "sharepoint", "graph api", "ews", "oauth2", "devicecode"),
                "directory_context" => ContainsAny(text, "active directory", "domain controller", "kerberos", "ldap", "dcsync", "samr", "lsarpc", "ntlm", "bloodhound", "sharp hound", "gpo", "adminsdholder", "spn")
                    || (Port(record, 53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 5985, 5986) && HasAny(record.ApplicationProtocol, record.ApplicationService, record.Info, record.ProcessName)),
                "devops_or_cloud_context" => ContainsAny(host, "github", "gitlab", "dev.azure.com", "azure.com", "jenkins", "circleci", "buildkite", "bamboo", "terraform", "vault", "docker.io", "registry", "npmjs.org", "pypi.org", "maven", "sonatype", "nexus", "artifactory", "amazonaws", "googleapis", "blob.core.windows.net") || ContainsAny(text, "github", "gitlab", "jenkins", "dev.azure", "personalaccesstoken", "x-vault-token", "terraform", "vault", "npm_token", "_authtoken", "pypi", "twine", "artifact", "build", "runner", "secret", "cloudtrail", "guardduty", "metadata"),
                "c2_context" => HasTelemetryKind(RuleTelemetryKind.Http, record) || HasTelemetryKind(RuleTelemetryKind.Tls, record) || HasAny(record.ProcessName, record.Sni, record.HttpUserAgent),
                "admin_or_service_context" => HasTelemetryKind(RuleTelemetryKind.Http, record) || ContainsAny(text, "admin", "login", "api", "config", "redis", "postgres", "mysql", "mongo", "elasticsearch", "grafana", "prometheus", "jupyter", "airflow")
                    || (Port(record, 22, 80, 443, 2375, 2376, 3306, 5432, 6379, 8080, 8443, 9200, 9300, 11211, 27017) && HasAny(record.ApplicationProtocol, record.ApplicationService, record.Info, record.ProcessName)),
                "lan_discovery_or_remote_admin_context" => ContainsAny(text, "mdns", "ssdp", "m-search", "airplay", "chromecast", "netbios", "dhcp", "arp", "capwap", "adb", "rdp", "remote support")
                    || (Port(record, 23, 137, 138, 139, 445, 1900, 5353, 3389, 5985, 5986, 8008, 8009, 9100) && HasAny(record.ApplicationProtocol, record.ApplicationService, record.Info, record.ProcessName)),
                "tunnel_or_proxy_context" => HasAny(record.ProcessName, record.Sni, record.HttpHost, record.HttpUserAgent) && ContainsAny(text, "tor", "i2p", "proxy", "vpn", "wireguard", "tailscale", "zerotier", "ngrok", "cloudflared", "trycloudflare", "frp", "chisel", "stunnel", "socat", "rclone", "ssh", "quic", "masque"),
                "engine_health_signal" => ContainsAny(record.Protocol, "health") || ContainsAny(record.Source, "carthago", "sensor", "engine") || ContainsAny(record.Info, "engine", "health", "drop", "gap", "journal", "sink", "queue", "parser", "geoip", "reputation", "baseline", "benchmark", "content pack", "suppression", "clock skew", "disk", "no space", "failed", "failure", "error"),
                _ => false
            };
        }

        private static RulePrecisionProfile Build(
            string ruleId,
            RulePrecisionMaturity maturity,
            RuleRuntimeMode mode,
            IReadOnlySet<RuleTelemetryKind> requiredTelemetry,
            IReadOnlySet<string> requiredFields,
            IReadOnlySet<string> optionalEnrichment,
            IReadOnlySet<string> evidenceFields,
            IReadOnlyList<string> positives,
            IReadOnlyList<string> negatives,
            int minimumConfidence,
            int? threshold,
            TimeSpan? window,
            TimeSpan? cooldown,
            string? distinctBy,
            IReadOnlyList<string> falsePositives,
            IReadOnlyList<string> tuning,
            IReadOnlyList<string> env,
            IReadOnlyList<string> tests)
        {
            return new RulePrecisionProfile(
                ruleId,
                maturity,
                mode,
                new HashSet<RuleTelemetryKind>(requiredTelemetry),
                new HashSet<string>(requiredFields, StringComparer.OrdinalIgnoreCase),
                new HashSet<string>(optionalEnrichment, StringComparer.OrdinalIgnoreCase),
                new HashSet<string>(evidenceFields, StringComparer.OrdinalIgnoreCase),
                positives.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                negatives.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                Math.Max(0, Math.Min(100, minimumConfidence)),
                threshold,
                window,
                cooldown,
                distinctBy,
                falsePositives.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                tuning.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                env.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                tests.Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
        }

        private static int RuleNumber(string? ruleId)
            => int.TryParse((ruleId ?? string.Empty).Trim().TrimStart('R', 'r'), out var n) ? n : 0;

        private static int Rank(RuleMode mode)
            => mode switch
            {
                RuleMode.Disabled => 0,
                RuleMode.Shadow => 1,
                RuleMode.Alert => 2,
                _ => 1
            };

        private static bool Port(TrafficRecord record, params int[] ports)
        {
            if (ports == null || ports.Length == 0) return false;
            return (record.SourcePort.HasValue && ports.Contains(record.SourcePort.Value))
                || (record.DestinationPort.HasValue && ports.Contains(record.DestinationPort.Value));
        }

        private static bool HasAny(params string?[] values)
            => values.Any(value => !string.IsNullOrWhiteSpace(value));

        private static bool LooksLikeDomain(string? value)
            => !string.IsNullOrWhiteSpace(value) && value.Contains('.') && value.Any(char.IsLetter);

        private static string ProtocolText(TrafficRecord record)
            => string.Join(" ", new[] { record.Protocol, record.ApplicationProtocol, record.ApplicationService }.Where(value => !string.IsNullOrWhiteSpace(value))!);

        private static string HostText(TrafficRecord record)
            => string.Join(" ", new[] { record.Destination, record.HttpHost, record.Sni, record.DnsQname, record.WhoisOrganization }.Where(value => !string.IsNullOrWhiteSpace(value))!);

        private static string Text(TrafficRecord record)
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
                record.Alpn,
                record.TlsVersion,
                record.Ja3,
                record.Ja4,
                record.Ja4H,
                record.Ja4SSH,
                record.Hassh,
                record.DnsQname,
                record.DnsQtype,
                record.DnsRcode,
                record.DnsAnswers,
                record.ProcessName,
                record.WhoisRegistrar,
                record.WhoisOrganization,
                record.WhoisCountry,
                record.WhoisASN
            }.Where(value => !string.IsNullOrWhiteSpace(value))!);

        private static bool ContainsAny(string? text, params string[] needles)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;
            foreach (var needle in needles)
            {
                if (!string.IsNullOrWhiteSpace(needle) && text.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }
    }
}
