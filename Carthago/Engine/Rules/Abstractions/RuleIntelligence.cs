// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/RuleIntelligence.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    public enum RuleMaturity
    {
        Experimental,
        Candidate,
        Stable,
        Deprecated
    }

    public enum RuleSignalKind
    {
        Signature,
        Threshold,
        Baseline,
        Behavioral,
        Correlation,
        Health,
        Inventory,
        Payload,
        ProtocolAnomaly
    }

    public sealed record RuleReference(
        string Source,
        string Title,
        string Url,
        string? ExternalId = null);

    public sealed record RuleTelemetryRequirement(
        string Name,
        bool Required,
        string Description);

    public sealed record RuleFalsePositiveNote(
        string Scenario,
        string TuningAdvice);

    public sealed record RuleIntelligence
    {
        public required string RuleId { get; init; }
        public RuleMaturity Maturity { get; init; }
        public RuleSignalKind SignalKind { get; init; }
        public IReadOnlyList<string> AttackTactics { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> AttackTechniqueIds { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
        public IReadOnlyList<RuleReference> References { get; init; } = Array.Empty<RuleReference>();
        public IReadOnlyList<RuleTelemetryRequirement> TelemetryRequirements { get; init; } = Array.Empty<RuleTelemetryRequirement>();
        public IReadOnlyList<RuleFalsePositiveNote> KnownFalsePositives { get; init; } = Array.Empty<RuleFalsePositiveNote>();
        public RulePrecisionProfile? PrecisionProfile { get; init; }
        public string InvestigationHint { get; init; } = string.Empty;
        public string TuningHint { get; init; } = string.Empty;
        public int Revision { get; init; } = 1;
    }

    public static class RuleIntelligenceFactory
    {
        public static RuleIntelligence CreateDefault(RuleDescriptor descriptor)
        {
            if (descriptor == null) throw new ArgumentNullException(nameof(descriptor));
            var n = RuleNumber(descriptor.RuleId);
            var category = descriptor.Category ?? string.Empty;
            var signal = SignalKindFor(n, category);
            var maturity = MaturityFor(n);
            var techniques = TechniquesFor(n);
            var tactics = TacticsFor(n);
            var refs = ReferencesFor(n, signal);
            var reqs = TelemetryFor(n, descriptor);
            var falsePositives = FalsePositivesFor(n, category);

            return new RuleIntelligence
            {
                RuleId = descriptor.RuleId,
                Maturity = maturity,
                SignalKind = signal,
                AttackTactics = tactics,
                AttackTechniqueIds = techniques,
                Tags = TagsFor(n, category, signal, techniques),
                References = refs,
                TelemetryRequirements = reqs,
                KnownFalsePositives = falsePositives,
                PrecisionProfile = RulePrecisionCatalog.GetProfile(descriptor),
                InvestigationHint = InvestigationHintFor(n, descriptor, techniques),
                TuningHint = TuningHintFor(n, descriptor, signal),
                Revision = 1
            };
        }

        private static int RuleNumber(string? ruleId)
            => int.TryParse((ruleId ?? string.Empty).Trim().TrimStart('R', 'r'), out var n) ? n : 0;

        private static RuleMaturity MaturityFor(int n)
        {
            if (n is >= 1 and <= 49) return RuleMaturity.Stable;
            if (n is >= 50 and <= 56) return RuleMaturity.Candidate;
            if (n is >= 57 and <= 83) return RuleMaturity.Candidate;
            if (n is >= 84 and <= 103) return RuleMaturity.Candidate;
            if (n is >= 104 and <= 122) return RuleMaturity.Experimental;
            if (n is >= 123 and <= 197) return RuleMaturity.Candidate;
            if (n is >= 198 and <= 272) return RuleMaturity.Experimental;
            if (n is >= 273 and <= 392) return RuleMaturity.Candidate;
            if (n is >= 393 and <= 528) return RuleMaturity.Experimental;
            if (n is >= 529 and <= 544) return RuleMaturity.Candidate;
            return RuleMaturity.Experimental;
        }

        private static RuleSignalKind SignalKindFor(int n, string category)
        {
            if (n is >= 50 and <= 56) return RuleSignalKind.Health;
            if (n is >= 57 and <= 66) return RuleSignalKind.Baseline;
            if (n is >= 67 and <= 72) return RuleSignalKind.ProtocolAnomaly;
            if (n is >= 73 and <= 83) return RuleSignalKind.Behavioral;
            if (n is >= 84 and <= 93) return RuleSignalKind.Payload;
            if (n is >= 94 and <= 103) return RuleSignalKind.Behavioral;
            if (n is >= 104 and <= 112) return RuleSignalKind.Behavioral;
            if (n is >= 113 and <= 122) return RuleSignalKind.ProtocolAnomaly;
            if (n is >= 123 and <= 137) return RuleSignalKind.Behavioral;
            if (n is >= 138 and <= 152) return RuleSignalKind.ProtocolAnomaly;
            if (n is >= 153 and <= 177) return RuleSignalKind.Payload;
            if (n is >= 178 and <= 197) return RuleSignalKind.Behavioral;
            if (n is >= 198 and <= 222) return RuleSignalKind.Behavioral;
            if (n is >= 223 and <= 242) return RuleSignalKind.ProtocolAnomaly;
            if (n is >= 243 and <= 257) return RuleSignalKind.Behavioral;
            if (n is >= 258 and <= 272) return RuleSignalKind.ProtocolAnomaly;
            if (n is >= 273 and <= 292) return RuleSignalKind.Behavioral;
            if (n is >= 293 and <= 312) return RuleSignalKind.ProtocolAnomaly;
            if (n is >= 313 and <= 332) return RuleSignalKind.Behavioral;
            if (n is >= 333 and <= 352) return RuleSignalKind.Behavioral;
            if (n is >= 353 and <= 372) return RuleSignalKind.Payload;
            if (n is >= 373 and <= 392) return RuleSignalKind.Behavioral;
            if (n is >= 393 and <= 412) return RuleSignalKind.Behavioral;
            if (n is >= 413 and <= 452) return RuleSignalKind.ProtocolAnomaly;
            if (n is >= 453 and <= 492) return RuleSignalKind.ProtocolAnomaly;
            if (n is >= 493 and <= 512) return RuleSignalKind.Behavioral;
            if (n is >= 513 and <= 528) return RuleSignalKind.ProtocolAnomaly;
            if (n is >= 529 and <= 544) return RuleSignalKind.Health;
            if (category.Contains("DNS", StringComparison.OrdinalIgnoreCase)) return RuleSignalKind.Behavioral;
            if (category.Contains("Network", StringComparison.OrdinalIgnoreCase)) return RuleSignalKind.Threshold;
            return RuleSignalKind.Signature;
        }

        private static IReadOnlyList<string> TechniquesFor(int n)
        {
            return n switch
            {
                7 or 94 or 102 or 103 => new[] { "T1071.004" },
                17 or 30 => new[] { "T1046" },
                26 or 76 or 78 => new[] { "T1021.002" },
                73 => new[] { "T1021.001" },
                74 => new[] { "T1021.006" },
                75 or 77 => new[] { "T1021" },
                79 => new[] { "T1087", "T1069" },
                80 or 81 or 82 => new[] { "T1558" },
                83 => new[] { "T1557.001" },
                84 => new[] { "T1190" },
                85 or 86 or 87 or 88 or 89 => new[] { "T1190" },
                90 or 93 => new[] { "T1059", "T1105" },
                91 => new[] { "T1595" },
                104 or 105 or 107 or 108 or 112 => new[] { "T1041", "T1567" },
                109 or 110 or 111 => new[] { "T1102", "T1105" },
                113 or 114 or 115 or 117 or 118 or 119 or 122 => new[] { "T1046", "T1105" },
                120 or 121 => new[] { "T0846", "T0861" },
                >= 123 and <= 137 => new[] { "T1110", "T1078" },
                >= 138 and <= 152 => new[] { "T1573", "T1071" },
                >= 153 and <= 177 => new[] { "T1190" },
                >= 178 and <= 197 => new[] { "T1071.004" },
                >= 198 and <= 222 => new[] { "T1552", "T1105", "T1567" },
                >= 223 and <= 242 => new[] { "T0846", "T0861" },
                >= 243 and <= 257 => new[] { "T1041", "T1567" },
                >= 258 and <= 272 => new[] { "T1027", "T1070", "T1090" },
                >= 273 and <= 292 => new[] { "T1078", "T1110", "T1556" },
                >= 293 and <= 312 => new[] { "T1611", "T1613", "T1528" },
                >= 313 and <= 332 => new[] { "T1566", "T1114", "T1041" },
                >= 333 and <= 352 => new[] { "T1021", "T1046", "T1558" },
                >= 353 and <= 372 => new[] { "T1195", "T1552", "T1078" },
                >= 373 and <= 392 => new[] { "T1552", "T1098", "T1567" },
                >= 393 and <= 412 => new[] { "T1071", "T1105" },
                >= 413 and <= 452 => new[] { "T1190", "T1595" },
                >= 453 and <= 472 => new[] { "T1046", "T1018" },
                >= 473 and <= 492 => new[] { "T0846", "T0861" },
                >= 493 and <= 512 => new[] { "T1041", "T1567" },
                >= 513 and <= 528 => new[] { "T1090", "T1572", "T1573" },
                _ => Array.Empty<string>()
            };
        }

        private static IReadOnlyList<string> TacticsFor(int n)
        {
            if (n is >= 73 and <= 83) return new[] { "Lateral Movement", "Discovery" };
            if (n is >= 84 and <= 93) return new[] { "Initial Access", "Execution" };
            if (n is 7 or >= 94 and <= 103) return new[] { "Command and Control" };
            if (n is >= 104 and <= 112) return new[] { "Exfiltration", "Command and Control" };
            if (n is >= 113 and <= 122) return new[] { "Discovery", "Command and Control" };
            if (n is >= 123 and <= 137) return new[] { "Initial Access", "Credential Access" };
            if (n is >= 138 and <= 152) return new[] { "Command and Control", "Defense Evasion" };
            if (n is >= 153 and <= 177) return new[] { "Initial Access", "Discovery" };
            if (n is >= 178 and <= 197) return new[] { "Command and Control", "Discovery" };
            if (n is >= 198 and <= 222) return new[] { "Credential Access", "Exfiltration", "Command and Control" };
            if (n is >= 223 and <= 242) return new[] { "Discovery", "Lateral Movement", "Impact" };
            if (n is >= 243 and <= 257) return new[] { "Collection", "Exfiltration" };
            if (n is >= 258 and <= 272) return new[] { "Defense Evasion", "Command and Control" };
            if (n is >= 273 and <= 292) return new[] { "Initial Access", "Credential Access", "Defense Evasion" };
            if (n is >= 293 and <= 312) return new[] { "Privilege Escalation", "Defense Evasion", "Credential Access" };
            if (n is >= 313 and <= 332) return new[] { "Initial Access", "Collection", "Exfiltration" };
            if (n is >= 333 and <= 352) return new[] { "Discovery", "Lateral Movement", "Credential Access" };
            if (n is >= 353 and <= 372) return new[] { "Initial Access", "Credential Access", "Resource Development" };
            if (n is >= 373 and <= 392) return new[] { "Credential Access", "Defense Evasion", "Exfiltration" };
            if (n is >= 393 and <= 412) return new[] { "Command and Control", "Execution" };
            if (n is >= 413 and <= 452) return new[] { "Initial Access", "Discovery" };
            if (n is >= 453 and <= 472) return new[] { "Discovery", "Lateral Movement" };
            if (n is >= 473 and <= 492) return new[] { "Discovery", "Impair Process Control", "Impact" };
            if (n is >= 493 and <= 512) return new[] { "Collection", "Exfiltration" };
            if (n is >= 513 and <= 528) return new[] { "Command and Control", "Defense Evasion" };
            if (n is >= 529 and <= 544) return new[] { "Detection Engineering" };
            if (n is >= 57 and <= 66) return new[] { "Discovery" };
            if (n is >= 50 and <= 56) return new[] { "Detection Engineering" };
            return Array.Empty<string>();
        }

        private static IReadOnlyList<RuleReference> ReferencesFor(int n, RuleSignalKind signal)
        {
            var refs = new List<RuleReference>
            {
                new("Sigma", "Sigma rule metadata model", "https://sigmahq.io/docs/basics/rules.html"),
                new("Zeek", "Structured network logs", "https://docs.zeek.org/en/current/logs/index.html")
            };

            if (n is 7 or >= 94 and <= 103 or >= 178 and <= 197)
                refs.Add(new("MITRE ATT&CK", "Application Layer Protocol: DNS", "https://attack.mitre.org/techniques/T1071/004/", "T1071.004"));
            if (n is >= 273 and <= 392)
                refs.Add(new("MITRE ATT&CK", "Enterprise techniques", "https://attack.mitre.org/techniques/enterprise/"));
            if (n is >= 293 and <= 312)
                refs.Add(new("MITRE ATT&CK", "Containers matrix", "https://attack.mitre.org/matrices/enterprise/containers/"));
            if (n is >= 353 and <= 392)
                refs.Add(new("CISA", "Known Exploited Vulnerabilities Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"));
            if (n is 26 or 76 or 78)
                refs.Add(new("MITRE ATT&CK", "SMB/Windows Admin Shares", "https://attack.mitre.org/techniques/T1021/002/", "T1021.002"));
            if (n == 74)
                refs.Add(new("MITRE ATT&CK", "Windows Remote Management", "https://attack.mitre.org/techniques/T1021/006/", "T1021.006"));
            if (n is >= 84 and <= 93 or >= 153 and <= 177)
                refs.Add(new("OWASP", "Web Security Testing Guide", "https://owasp.org/www-project-web-security-testing-guide/latest/"));
            if (n == 84)
            {
                refs.Add(new("CISA", "Apache Log4j vulnerability guidance", "https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance"));
                refs.Add(new("CERT/CC", "Apache Log4j allows remote code execution", "https://kb.cert.org/vuls/id/930724", "VU#930724"));
            }
            if (n is >= 198 and <= 222 or >= 243 and <= 257)
                refs.Add(new("MITRE ATT&CK", "Exfiltration Over Web Service", "https://attack.mitre.org/techniques/T1567/", "T1567"));
            if (n is >= 223 and <= 242 or >= 473 and <= 492)
                refs.Add(new("MITRE ATT&CK ICS", "ICS technique matrix", "https://attack.mitre.org/matrices/ics/"));
            if (signal is RuleSignalKind.Threshold or RuleSignalKind.Behavioral)
                refs.Add(new("Suricata", "Rule thresholding", "https://docs.suricata.io/en/latest/rules/thresholding.html"));

            return refs.DistinctBy(r => r.Url, StringComparer.OrdinalIgnoreCase).ToArray();
        }

        private static IReadOnlyList<RuleTelemetryRequirement> TelemetryFor(int n, RuleDescriptor d)
        {
            var reqs = new List<RuleTelemetryRequirement>
            {
                new("source_ip", true, "Source host/IP for attribution and baseline grouping."),
                new("destination_ip_or_host", false, "Destination endpoint for correlation and investigation."),
                new("protocol_or_port", false, "Transport or application protocol evidence when available.")
            };

            if (n is >= 57 and <= 66)
            {
                reqs.Add(new("mac_address_or_host_identity", n is 57 or 58 or 59 or 60, "MAC/IP identity used by inventory and novelty rules."));
                reqs.Add(new("baseline_store", true, "Persistent baseline store for first-seen/known-good decisions."));
            }
            if (n is >= 67 and <= 72)
                reqs.Add(new("ipv6_or_multicast_fields", true, "IPv6 version, ICMPv6, multicast, or tunnel indicators."));
            if (n is >= 73 and <= 83)
                reqs.Add(new("remote_service_port_or_protocol", true, "RDP/SMB/RPC/WinRM/WMI/LDAP/Kerberos/NTLM traffic identifiers."));
            if (n is >= 84 and <= 93)
            {
                reqs.Add(new("http_payload_or_headers", true, "HTTP URI, headers, user-agent, request metadata, or payload text."));
                reqs.Add(new("normalized_payload", true, "Decoded/normalized payload copy used for obfuscation-resistant matching."));
            }
            if (n is >= 94 and <= 103)
                reqs.Add(new("dns_query_metadata", true, "DNS qname, qtype, rcode, answer, TTL, label length, or interval metadata."));
            if (n is >= 104 and <= 112)
                reqs.Add(new("upload_direction_and_saas_host", true, "HTTP method/length plus SaaS/cloud host classification."));
            if (n is >= 113 and <= 122)
                reqs.Add(new("iot_ot_protocol_context", true, "MQTT/UPnP/Telnet/Modbus/BACnet/CoAP/Zigbee protocol, port, topic, or segment evidence."));
            if (n is >= 50 and <= 56)
                reqs.Add(new("engine_health_snapshot", true, "Rule engine health state such as gaps, drops, backpressure, journal failures, config reloads, feed freshness, or clock skew."));
            if (n is >= 123 and <= 544)
                reqs.Add(new("traffic_record_text_and_protocol_fields", true, "TrafficRecord Info, HTTP, DNS, TLS, protocol, port, process, WHOIS, and enrichment fields used by expansion heuristics."));
            if (n is >= 293 and <= 312)
                reqs.Add(new("kubernetes_container_indicators", true, "Kubernetes API, kubelet, container runtime, registry, or workload metadata evidence."));
            if (n is >= 353 and <= 392)
                reqs.Add(new("cloud_devops_indicators", true, "Cloud API, CI/CD, token, storage, metadata, or developer tooling evidence."));
            if (n is >= 473 and <= 492)
                reqs.Add(new("ot_ics_protocol_context", true, "Modbus, S7, DNP3, IEC-104, OPC UA, BACnet, Profinet, Ethernet/IP, or IEC-61850 evidence."));
            if (n is >= 529 and <= 544)
                reqs.Add(new("platform_health_signal", true, "Sensor, journal, outbox, parser, baseline, benchmark, or suppression health event evidence."));

            return reqs.DistinctBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToArray();
        }

        private static IReadOnlyList<RuleFalsePositiveNote> FalsePositivesFor(int n, string category)
        {
            if (n is >= 57 and <= 66)
                return new[] { new RuleFalsePositiveNote("New asset onboarding or DHCP churn", "Use learning mode, asset allowlists, and stable MAC/IP baseline windows.") };
            if (n is >= 84 and <= 93)
                return new[] { new RuleFalsePositiveNote("Security scanners or vulnerability validation", "Tune by source scanner IP, maintenance window, and payload confidence threshold.") };
            if (n is >= 94 and <= 103)
                return new[] { new RuleFalsePositiveNote("CDN, telemetry, or security-product generated DNS", "Tune entropy/length thresholds and allowlist known domains/providers.") };
            if (n is >= 113 and <= 122)
                return new[] { new RuleFalsePositiveNote("Legitimate IoT/OT management traffic", "Define approved brokers, controllers, segments, and administrative hosts.") };
            if (n is >= 273 and <= 292)
                return new[] { new RuleFalsePositiveNote("Legitimate identity-provider or VPN maintenance activity", "Tune by trusted IdP/VPN hosts, maintenance windows, and known admin sources.") };
            if (n is >= 293 and <= 312)
                return new[] { new RuleFalsePositiveNote("Legitimate cluster administration or CI/CD automation", "Allowlist trusted Kubernetes admins, CI runners, and cluster control planes.") };
            if (n is >= 353 and <= 392)
                return new[] { new RuleFalsePositiveNote("Legitimate DevOps/cloud automation", "Tune by approved service accounts, CI runners, cloud regions, and expected API hosts.") };
            if (n is >= 473 and <= 492)
                return new[] { new RuleFalsePositiveNote("Legitimate OT engineering workstation activity", "Define approved controllers, engineering workstations, time windows, and OT segments.") };
            if (n is >= 529 and <= 544)
                return new[] { new RuleFalsePositiveNote("Planned maintenance or testing", "Correlate with maintenance windows and platform health diagnostics before alerting analysts.") };
            return new[] { new RuleFalsePositiveNote("Environment-specific legitimate activity", "Review baseline, source role, destination role, threshold, and suppression profile before disabling the rule.") };
        }

        private static IReadOnlyList<string> TagsFor(int n, string category, RuleSignalKind signal, IReadOnlyList<string> techniques)
        {
            var tags = new List<string> { "carthago", category.ToLowerInvariant().Replace(' ', '_'), signal.ToString().ToLowerInvariant() };
            tags.AddRange(techniques.Select(t => "attack." + t.ToLowerInvariant()));
            return tags.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }

        private static string InvestigationHintFor(int n, RuleDescriptor d, IReadOnlyList<string> techniques)
        {
            var technique = techniques.Count > 0 ? $" Map to {string.Join(", ", techniques)} and inspect adjacent detections for an attack chain." : string.Empty;
            return $"Investigate {d.RuleId} by reviewing the journaled DetectionEvent evidence, packet/flow tuple, source host role, destination, and nearby rule hits.{technique}";
        }

        private static string TuningHintFor(int n, RuleDescriptor d, RuleSignalKind signal)
        {
            return signal switch
            {
                RuleSignalKind.Baseline => "Tune the learning period, allowlists, and first-seen thresholds before promoting to Stable.",
                RuleSignalKind.Payload => "Tune only after reviewing normalized and original payload evidence; prefer allowlisting trusted scanners over disabling the rule.",
                RuleSignalKind.ProtocolAnomaly => "Tune approved protocols, segments, brokers/controllers, and expected host roles per environment.",
                RuleSignalKind.Health => "Treat as platform reliability signal; tune thresholds to avoid alerting during startup or maintenance.",
                _ => "Tune threshold/window/severity through rules.json profiles without editing rule code."
            };
        }
    }
}
