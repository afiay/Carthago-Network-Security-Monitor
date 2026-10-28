// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/EvasionInfraPrecisionDetectionRuleBase.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Precision base for network-evasion, proxy/VPN/Tor, endpoint-process egress, and
    /// signal-stack correlation rules. The goal is to prevent descriptor-only detections by
    /// requiring concrete packet/process/pipeline evidence before a rule can match.
    /// </summary>
    public abstract class EvasionInfraPrecisionDetectionRuleBase : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly ConcurrentDictionary<string, List<DateTime>> TimeWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> DistinctWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, DateTime> CooldownWindows = new(StringComparer.OrdinalIgnoreCase);

        private static readonly Regex TcpOptionFingerprintRegex = new(
            @"(?i)\b(?:tcp[_\s-]*options?|tcp[_\s-]*fp|fingerprint)\s*[:=]\s*(?<value>[a-z0-9,;:\-_.|/ ]{8,120})",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex TtlRegex = new(
            @"(?i)\b(?:ttl|hop[_\s-]*limit)\s*[:=]\s*(?<value>\d{1,3})\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly string[] UserSpaceProxyProcesses =
        {
            "ngrok", "cloudflared", "frpc", "frps", "chisel", "ligolo", "socat", "sshuttle", "proxychains",
            "proxifier", "mitmproxy", "tinyproxy", "privoxy", "redsocks", "gost", "rathole", "nps", "npc"
        };

        private static readonly string[] TorHostOrServiceHints =
        {
            "torproject.org", "check.torproject.org", "torstatus", "tor metrics", "tor guard", "tor directory",
            "directory authority", "consensus", "onionoo", ".onion"
        };

        private static readonly string[] PublicVpnProxyHints =
        {
            "nordvpn", "expressvpn", "protonvpn", "surfshark", "mullvad", "privateinternetaccess", "pia-vpn",
            "cyberghost", "windscribe", "hidemyass", "hma", "ipvanish", "tunnelbear", "purevpn", "hide.me",
            "vpnbook", "vpnjantit", "openvpn free", "free vpn", "public proxy", "proxy-list", "proxyscrape",
            "webshare", "brightdata", "luminati", "residential proxy", "rotating proxy"
        };

        private static readonly string[] SuspiciousProcessNames =
        {
            "svchosts", "scvhost", "svhost", "explorer32", "chrome_update", "chromeupdate", "firefox_update",
            "windows_update", "winupdate", "updater64", "servicehost", "spoolsv32", "lsasss", "lsass64",
            "rundll32x", "msiexec32", "conhost64", "javaw_update", "system32.exe", "taskhostw32"
        };

        private static readonly string[] ScriptInterpreters =
        {
            "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "python",
            "pythonw", "node", "nodejs", "ruby", "perl", "php", "java", "groovy", "bash", "sh", "zsh",
            "curl", "wget", "bitsadmin", "certutil"
        };

        private static readonly string[] SecurityUpdateHints =
        {
            "defender", "windows defender", "security intelligence", "microsoft update", "sophos", "crowdstrike",
            "sentinelone", "carbon black", "cylance", "trendmicro", "trend micro", "eset", "kaspersky",
            "bitdefender", "avast", "avg", "clamav", "yara rules", "threat feed update", "signature update"
        };

        private static readonly string[] BlockOrFailureHints =
        {
            "blocked", "sinkhole", "blackhole", "tampered", "disabled", "failed", "failure", "timeout",
            "connection refused", "reset", "servfail", "nxdomain", "access denied", "403", "certificate error"
        };

        private static readonly string[] PipelineTamperHints =
        {
            "tamper", "disabled", "stopped", "deleted", "journal deleted", "rules disabled", "sensor stopped",
            "pipeline stopped", "detector disabled", "event writer disabled", "outbox disabled", "rule catalog changed",
            "content pack removed", "telemetry source removed", "log cleared", "service killed"
        };

        protected EvasionInfraPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }

        protected static RulePrecisionProfile CreateEvasionInfraProfile(
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
            => CreateCloudDevProfile(
                ruleId,
                maturity,
                defaultMode,
                requiredTelemetry,
                requiredFields,
                evidenceFields,
                positiveConditions,
                negativeConditions,
                minimumConfidence,
                threshold,
                window,
                cooldown,
                distinctBy,
                falsePositives,
                tuningKnobs,
                requiredTests);

        protected RuleEvaluationResult MatchEvasionInfra(
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
            var host = Descriptor.RuleId is "R261" or "R262" or "R263" or "R264" or "R265" or "R266" or "R267" or "R268" or "R269" or "R270" or "R271" or "R272"
                ? record.Destination : BestHost(record);
            var items = new List<DetectionEvidenceItem>
            {
                new("evasion.family", detectionFamily, "evasion-infra"),
                new("network.source", record.Source ?? "unknown", "network"),
                new("network.destination", string.IsNullOrWhiteSpace(host) ? record.Destination ?? "unknown" : host, "network")
            };

            if (!string.IsNullOrWhiteSpace(record.Protocol))
                items.Add(new DetectionEvidenceItem("network.protocol", record.Protocol!, "network"));
            if (record.SourcePort.HasValue)
                items.Add(new DetectionEvidenceItem("network.sourcePort", record.SourcePort.Value.ToString(CultureInfo.InvariantCulture), "network"));
            if (record.DestinationPort.HasValue)
                items.Add(new DetectionEvidenceItem("network.destinationPort", record.DestinationPort.Value.ToString(CultureInfo.InvariantCulture), "network"));
            if (Descriptor.RuleId is not ("R261" or "R262" or "R263" or "R264" or "R265" or "R266" or "R267" or "R268" or "R269" or "R270" or "R271" or "R272") && !string.IsNullOrWhiteSpace(record.ProcessName))
                items.Add(new DetectionEvidenceItem("process.name", record.ProcessName!, "process"));
            if (Descriptor.RuleId is not ("R258" or "R259" or "R260" or "R261" or "R262" or "R263" or "R264" or "R265" or "R266" or "R267" or "R268" or "R269" or "R270" or "R271" or "R272")
                && !string.IsNullOrWhiteSpace(record.Info))
                items.Add(new DetectionEvidenceItem("event.info", ShortText(record.Info!, 240), "telemetry"));

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

            if (Descriptor.RuleId is "R266" or "R267" or "R268" or "R269" or "R270" or "R271" or "R272")
            {
                evt.DestinationHost = "[REDACTED]";
                if (evt.StructuredEvidence != null)
                {
                    var safe = evt.StructuredEvidence.Items.Select(item =>
                        item.Key.Equals("destinationHost", StringComparison.OrdinalIgnoreCase)
                            ? item with { Value = "[REDACTED]" } : item).ToArray();
                    evt.StructuredEvidence = new DetectionEvidenceSet(safe, evt.StructuredEvidence.Summary);
                }
                if (evt.Evidence != null)
                    evt.Evidence = Regex.Replace(evt.Evidence, @"destinationHost=[^;]*",
                        "destinationHost=[REDACTED]", RegexOptions.IgnoreCase);
            }

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

        protected new static IEnumerable<DetectionEvidenceItem> AnalystContext(
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

        protected static bool IsOutboundExternal(TrafficRecord record)
        {
            var destination = string.IsNullOrWhiteSpace(BestHost(record)) ? record.Destination : BestHost(record);
            return IsInternalAddress(record.Source) && IsExternalAddress(destination);
        }

        protected static bool HasIcmpDestinationUnreachableContext(TrafficRecord record)
        {
            var text = Text(record);
            return ContainsAny(record.Protocol, "icmp")
                   && ContainsAny(text, "destination unreachable", "port unreachable", "host unreachable", "network unreachable", "administratively prohibited", "type 3", "icmp unreachable");
        }

        protected static bool HasTcpResetContext(TrafficRecord record)
        {
            var text = Text(record);
            return record.IsTcp
                   && ContainsAny(text, "tcp reset", "rst", "rst,ack", "connection reset", "reset storm", "flags=r", "flags: r");
        }

        protected static string TcpOptionFingerprint(TrafficRecord record)
        {
            var text = Text(record);
            var match = TcpOptionFingerprintRegex.Match(text);
            if (match.Success)
                return match.Groups["value"].Value.Trim();

            if (ContainsAny(text, "mss", "sack", "wscale", "window scale", "timestamp", "nop"))
                return ShortText(text, 120);

            return string.Empty;
        }

        protected static bool IsRareTcpOptionFingerprint(TrafficRecord record, RuleEvaluationContext context, out string fingerprint)
        {
            fingerprint = TcpOptionFingerprint(record);
            if (string.IsNullOrWhiteSpace(fingerprint) || !record.IsTcp)
                return false;

            var text = Text(record);
            if (ContainsAny(text, "rare tcp option", "unknown tcp option", "malformed tcp option", "weird tcp option", "p0f rare"))
                return true;

            var subject = $"tcp-options:{record.Source}:{record.DestinationPort ?? 0}";
            var decision = ObserveBaseline("tcp_option_fingerprint", subject, fingerprint, context, "tcp-options");
            return decision.IsFirstSeen || !decision.IsKnown;
        }

        protected static bool HasTtlAnomalyContext(TrafficRecord record, out string ttlValue)
        {
            var text = Text(record);
            ttlValue = string.Empty;
            var match = TtlRegex.Match(text);
            if (match.Success)
                ttlValue = match.Groups["value"].Value;

            return ContainsAny(text, "ttl anomaly", "ttl mismatch", "hop limit anomaly", "impossible ttl", "ttl changed", "unexpected ttl", "ttl outlier");
        }

        protected static bool HasSuspiciousFragmentationContext(TrafficRecord record)
        {
            var text = Text(record);
            return ContainsAny(text, "fragment", "fragmented", "more fragments", "mf flag", "fragment offset", "overlapping fragment", "tiny fragment", "teardrop", "atomic fragment");
        }

        protected static bool IsUserSpaceProxyProcess(TrafficRecord record)
            => ContainsAny(record.ProcessName, UserSpaceProxyProcesses) || ContainsAny(Text(record), UserSpaceProxyProcesses);

        protected static bool IsTorDirectoryOrGuardContext(TrafficRecord record)
        {
            var port = record.DestinationPort ?? record.SourcePort ?? -1;
            return ContainsAny(BestHost(record), TorHostOrServiceHints)
                   || ContainsAny(Text(record), TorHostOrServiceHints)
                   || port is 9001 or 9030 or 9040 or 9050 or 9150;
        }

        protected static bool IsPublicVpnProxyDomainContact(TrafficRecord record)
        {
            var host = BestHost(record);
            return ContainsAny(host, PublicVpnProxyHints) || ContainsAny(Text(record), PublicVpnProxyHints);
        }

        protected static bool IsSuspiciousProcessName(string? processName)
            => ContainsAny(processName, SuspiciousProcessNames);

        protected static bool IsScriptInterpreterProcess(TrafficRecord record)
            => ContainsAny(record.ProcessName, ScriptInterpreters);

        protected static bool HasDnsOrHttpContext(TrafficRecord record)
            => HasDnsContext(record) || HasHttpContext(record);

        protected static bool HasDnsContext(TrafficRecord record)
            => !string.IsNullOrWhiteSpace(record.DnsQname)
               || ContainsAny(record.Protocol, "dns")
               || ContainsAny(record.ApplicationProtocol, "dns")
               || ContainsAny(record.ApplicationService, "dns")
               || (record.SourcePort ?? -1) == 53
               || (record.DestinationPort ?? -1) == 53;

        protected static bool HasSecurityToolUpdateBlockContext(TrafficRecord record)
        {
            var text = Text(record);
            return ContainsAny(text, SecurityUpdateHints)
                   && (ContainsAny(text, BlockOrFailureHints) || ContainsAny(record.DnsRcode, "servfail", "nxdomain", "refused"));
        }

        protected static bool HasPipelineTamperContext(TrafficRecord record)
        {
            var text = Text(record);
            return ContainsAny(text, "carthago", "detector", "pipeline", "sensor", "rule engine", "journal", "outbox", "content pack")
                   && ContainsAny(text, PipelineTamperHints);
        }

        protected static bool HasThreatFeedIocLowReputationContext(TrafficRecord record)
        {
            var text = Text(record);
            var ioc = ContainsAny(text, "ioc", "indicator", "threat feed", "feed hit", "matched indicator", "known bad");
            var lowRep = ContainsAny(text, "low reputation", "malicious", "high risk", "abuse", "phishing", "botnet", "c2", "command and control", "blacklist");
            return ioc && lowRep;
        }

        protected static bool HasMultiSignalStackContext(TrafficRecord record)
        {
            var text = Text(record);
            return ContainsAny(text, "multi signal", "signal stack", "stack surge", "multiple rules", "correlation surge", "rule stack", "detections from host");
        }

        protected static int CountWithin(string key, DateTime now, TimeSpan window)
        {
            var list = TimeWindows.GetOrAdd(key, _ => new List<DateTime>());
            lock (list)
            {
                list.Add(now);
                list.RemoveAll(timestamp => now - timestamp > window);
                return list.Count;
            }
        }

        protected static int DistinctWithin(string key, string distinctValue, DateTime now, TimeSpan window)
        {
            var map = DistinctWindows.GetOrAdd(key, _ => new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase));
            map[distinctValue] = now;
            foreach (var entry in map.ToArray())
            {
                if (now - entry.Value > window)
                    map.TryRemove(entry.Key, out _);
            }

            return map.Count;
        }



        public new static void ResetSharedStateForReplay()
        {
            TimeWindows.Clear();
            DistinctWindows.Clear();
            CooldownWindows.Clear();
        }

        private static bool IsSuppressedByCooldown(string key, DateTime now, TimeSpan cooldown, out TimeSpan remaining)
        {
            remaining = TimeSpan.Zero;
            if (cooldown <= TimeSpan.Zero)
                return false;

            if (CooldownWindows.TryGetValue(key, out var previous))
            {
                var elapsed = now - previous;
                if (elapsed < cooldown)
                {
                    remaining = cooldown - elapsed;
                    return true;
                }
            }

            CooldownWindows[key] = now;
            return false;
        }

        protected static string ProcessKey(TrafficRecord record)
            => string.IsNullOrWhiteSpace(record.ProcessName) ? "unknown-process" : record.ProcessName!.Trim().ToLowerInvariant();

        protected new static string ShortText(string value, int maxLength)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            var trimmed = value.Trim();
            return trimmed.Length <= maxLength ? trimmed : trimmed.Substring(0, maxLength) + "…";
        }
    }
}
