// SPDX-License-Identifier: MIT
// File: Engine/Rules/CloudSaas/CloudSaasPrecisionDetectionRuleBase.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.Baseline;

namespace Carthago.Engine.Rules.CloudSaas
{
    public abstract class CloudSaasPrecisionDetectionRuleBase : PrecisionTelemetryDetectionRuleBase
    {
        private static readonly ConcurrentDictionary<string, List<DateTime>> TimeWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> DistinctWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, List<(DateTime TimestampUtc, long Bytes)>> ByteWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, DateTime> CooldownWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, DateTime> RecentInternalSweepBySource = new(StringComparer.OrdinalIgnoreCase);

        private static readonly string[] CommonTwoLabelPublicSuffixes =
        {
            "ac.uk", "co.uk", "gov.uk", "org.uk",
            "co.jp", "com.au", "net.au", "org.au",
            "com.br", "com.cn", "com.mx", "com.sg",
            "co.in", "co.nz"
        };

        private static readonly string[] CloudStorageHostSuffixes =
        {
            "drive.google.com", "docs.google.com", "dropbox.com", "dropboxusercontent.com",
            "box.com", "boxcloud.com", "icloud.com", "mega.nz", "pcloud.com",
            "mediafire.com", "wetransfer.com", "transfer.sh", "file.io",
            "gofile.io", "pixeldrain.com", "catbox.moe", "tmpfiles.org",
            "onedrive.com", "onedrive.live.com", "sharepoint.com",
            "storage.googleapis.com", "blob.core.windows.net", "1drv.ms"
        };

        private static readonly string[] PersonalCloudHostSuffixes =
        {
            "drive.google.com", "dropbox.com", "dropboxusercontent.com", "box.com",
            "icloud.com", "mega.nz", "pcloud.com", "mediafire.com",
            "wetransfer.com", "transfer.sh", "file.io", "gofile.io",
            "pixeldrain.com", "catbox.moe", "tmpfiles.org"
        };

        private static readonly string[] EnterpriseSyncHostSuffixes =
        {
            "docs.google.com", "onedrive.com", "onedrive.live.com", "sharepoint.com",
            "storage.googleapis.com", "blob.core.windows.net", "1drv.ms"
        };

        private static readonly string[] GitRawHostSuffixes =
        {
            "raw.githubusercontent.com", "gist.githubusercontent.com", "githubusercontent.com",
            "gitlabusercontent.com", "gitlab.com", "bitbucket.org"
        };

        private static readonly string[] ChatApiHostSuffixes =
        {
            "api.telegram.org", "discord.com", "discordapp.com", "hooks.slack.com", "slack.com"
        };

        private static readonly string[] PasteOrDropHostSuffixes =
        {
            "pastebin.com", "hastebin.com", "paste.rs", "ghostbin.com",
            "transfer.sh", "file.io", "gofile.io", "pixeldrain.com",
            "catbox.moe", "tmpfiles.org", "wetransfer.com", "mega.nz"
        };

        private static readonly string[] SaasBusinessHostSuffixes =
        {
            "salesforce.com", "atlassian.net", "notion.so", "airtable.com",
            "hubspot.com", "zendesk.com", "servicenow.com", "slack.com",
            "dropbox.com", "box.com", "sharepoint.com", "googleapis.com"
        };

        private static readonly string[] ProviderSuffixes = CloudStorageHostSuffixes
            .Concat(GitRawHostSuffixes)
            .Concat(ChatApiHostSuffixes)
            .Concat(PasteOrDropHostSuffixes)
            .Concat(SaasBusinessHostSuffixes)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(static value => value.Length)
            .ToArray();

        private static readonly HashSet<int> InternalSweepPorts = new()
        {
            22, 135, 139, 445, 3389, 5985, 5986, 5900, 1433, 3306, 5432
        };

        protected CloudSaasPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }

        internal static void ResetSharedStateForReplay()
        {
            TimeWindows.Clear();
            DistinctWindows.Clear();
            ByteWindows.Clear();
            CooldownWindows.Clear();
            RecentInternalSweepBySource.Clear();
        }

        protected RuleEvaluationResult NoMatch()
            => RuleEvaluationResult.NoMatch(Descriptor.RuleId);

        protected RuleEvaluationResult MatchCloud(
            RuleEvaluationContext context,
            SeverityLevel severity,
            string summary,
            string host,
            IEnumerable<DetectionEvidenceItem> evidenceItems,
            Action<ConfidenceBuilder> configureConfidence,
            int count = 1,
            TimeSpan? window = null,
            string? cooldownKey = null,
            bool redactHttpUri = false)
        {
            var bytes = TransferBytes(context.Record);
            var items = new List<DetectionEvidenceItem>
            {
                new("cloud.host", string.IsNullOrWhiteSpace(host) ? context.Record.Destination ?? "unknown" : host, "cloud"),
                new("cloud.providerRoot", ProviderIdentity(host), "cloud")
            };

            if (!string.IsNullOrWhiteSpace(context.Record.HttpMethod))
                items.Add(new DetectionEvidenceItem("http.method", context.Record.HttpMethod!, "http"));
            // R104/R105 omit raw URI because query parameters may contain
            // credentials, signed URLs, filenames or user identifiers.
            if (!redactHttpUri && !string.IsNullOrWhiteSpace(context.Record.HttpUri))
                items.Add(new DetectionEvidenceItem("http.uri", ShortText(context.Record.HttpUri!, 220), "http"));
            if (!string.IsNullOrWhiteSpace(context.Record.ProcessName))
                items.Add(new DetectionEvidenceItem("process.name", context.Record.ProcessName!, "process"));
            if (bytes > 0)
                items.Add(new DetectionEvidenceItem("flow.bytes", bytes.ToString(System.Globalization.CultureInfo.InvariantCulture), "flow"));

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
                EvidenceBuilder.AppendEvidence(evt, "suppression.remainingSeconds", Math.Ceiling(remaining.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule");
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

        protected static BaselineDecision ObserveBaseline(string kind, string subject, string value, RuleEvaluationContext context, string evidence)
        {
            try
            {
                return BaselineStore.Current.ObserveAsync(new BaselineObservation(kind, subject, value, context.TimestampUtc, evidence)).GetAwaiter().GetResult();
            }
            catch
            {
                return new BaselineDecision(false, true, false, "baseline unavailable", 0, null, null);
            }
        }

        protected static void TrackPotentialInternalSweep(TrafficRecord record, DateTime timestampUtc)
        {
            if (!IsInternalAddress(record.Source) || !IsInternalAddress(record.Destination))
                return;

            if (string.IsNullOrWhiteSpace(record.Source) || string.IsNullOrWhiteSpace(record.Destination))
                return;

            var port = record.DestinationPort ?? record.SourcePort ?? -1;
            var text = Text(record);
            if (!InternalSweepPorts.Contains(port)
                && !ContainsAny(text, "smb", "cifs", "admin$", "psexec", "winrm", "powershell remoting", "rdp", "ssh", "wmic", "rpc", "mssql", "mysql", "postgres"))
            {
                return;
            }

            CountDistinctValues($"internal-sweep:{record.Source}", record.Destination!, timestampUtc, TimeSpan.FromMinutes(20));
            RecentInternalSweepBySource[record.Source!] = timestampUtc;
        }

        protected static int RecentInternalSweepCount(string? source, DateTime now, TimeSpan window)
            => string.IsNullOrWhiteSpace(source)
                ? 0
                : PeekDistinctCount($"internal-sweep:{source}", now, window);

        protected static DateTime? RecentInternalSweepAt(string? source, DateTime now, TimeSpan window)
        {
            if (string.IsNullOrWhiteSpace(source))
                return null;

            if (!RecentInternalSweepBySource.TryGetValue(source, out var timestampUtc))
                return null;

            return now - timestampUtc <= window ? timestampUtc : null;
        }

        protected static string BestHost(TrafficRecord record)
        {
            var candidate = FirstPopulated(record.HttpHost, record.Sni, LooksLikeDomain(record.Destination) ? record.Destination : null);
            return NormalizeHost(candidate) ?? string.Empty;
        }

        protected static string ProviderIdentity(string? host)
        {
            var normalized = NormalizeHost(host);
            if (string.IsNullOrWhiteSpace(normalized))
                return string.Empty;

            if (LooksLikeAmazonS3Host(normalized))
                return "s3.amazonaws.com";

            foreach (var suffix in ProviderSuffixes)
            {
                if (HostMatches(normalized, suffix))
                    return suffix;
            }

            return RootDomain(normalized);
        }

        protected static bool IsInternalAddress(string? ipOrHost)
        {
            if (string.IsNullOrWhiteSpace(ipOrHost))
                return false;

            var host = ipOrHost.Trim();
            if (!IPAddress.TryParse(host, out var ip))
            {
                var normalized = NormalizeHost(host) ?? string.Empty;
                return normalized.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
                    || normalized.EndsWith(".lan", StringComparison.OrdinalIgnoreCase)
                    || normalized.EndsWith(".internal", StringComparison.OrdinalIgnoreCase)
                    || normalized.EndsWith(".corp", StringComparison.OrdinalIgnoreCase)
                    || normalized.EndsWith(".home", StringComparison.OrdinalIgnoreCase);
            }

            var bytes = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                return bytes[0] == 10
                    || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                    || (bytes[0] == 192 && bytes[1] == 168)
                    || bytes[0] == 127
                    || (bytes[0] == 169 && bytes[1] == 254);
            }

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                return ip.IsIPv6LinkLocal
                    || ip.IsIPv6SiteLocal
                    || host.StartsWith("fc", StringComparison.OrdinalIgnoreCase)
                    || host.StartsWith("fd", StringComparison.OrdinalIgnoreCase)
                    || IPAddress.IsLoopback(ip);
            }

            return false;
        }

        protected static bool IsExternalAddress(string? ipOrHost)
            => !string.IsNullOrWhiteSpace(ipOrHost) && !IsInternalAddress(ipOrHost);

        protected static bool IsUploadMethod(TrafficRecord record)
            => string.Equals(record.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase)
               || string.Equals(record.HttpMethod, "PUT", StringComparison.OrdinalIgnoreCase)
               || string.Equals(record.HttpMethod, "PATCH", StringComparison.OrdinalIgnoreCase);

        protected static long TransferBytes(TrafficRecord record)
            => Math.Max(record.Length, record.L4Len ?? 0);

        protected static bool HasUploadMetadata(TrafficRecord record)
        {
            var text = string.Join(" ", new[] { record.HttpUri, record.HttpRequestHeaders, record.Info }.Where(static value => !string.IsNullOrWhiteSpace(value))!);
            return ContainsAny(
                text,
                "upload",
                "multipart",
                "filename=",
                "content-disposition",
                "createuploadsession",
                "resumable",
                "x-goog-upload",
                "x-ms-blob-type",
                "content-range",
                "/upload",
                "/uploads",
                "/files",
                "/attachments",
                "putobject");
        }

        protected static bool HasUploadShape(TrafficRecord record, long minimumBytes = 250_000)
            => IsUploadMethod(record) || HasUploadMetadata(record) || TransferBytes(record) >= minimumBytes;

        protected static bool HasExportMetadata(TrafficRecord record)
        {
            var text = string.Join(" ", new[] { record.HttpUri, record.HttpRequestHeaders, record.Info }.Where(static value => !string.IsNullOrWhiteSpace(value))!);
            return ContainsAny(text, "export", "takeout", "archive", "backup", "bulk", "csv", "content-export", "/export", "workspace/export", "admin/export");
        }

        protected static bool HasGitPayloadHint(TrafficRecord record)
        {
            var text = string.Join(" ", new[] { record.HttpUri, record.Info }.Where(static value => !string.IsNullOrWhiteSpace(value))!);
            return ContainsAny(
                text,
                "/-/raw/",
                "/raw/",
                "?raw=1",
                "/releases/download/",
                ".ps1",
                ".exe",
                ".dll",
                ".bat",
                ".cmd",
                ".vbs",
                ".js",
                ".zip",
                ".7z",
                ".msi",
                ".hta",
                ".sh",
                ".py",
                ".jar");
        }

        protected static bool HasChatExfilHint(TrafficRecord record)
        {
            var text = string.Join(" ", new[] { record.HttpUri, record.HttpRequestHeaders, record.Info }.Where(static value => !string.IsNullOrWhiteSpace(value))!);
            return ContainsAny(text, "senddocument", "sendphoto", "sendvideo", "sendmediagroup", "sendmessage", "files.upload", "chat.postmessage", "webhook", "attachments", "completeuploadexternal");
        }

        protected static bool HasPasteUploadHint(TrafficRecord record)
        {
            var text = string.Join(" ", new[] { record.HttpUri, record.HttpRequestHeaders, record.Info }.Where(static value => !string.IsNullOrWhiteSpace(value))!);
            return HasUploadMetadata(record) || ContainsAny(text, "/documents", "/upload", "/file", "/api/upload", "/api/file");
        }

        protected static bool IsLikelyAutomationProcess(TrafficRecord record)
        {
            var process = record.ProcessName ?? string.Empty;
            var userAgent = record.HttpUserAgent ?? string.Empty;
            return ContainsAny(
                       process,
                       "powershell",
                       "pwsh",
                       "cmd",
                       "wscript",
                       "cscript",
                       "mshta",
                       "rundll32",
                       "regsvr32",
                       "curl",
                       "wget",
                       "python",
                       "node",
                       "ruby",
                       "perl",
                       "java",
                       "rclone",
                       "winscp",
                       "scp",
                       "sftp",
                       "ftp",
                       "bitsadmin",
                       "certutil")
                   || ContainsAny(
                       userAgent,
                       "curl/",
                       "wget/",
                       "python-requests",
                       "go-http-client",
                       "powershell",
                       "rclone",
                       "winscp",
                       "boto");
        }

        protected static bool IsLikelyBrowserProcess(string? processName)
            => ContainsAny(processName, "chrome", "msedge", "edge", "firefox", "brave", "opera", "iexplore", "safari");

        protected static bool IsLikelyCollaborationClientProcess(string? processName)
            => ContainsAny(processName, "slack", "teams", "discord");

        protected static bool IsCloudStorageHost(string host)
            => HostMatchesAny(host, CloudStorageHostSuffixes) || LooksLikeAmazonS3Host(host);

        protected static bool IsPersonalCloudHost(string host)
            => HostMatchesAny(host, PersonalCloudHostSuffixes);

        protected static bool IsEnterpriseSyncHost(string host)
            => HostMatchesAny(host, EnterpriseSyncHostSuffixes) || LooksLikeAmazonS3Host(host);

        protected static bool IsGitRawHost(string host)
            => HostMatchesAny(host, GitRawHostSuffixes);

        protected static bool IsChatApiHost(string host)
            => HostMatchesAny(host, ChatApiHostSuffixes);

        protected static bool IsPasteOrDropHost(string host)
            => HostMatchesAny(host, PasteOrDropHostSuffixes);

        protected static bool IsSaasBusinessHost(string host)
            => HostMatchesAny(host, SaasBusinessHostSuffixes) || IsCloudStorageHost(host);

        protected static bool TryClassifyGitRawAccess(string host, string? uri, out string classifier)
        {
            classifier = string.Empty;
            var normalizedHost = NormalizeHost(host) ?? string.Empty;
            var normalizedUri = uri ?? string.Empty;

            if (HostMatches(normalizedHost, "raw.githubusercontent.com")
                || HostMatches(normalizedHost, "gist.githubusercontent.com")
                || HostMatches(normalizedHost, "githubusercontent.com"))
            {
                classifier = "github-raw-host";
                return true;
            }

            if (HostMatches(normalizedHost, "gitlabusercontent.com"))
            {
                classifier = "gitlabusercontent-raw-host";
                return true;
            }

            if (HostMatches(normalizedHost, "gitlab.com") && ContainsAny(normalizedUri, "/-/raw/", "/raw/"))
            {
                classifier = "gitlab-raw-uri";
                return true;
            }

            if (HostMatches(normalizedHost, "bitbucket.org") && ContainsAny(normalizedUri, "/raw/"))
            {
                classifier = "bitbucket-raw-uri";
                return true;
            }

            return false;
        }

        protected static bool TryClassifyChatApiRequest(string host, TrafficRecord record, out string classifier)
        {
            classifier = string.Empty;
            var normalizedHost = NormalizeHost(host) ?? string.Empty;
            var uri = record.HttpUri ?? string.Empty;

            if (HostMatches(normalizedHost, "api.telegram.org")
                && ContainsAny(uri, "/bot")
                && ContainsAny(uri, "senddocument", "sendphoto", "sendvideo", "sendmediagroup", "sendmessage"))
            {
                classifier = "telegram-bot-api";
                return true;
            }

            if ((HostMatches(normalizedHost, "discord.com") || HostMatches(normalizedHost, "discordapp.com"))
                && ContainsAny(uri, "/api/webhooks/", "/api/v")
                && ContainsAny(uri, "/messages", "/attachments", "/webhooks/"))
            {
                classifier = "discord-api";
                return true;
            }

            if (HostMatches(normalizedHost, "hooks.slack.com") && ContainsAny(uri, "/services/"))
            {
                classifier = "slack-webhook";
                return true;
            }

            if (HostMatches(normalizedHost, "slack.com")
                && ContainsAny(uri, "/api/files.upload", "/api/chat.postmessage", "/api/files.completeuploadexternal", "/api/files.getuploadurlexternal"))
            {
                classifier = "slack-api";
                return true;
            }

            return false;
        }

        protected static int CountWindowEvents(string key, DateTime now, TimeSpan window)
        {
            var list = TimeWindows.GetOrAdd(key, _ => new List<DateTime>());
            lock (list)
            {
                list.Add(now);
                list.RemoveAll(timestamp => now - timestamp > window);
                return list.Count;
            }
        }

        protected static int CountDistinctValues(string key, string value, DateTime now, TimeSpan window)
        {
            var map = DistinctWindows.GetOrAdd(key, _ => new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase));
            map[value] = now;
            foreach (var item in map.ToArray())
            {
                if (now - item.Value > window)
                    map.TryRemove(item.Key, out _);
            }

            return map.Count;
        }

        protected static int PeekDistinctCount(string key, DateTime now, TimeSpan window)
        {
            if (!DistinctWindows.TryGetValue(key, out var map))
                return 0;

            foreach (var item in map.ToArray())
            {
                if (now - item.Value > window)
                    map.TryRemove(item.Key, out _);
            }

            return map.Count;
        }

        protected static long AddBytesWindow(string key, DateTime now, long bytes, TimeSpan window)
        {
            var list = ByteWindows.GetOrAdd(key, _ => new List<(DateTime TimestampUtc, long Bytes)>());
            lock (list)
            {
                list.Add((now, Math.Max(0L, bytes)));
                list.RemoveAll(entry => now - entry.TimestampUtc > window);
                return list.Sum(static entry => entry.Bytes);
            }
        }

        protected static long SumBytesWindow(string key, DateTime now, TimeSpan window)
        {
            if (!ByteWindows.TryGetValue(key, out var list))
                return 0;

            lock (list)
            {
                list.RemoveAll(entry => now - entry.TimestampUtc > window);
                return list.Sum(static entry => entry.Bytes);
            }
        }

        protected static int IntSetting(string ruleId, string key, int defaultValue, int min, int max)
            => RuleEngine.GetRuleIntSetting(ruleId, key, defaultValue, min, max);

        protected static double DoubleSetting(string ruleId, string key, double defaultValue, double min, double max)
            => RuleEngine.GetRuleDoubleSetting(ruleId, key, defaultValue, min, max);

        protected static RulePrecisionProfile CreateCloudSaasProfile(
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
                new HashSet<string>(new[] { "process.name", "whois.organization", "http.userAgent", "tls.sni", "geo.country" }, StringComparer.OrdinalIgnoreCase),
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

        protected static string ShortText(string value, int maxLength = 160)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length <= maxLength)
                return value;

            return value[..maxLength] + "...";
        }

        private static bool LooksLikeAmazonS3Host(string? host)
        {
            var normalized = NormalizeHost(host) ?? string.Empty;
            return normalized.EndsWith(".amazonaws.com", StringComparison.OrdinalIgnoreCase)
                   && (normalized.StartsWith("s3.", StringComparison.OrdinalIgnoreCase)
                       || normalized.Contains(".s3.", StringComparison.OrdinalIgnoreCase)
                       || normalized.Equals("s3.amazonaws.com", StringComparison.OrdinalIgnoreCase));
        }

        private static string RootDomain(string host)
        {
            var normalized = NormalizeHost(host) ?? string.Empty;
            if (string.IsNullOrWhiteSpace(normalized))
                return string.Empty;

            var parts = normalized.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length <= 2)
                return normalized;

            var suffix = parts[^2] + "." + parts[^1];
            if (parts.Length >= 3 && CommonTwoLabelPublicSuffixes.Any(value => string.Equals(value, suffix, StringComparison.OrdinalIgnoreCase)))
                return string.Join(".", parts.Skip(parts.Length - 3));

            return parts[^2] + "." + parts[^1];
        }

        private static string? NormalizeHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host))
                return null;

            var trimmed = host.Trim().TrimEnd('.').ToLowerInvariant();
            if ((trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                && Uri.TryCreate(trimmed, UriKind.Absolute, out var absoluteUri))
            {
                trimmed = absoluteUri.Host.Trim().TrimEnd('.').ToLowerInvariant();
            }

            if (trimmed.Contains('/') && Uri.TryCreate("https://" + trimmed, UriKind.Absolute, out var schemedUri))
                trimmed = schemedUri.Host.Trim().TrimEnd('.').ToLowerInvariant();

            if (trimmed.Count(character => character == ':') == 1
                && trimmed.Contains('.')
                && trimmed.LastIndexOf(':') > trimmed.LastIndexOf(']'))
            {
                trimmed = trimmed[..trimmed.LastIndexOf(':')];
            }

            return trimmed;
        }

        private static bool LooksLikeDomain(string? value)
            => !string.IsNullOrWhiteSpace(value) && value.Contains('.') && value.Any(char.IsLetter);

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
                record.ProcessName,
                record.WhoisOrganization,
                record.WhoisASN
            }.Where(static value => !string.IsNullOrWhiteSpace(value))!);

        private static bool ContainsAny(string? text, params string[] needles)
        {
            if (string.IsNullOrWhiteSpace(text))
                return false;

            foreach (var needle in needles)
            {
                if (!string.IsNullOrWhiteSpace(needle) && text.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        private static string? FirstPopulated(params string?[] values)
            => values.FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value));

        private static bool HostMatchesAny(string host, IEnumerable<string> suffixes)
        {
            foreach (var suffix in suffixes)
            {
                if (HostMatches(host, suffix))
                    return true;
            }

            return false;
        }

        private static bool HostMatches(string? host, string suffix)
        {
            var normalizedHost = NormalizeHost(host) ?? string.Empty;
            var normalizedSuffix = NormalizeHost(suffix) ?? string.Empty;
            if (string.IsNullOrWhiteSpace(normalizedHost) || string.IsNullOrWhiteSpace(normalizedSuffix))
                return false;

            return string.Equals(normalizedHost, normalizedSuffix, StringComparison.OrdinalIgnoreCase)
                   || normalizedHost.EndsWith("." + normalizedSuffix, StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsSuppressedByCooldown(string key, DateTime now, TimeSpan cooldown, out TimeSpan remaining)
        {
            remaining = TimeSpan.Zero;
            if (CooldownWindows.TryGetValue(key, out var previous) && now - previous < cooldown)
            {
                remaining = cooldown - (now - previous);
                return true;
            }

            CooldownWindows[key] = now;
            return false;
        }
    }
}
