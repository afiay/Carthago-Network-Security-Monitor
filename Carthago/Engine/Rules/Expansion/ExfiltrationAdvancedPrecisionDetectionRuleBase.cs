// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/ExfiltrationAdvancedPrecisionDetectionRuleBase.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class ExfiltrationAdvancedPrecisionDetectionRuleBase : CloudDevPrecisionDetectionRuleBase
    {
        private const long LargeTransferBytes = 100L * 1024L * 1024L;
        private const long VeryLargeTransferBytes = 500L * 1024L * 1024L;
        private const long SmallChunkMaxBytes = 128L * 1024L;

        private static readonly Regex Base64BlobRegex = new(
            @"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{80,}={0,2})(?![A-Za-z0-9+/=])",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex LongTokenRegex = new(
            @"[A-Za-z0-9_-]{48,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly string[] ArchiveExtensions =
        {
            ".zip", ".7z", ".rar", ".tar", ".tgz", ".tar.gz", ".gz", ".bz2", ".xz"
        };

        private static readonly string[] DatabaseDumpIndicators =
        {
            "dump", "backup", "db_backup", "database", "mysqldump", "pg_dump", "mongodb", "mongoexport",
            "sqldump", "sql-dump", "schema", "customers", "users", "accounts"
        };

        private static readonly string[] DatabaseDumpExtensions =
        {
            ".sql", ".dump", ".bak", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".bson"
        };

        private static readonly string[] SensitiveExtensions =
        {
            ".pem", ".key", ".pfx", ".p12", ".kdbx", ".env", ".ovpn", ".rdp", ".ppk",
            ".vault", ".secret", ".secrets", ".config", ".json", ".yml", ".yaml", ".csv", ".xlsx"
        };

        private static readonly string[] SensitiveNameIndicators =
        {
            "secret", "secrets", "credential", "credentials", "password", "passwd", "token", "apikey", "api_key",
            "private", "id_rsa", "wallet", "customer", "clients", "personnummer", "ssn", "export"
        };

        private static readonly string[] SourceCodeArchiveIndicators =
        {
            "src", "source", "sourcecode", "repo", "repository", "git", "project", "solution", "frontend", "backend",
            "node_modules", "package-lock", "requirements", "csproj", "sln"
        };

        private static readonly string[] ApprovedSyncProcesses =
        {
            "onedrive", "dropbox", "googledrive", "google drive", "drivefs", "box", "icloud", "sharepoint",
            "teams", "slack", "backup", "veeam", "rclone-approved", "rsync-approved"
        };

        private static readonly string[] KnownCloudStorageRoots =
        {
            "microsoft.com", "sharepoint.com", "onedrive.com", "dropbox.com", "box.com", "google.com", "googleapis.com",
            "storage.googleapis.com", "blob.core.windows.net", "amazonaws.com", "icloud.com", "mega.nz", "wetransfer.com"
        };

        private static readonly string[] CredentialAlertIndicators =
        {
            "credential", "password", "token", "bearer", "basic auth", "phishing", "login failure", "bruteforce",
            "brute force", "impossible travel", "session cookie", "api key", "oauth", "saml", "oidc"
        };

        protected ExfiltrationAdvancedPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }

        protected static RulePrecisionProfile CreateExfiltrationProfile(
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

        protected RuleEvaluationResult MatchExfiltration(
            RuleEvaluationContext context,
            SeverityLevel severity,
            string summary,
            string detectionFamily,
            IEnumerable<DetectionEvidenceItem> evidenceItems,
            Action<ConfidenceBuilder> configureConfidence,
            int count = 1,
            TimeSpan? window = null,
            string? cooldownKey = null)
            => MatchCloudDev(context, severity, summary, detectionFamily, evidenceItems, configureConfidence, count, window, cooldownKey);

        protected static bool IsOutboundExternal(TrafficRecord record)
        {
            var target = FirstNonEmptyLocal(BestHost(record), record.Destination);
            return IsInternalAddress(record.Source) && IsExternalAddress(target);
        }

        protected static bool IsUploadLike(TrafficRecord record)
            => IsUploadMethod(record)
               || HasUploadMetadata(record)
               || ContainsAny(Text(record), "upload", "put object", "append block", "multipart/form-data", "content-disposition");

        protected static bool IsLargeOutboundTransfer(TrafficRecord record, long minimumBytes = LargeTransferBytes)
            => IsOutboundExternal(record) && TransferBytes(record) >= minimumBytes;

        protected static bool IsVeryLargeOutboundTransfer(TrafficRecord record)
            => IsLargeOutboundTransfer(record, VeryLargeTransferBytes);

        protected static bool IsLikelyApprovedSyncOrBackup(TrafficRecord record)
            => ContainsAny(record.ProcessName, ApprovedSyncProcesses)
               || ContainsAny(UserAgent(record), "onedrive", "dropbox", "googledrive", "backup-agent", "veeam")
               || (HostMatchesAny(BestHost(record), KnownCloudStorageRoots) && IsLikelyBrowserProcess(record.ProcessName));

        protected static string EvidenceName(TrafficRecord record)
        {
            var candidates = new[]
            {
                TryGetFilenameFromHeaders(record),
                HttpPath(record),
                record.HttpUri,
                record.Info,
                BestHost(record)
            };

            foreach (var candidate in candidates)
            {
                if (!string.IsNullOrWhiteSpace(candidate))
                    return candidate!;
            }

            return string.Empty;
        }

        protected static bool LooksLikeArchiveTransfer(TrafficRecord record)
        {
            var text = EvidenceName(record);
            return ContainsAny(text, ArchiveExtensions) || ContainsAny(Text(record), "application/zip", "application/x-7z", "application/x-rar", "application/gzip", "application/x-tar");
        }

        protected static bool LooksLikeDatabaseDumpTransfer(TrafficRecord record)
        {
            var name = EvidenceName(record);
            return (ContainsAny(name, DatabaseDumpExtensions) && ContainsAny(name, DatabaseDumpIndicators))
                   || (ContainsAny(Text(record), DatabaseDumpExtensions) && ContainsAny(Text(record), DatabaseDumpIndicators));
        }

        protected static bool LooksLikeSensitiveFileTransfer(TrafficRecord record)
        {
            var name = EvidenceName(record);
            return ContainsAny(name, SensitiveExtensions) && ContainsAny(name, SensitiveNameIndicators)
                   || ContainsAny(Text(record), "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "aws_access_key_id", "private_key", "password=");
        }

        protected static bool LooksLikeSourceCodeArchiveTransfer(TrafficRecord record)
        {
            var name = EvidenceName(record);
            return LooksLikeArchiveTransfer(record)
                   && (ContainsAny(name, SourceCodeArchiveIndicators) || ContainsAny(Text(record), SourceCodeArchiveIndicators));
        }

        protected static bool IsSshScpOrSftpContext(TrafficRecord record)
            => record.IsTcp
               && ((record.SourcePort ?? -1) == 22 || (record.DestinationPort ?? -1) == 22
                   || ContainsAny(record.ApplicationProtocol, "ssh", "scp", "sftp")
                   || ContainsAny(record.ApplicationService, "ssh", "scp", "sftp")
                   || ContainsAny(Text(record), "scp", "sftp", "openssh"));

        protected static bool IsFtpUploadContext(TrafficRecord record)
            => record.IsTcp
               && ((record.SourcePort ?? -1) == 20 || (record.SourcePort ?? -1) == 21 || (record.DestinationPort ?? -1) == 20 || (record.DestinationPort ?? -1) == 21
                   || ContainsAny(record.ApplicationProtocol, "ftp")
                   || ContainsAny(record.ApplicationService, "ftp")
                   || ContainsAny(Text(record), "STOR ", "APPE ", "ftp upload"));

        protected static bool IsSmbContext(TrafficRecord record)
            => record.IsTcp
               && ((record.SourcePort ?? -1) == 445 || (record.DestinationPort ?? -1) == 445
                   || ContainsAny(record.ApplicationProtocol, "smb", "cifs")
                   || ContainsAny(record.ApplicationService, "smb", "cifs")
                   || ContainsAny(Text(record), "smb2", "tree connect", "write request", "file rename information"));

        protected static bool HasSmbWriteSemantics(TrafficRecord record)
            => ContainsAny(Text(record), "write request", "create request file", "set_info", "file rename", "upload", "copychunk", "tree connect");

        protected static bool IsIpLiteralTarget(TrafficRecord record)
        {
            var host = BestHost(record);
            if (IPAddress.TryParse(host, out _))
                return true;

            return IPAddress.TryParse(record.Destination ?? string.Empty, out _)
                   && string.IsNullOrWhiteSpace(record.HttpHost)
                   && string.IsNullOrWhiteSpace(record.Sni);
        }

        protected static bool IsUnknownExternalDomain(TrafficRecord record, RuleEvaluationContext context, TimeSpan window)
        {
            var host = BestHost(record);
            if (string.IsNullOrWhiteSpace(host) || !IsExternalAddress(host) || IsIpLiteralTarget(record))
                return false;

            if (HostMatchesAny(host, KnownCloudStorageRoots) || IsOfficialGitHost(host) || IsOfficialSlackHost(host))
                return false;

            var root = RootDomain(host);
            return !string.IsNullOrWhiteSpace(root) && FirstSeenWithinWindow($"exfil:root:{root}", context.TimestampUtc, window);
        }

        protected static bool HasHighEntropyPath(TrafficRecord record, out double entropy, out string sample)
        {
            var path = HttpPath(record);
            sample = string.Empty;
            entropy = 0;
            if (string.IsNullOrWhiteSpace(path) || path.Length < 32)
                return false;

            var tokens = path.Split(new[] { '/', '?', '&', '=', '-', '_' }, StringSplitOptions.RemoveEmptyEntries)
                .Where(token => token.Length >= 24)
                .ToArray();

            foreach (var token in tokens)
            {
                var current = ShannonEntropy(token);
                if (current > entropy)
                {
                    entropy = current;
                    sample = token.Length > 48 ? token[..48] : token;
                }
            }

            return entropy >= 4.2 && LongTokenRegex.IsMatch(path);
        }

        protected static bool HasBase64BlobInRequest(TrafficRecord record, out string sample)
        {
            var text = string.Join(" ", new[] { record.HttpUri, record.HttpRequestHeaders, record.Info }.Where(static value => !string.IsNullOrWhiteSpace(value))!);
            var match = Base64BlobRegex.Match(text);
            if (match.Success)
            {
                sample = match.Value.Length > 64 ? match.Value[..64] : match.Value;
                return true;
            }

            sample = string.Empty;
            return false;
        }

        protected static bool IsOffHours(DateTime timestampUtc)
        {
            var hour = timestampUtc.Hour;
            return hour < 6 || hour >= 20 || timestampUtc.DayOfWeek == DayOfWeek.Saturday || timestampUtc.DayOfWeek == DayOfWeek.Sunday;
        }

        protected static bool HasInternalStagingIndicators(TrafficRecord record)
            => IsInternalAddress(record.Source)
               && IsInternalAddress(record.Destination)
               && (LooksLikeArchiveTransfer(record)
                   || LooksLikeDatabaseDumpTransfer(record)
                   || LooksLikeSensitiveFileTransfer(record)
                   || ContainsAny(Text(record), "staging", "temp export", "collection", "archive", "compress", "7z", "rar", "zip"));

        protected static bool HasCredentialAlertChainIndicator(TrafficRecord record)
            => ContainsAny(Text(record), CredentialAlertIndicators)
               || ContainsAny(record.ProcessName, "mimikatz", "rubeus", "secretsdump", "laZagne", "browserpass");

        protected static string CooldownIdentity(TrafficRecord record, string suffix)
            => $"{record.Source}:{FirstNonEmptyLocal(BestHost(record), record.Destination)}:{record.DestinationPort}:{suffix}";

        protected static IEnumerable<DetectionEvidenceItem> TransferEvidence(TrafficRecord record, string matchedConditions)
        {
            var bytes = TransferBytes(record);
            var items = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", matchedConditions, "rule"),
                new("network.direction", IsOutboundExternal(record) ? "internal_to_external" : "observed", "flow")
            };

            if (bytes > 0)
                items.Add(new DetectionEvidenceItem("flow.bytes", bytes.ToString(CultureInfo.InvariantCulture), "flow"));

            var name = EvidenceName(record);
            if (!string.IsNullOrWhiteSpace(name))
                items.Add(new DetectionEvidenceItem("file_or_path.indicator", ShortText(name, 160), "payload"));

            return items;
        }

        private static string? TryGetFilenameFromHeaders(TrafficRecord record)
        {
            if (string.IsNullOrWhiteSpace(record.HttpRequestHeaders))
                return null;

            var marker = "filename=";
            var index = record.HttpRequestHeaders.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
                return null;

            var value = record.HttpRequestHeaders[(index + marker.Length)..]
                .Split(new[] { ';', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault();
            return value?.Trim().Trim('"', '\'');
        }

        private static string FirstNonEmptyLocal(params string?[] values)
        {
            foreach (var value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    return value!;
            }

            return string.Empty;
        }

        private static double ShannonEntropy(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return 0;

            var groups = value.GroupBy(static character => character);
            var length = value.Length;
            var entropy = 0.0;
            foreach (var group in groups)
            {
                var p = (double)group.Count() / length;
                entropy -= p * Math.Log(p, 2);
            }

            return entropy;
        }
    }
}
