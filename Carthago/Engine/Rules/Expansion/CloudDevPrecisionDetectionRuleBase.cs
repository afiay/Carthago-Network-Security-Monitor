// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/CloudDevPrecisionDetectionRuleBase.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.Baseline;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class CloudDevPrecisionDetectionRuleBase : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly ConcurrentDictionary<string, List<(DateTime TimestampUtc, long Bytes)>> ByteWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, DateTime> CooldownWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, DateTime> SeenValues = new(StringComparer.OrdinalIgnoreCase);

        private static readonly string[] CommonTwoLabelPublicSuffixes =
        {
            "ac.uk", "co.uk", "gov.uk", "org.uk",
            "co.jp", "com.au", "net.au", "org.au",
            "com.br", "com.cn", "com.mx", "com.sg",
            "co.in", "co.nz"
        };

        private static readonly string[] OfficialGitHosts =
        {
            "github.com", "gitlab.com", "bitbucket.org", "dev.azure.com", "visualstudio.com", "git.sr.ht"
        };

        private static readonly string[] OfficialContainerRegistryHosts =
        {
            "docker.io", "registry-1.docker.io", "auth.docker.io", "ghcr.io", "quay.io",
            "mcr.microsoft.com", "public.ecr.aws", "gcr.io", "pkg.dev"
        };

        private static readonly string[] OfficialPackageRegistryHosts =
        {
            "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org", "pythonhosted.org",
            "api.nuget.org", "nuget.org", "repo.maven.apache.org", "repo1.maven.org", "rubygems.org",
            "www.powershellgallery.com", "powershellgallery.com"
        };

        private static readonly string[] OfficialPowerShellGalleryHosts =
        {
            "www.powershellgallery.com", "powershellgallery.com"
        };

        private static readonly string[] RawScriptHosts =
        {
            "raw.githubusercontent.com", "gist.githubusercontent.com", "gitlabusercontent.com",
            "pastebin.com", "hastebin.com", "paste.rs", "gist.github.com"
        };

        private static readonly string[] PasteOrDropHosts =
        {
            "pastebin.com", "hastebin.com", "paste.rs", "ghostbin.com", "rentry.co",
            "paste.ee", "dpaste.com", "transfer.sh"
        };

        private static readonly string[] CloudStorageHosts =
        {
            "blob.core.windows.net", "storage.googleapis.com", "storage.cloud.google.com"
        };

        private static readonly string[] SlackHosts =
        {
            "hooks.slack.com", "slack.com"
        };

        private static readonly string[] KubernetesComponentProcesses =
        {
            "kubelet", "kubectl", "helm", "kube-proxy", "kube-apiserver", "kube-controller",
            "containerd", "crictl", "flanneld", "calico", "istio"
        };

        private static readonly string[] PackageManagerProcessHints =
        {
            "npm", "pnpm", "yarn", "node", "pip", "poetry", "python", "nuget", "dotnet",
            "maven", "gradle", "gem", "bundle", "ruby"
        };

        private static readonly string[] AutomationProcessHints =
        {
            "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
            "curl", "wget", "python", "node", "ruby", "perl", "java", "rclone", "winscp",
            "scp", "sftp", "ftp", "bitsadmin", "certutil"
        };

        private static readonly string[] BrowserProcessHints =
        {
            "chrome", "msedge", "edge", "firefox", "brave", "opera", "iexplore", "safari"
        };

        private static readonly string[] CollaborationClientProcessHints =
        {
            "slack", "teams", "discord", "telegram"
        };

        private static readonly string[] RemoteDesktopVendorHints =
        {
            "anydesk", "teamviewer", "screenconnect", "connectwise", "splashtop", "rustdesk"
        };

        private static readonly string[] OverlayVendorHints =
        {
            "tailscale", "zerotier", "ngrok", "trycloudflare", "argotunnel", "cfargotunnel", "cloudflared", "wireguard"
        };

        private static readonly int[] OverlayNetworkPorts =
        {
            3478, 7844, 9993, 41641, 51820
        };

        protected CloudDevPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }

        protected static RulePrecisionProfile CreateCloudDevProfile(
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
                new HashSet<string>(new[] { "process.name", "http.user_agent", "whois.organization", "whois.asn", "geo.country" }, StringComparer.OrdinalIgnoreCase),
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

        protected RuleEvaluationResult MatchCloudDev(
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
            var host = BestHost(record);
            var path = HttpPath(record);
            var bytes = TransferBytes(record);
            var items = new List<DetectionEvidenceItem>
            {
                new("clouddev.family", detectionFamily, "cloud-dev"),
                new("clouddev.host", Descriptor.RuleId is "R381" or "R382" or "R383" or "R384" or "R385" or "R386" or "R387" or "R388" or "R389" or "R390" or "R221" or "R222" or "R243" or "R244" or "R245" or "R246" or "R247" or "R248" or "R249" or "R250" or "R251" or "R252" or "R253" or "R254" or "R255" or "R256" or "R257" ? "[REDACTED]" : string.IsNullOrWhiteSpace(host) ? record.Destination ?? "unknown" : host, "cloud-dev")
            };

            if (!string.IsNullOrWhiteSpace(path))
                items.Add(new DetectionEvidenceItem("http.path", Descriptor.RuleId is "R353" or "R354" or "R355" or "R356" or "R357" or "R358" or "R359" or "R360" or "R361" or "R362" or "R363" or "R364" or "R365" or "R366" or "R367" or "R368" or "R369" or "R370" or "R371" or "R372" or "R373" or "R374" or "R375" or "R376" or "R377" or "R378" or "R379" or "R380" or "R381" or "R382" or "R383" or "R384" or "R385" or "R386" or "R387" or "R388" or "R389" or "R390" or "R221" or "R222" or "R243" or "R244" or "R245" or "R246" or "R247" or "R248" or "R249" or "R250" or "R251" or "R252" or "R253" or "R254" or "R255" or "R256" or "R257" ? "[REDACTED]" : path, "http"));
            if (!string.IsNullOrWhiteSpace(record.HttpMethod))
                items.Add(new DetectionEvidenceItem("http.method", record.HttpMethod!, "http"));
            if (record.DestinationPort.HasValue)
                items.Add(new DetectionEvidenceItem("network.destinationPort", record.DestinationPort.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), "network"));
            if (!string.IsNullOrWhiteSpace(record.ProcessName))
                items.Add(new DetectionEvidenceItem("process.name", record.ProcessName!, "process"));
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

            // Cloud provider request targets and vault/account host labels are
            // potentially sensitive. Do not retain them in event summaries.
            if (Descriptor.RuleId is "R381" or "R382" or "R383" or "R384" or "R385" or "R386" or "R387" or "R388" or "R389" or "R390")
                evt.DestinationHost = "[REDACTED]";

            var effectiveCooldownKey = string.IsNullOrWhiteSpace(cooldownKey) ? null : $"{Descriptor.RuleId}:{cooldownKey}";
            var cooldown = PrecisionProfile.Cooldown ?? TimeSpan.Zero;
            if (effectiveCooldownKey != null
                && cooldown > TimeSpan.Zero
                && IsSuppressedByCooldown(effectiveCooldownKey, context.TimestampUtc, cooldown, out var remaining))
            {
                SuppressForCooldown(evt, $"Rule-owned cooldown active for {remaining.TotalSeconds:F0}s.");
                EvidenceBuilder.AppendEvidence(evt, "suppression.remainingSeconds", Math.Ceiling(remaining.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule");
            }

            if (Descriptor.RuleId is "R243" or "R244" or "R245" or "R246" or "R247" or "R248" or "R249" or "R250" or "R251" or "R252" or "R253" or "R254" or "R255" or "R256" or "R257")
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
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
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

        protected static bool FirstTimeSeen(string value, DateTime now)
            => SeenValues.TryAdd(value, now);

        protected static bool FirstSeenWithinWindow(string value, DateTime now, TimeSpan window)
        {
            var firstSeen = SeenValues.GetOrAdd(value, now);
            return now - firstSeen <= window;
        }

        protected static long TransferBytes(TrafficRecord record)
            => Math.Max(record.Length, record.L4Len ?? 0);

        protected static bool IsUploadMethod(TrafficRecord record)
            => string.Equals(record.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase)
               || string.Equals(record.HttpMethod, "PUT", StringComparison.OrdinalIgnoreCase)
               || string.Equals(record.HttpMethod, "PATCH", StringComparison.OrdinalIgnoreCase);

        protected static bool HasUploadMetadata(TrafficRecord record)
        {
            var text = string.Join(" ", new[] { record.HttpUri, record.HttpRequestHeaders, record.Info }.Where(static value => !string.IsNullOrWhiteSpace(value))!);
            return ContainsAny(
                text,
                "upload",
                "multipart",
                "filename=",
                "content-disposition",
                "payload_json",
                "document=",
                "attachment",
                "attachments",
                "/upload",
                "/uploads",
                "/files",
                "/attachments");
        }

        protected static bool HasPasteUploadHint(TrafficRecord record)
        {
            var text = string.Join(" ", new[] { record.HttpUri, record.HttpRequestHeaders, record.Info }.Where(static value => !string.IsNullOrWhiteSpace(value))!);
            return HasUploadMetadata(record) || ContainsAny(text, "/documents", "/document", "/upload", "/file", "/api/upload", "/api/file", "/api/pastes", "/new");
        }

        protected static bool IsLikelyAutomationProcess(TrafficRecord record)
            => ContainsAny(record.ProcessName, AutomationProcessHints)
               || ContainsAny(UserAgent(record), "curl/", "wget/", "python-requests", "go-http-client", "powershell", "rclone", "winscp", "boto");

        protected static bool IsLikelyBrowserProcess(string? processName)
            => ContainsAny(processName, BrowserProcessHints);

        protected static bool IsLikelyCollaborationClientProcess(string? processName)
            => ContainsAny(processName, CollaborationClientProcessHints);

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

        protected static string ProviderIdentity(string? host)
        {
            var normalized = NormalizeHostToken(host);
            if (string.IsNullOrWhiteSpace(normalized))
                return string.Empty;

            if (LooksLikeAmazonS3Host(normalized))
                return "s3.amazonaws.com";

            if (HostMatchesAny(normalized, SlackHosts))
                return HostMatches(normalized, "hooks.slack.com") ? "hooks.slack.com" : "slack.com";

            if (HostMatchesAny(normalized, OfficialContainerRegistryHosts))
                return RootDomain(normalized);

            if (HostMatchesAny(normalized, OfficialPackageRegistryHosts))
                return RootDomain(normalized);

            if (HostMatchesAny(normalized, CloudStorageHosts))
                return RootDomain(normalized);

            return RootDomain(normalized);
        }

        protected static bool IsOfficialGitHost(string? host)
            => HostMatchesAny(host, OfficialGitHosts);

        protected static bool IsOfficialContainerRegistryHost(string? host)
            => HostMatchesAny(host, OfficialContainerRegistryHosts) || LooksLikeAwsEcrHost(host);

        protected static bool IsOfficialPackageRegistryHost(string? host)
            => HostMatchesAny(host, OfficialPackageRegistryHosts);

        protected static bool IsOfficialPowerShellGalleryHost(string? host)
            => HostMatchesAny(host, OfficialPowerShellGalleryHosts);

        protected static bool IsOfficialSlackHost(string? host)
            => HostMatchesAny(host, SlackHosts);

        protected static bool IsRawScriptHost(string? host)
            => HostMatchesAny(host, RawScriptHosts);

        protected static bool IsCloudStorageHost(string? host)
            => HostMatchesAny(host, CloudStorageHosts) || LooksLikeAmazonS3Host(host);

        protected static bool IsLikelyKubernetesComponentProcess(string? processName)
            => ContainsAny(processName, KubernetesComponentProcesses);

        protected static bool LooksLikePackageManagerClient(TrafficRecord record)
            => ContainsAny(record.ProcessName, PackageManagerProcessHints)
               || ContainsAny(UserAgent(record), "npm/", "pnpm/", "yarn/", "pip/", "poetry/", "nuget", "maven", "gradle", "gem/");

        protected static bool LooksLikeGitClient(TrafficRecord record)
            => ContainsAny(record.ProcessName, "git", "git-lfs")
               || ContainsAny(UserAgent(record), "git/", "git-lfs/")
               || ContainsAny(Text(record), "git clone", "git fetch", "git push", "git-upload-pack", "git-receive-pack");

        protected static bool IsAwsMetadataCredentialRequest(TrafficRecord record)
        {
            if (!HasHttpContext(record) || IsKnownMetadataProcess(record))
                return false;

            var host = BestHost(record);
            var path = HttpPath(record);
            var target = string.Equals(host, "169.254.169.254", StringComparison.OrdinalIgnoreCase)
                         || string.Equals(record.Destination, "169.254.169.254", StringComparison.OrdinalIgnoreCase)
                         || HostMatches(host, "instance-data.ec2.internal");
            return target
                   && HasMethod(record, "GET", "PUT")
                   && (path.StartsWith("/latest/meta-data/iam/security-credentials", StringComparison.OrdinalIgnoreCase)
                       || path.StartsWith("/latest/dynamic/instance-identity", StringComparison.OrdinalIgnoreCase));
        }

        protected static bool IsGcpMetadataCredentialRequest(TrafficRecord record)
        {
            if (!HasHttpContext(record) || IsKnownMetadataProcess(record))
                return false;

            var host = BestHost(record);
            var path = HttpPath(record);
            var target = string.Equals(host, "metadata.google.internal", StringComparison.OrdinalIgnoreCase)
                         || string.Equals(record.Destination, "169.254.169.254", StringComparison.OrdinalIgnoreCase);
            return target
                   && HasMethod(record, "GET")
                   && HeaderContains(record, "Metadata-Flavor", "Google")
                   && path.StartsWith("/computeMetadata/v1/instance/service-accounts/", StringComparison.OrdinalIgnoreCase)
                   && ContainsAny(path, "/token", "/identity");
        }

        protected static bool IsAzureMetadataCredentialRequest(TrafficRecord record)
        {
            if (!HasHttpContext(record) || IsKnownMetadataProcess(record))
                return false;

            var host = BestHost(record);
            var path = HttpPath(record);
            var target = string.Equals(host, "169.254.169.254", StringComparison.OrdinalIgnoreCase)
                         || string.Equals(record.Destination, "169.254.169.254", StringComparison.OrdinalIgnoreCase);
            return target
                   && HasMethod(record, "GET")
                   && path.StartsWith("/metadata/identity/oauth2/token", StringComparison.OrdinalIgnoreCase)
                   && HeaderContains(record, "Metadata", "true")
                   && TryGetQueryParameter(record, "api-version", out _);
        }

        protected static bool TryClassifyKubernetesTokenAccess(TrafficRecord record, out string classifier)
        {
            classifier = string.Empty;
            if (IsLikelyKubernetesComponentProcess(record.ProcessName))
                return false;

            var text = Text(record);
            var path = HttpPath(record);
            if (ContainsAny(text, "/var/run/secrets/kubernetes.io/serviceaccount/token"))
            {
                classifier = "mounted_serviceaccount_token_path";
                return true;
            }

            if (path.StartsWith("/api/v1/namespaces/", StringComparison.OrdinalIgnoreCase)
                && path.Contains("/serviceaccounts/", StringComparison.OrdinalIgnoreCase)
                && path.EndsWith("/token", StringComparison.OrdinalIgnoreCase))
            {
                classifier = "serviceaccount_tokenrequest_api";
                return true;
            }

            return false;
        }

        protected static bool TryClassifyDockerRegistryOperation(TrafficRecord record, out string operation, out string artifactKey)
        {
            operation = string.Empty;
            artifactKey = string.Empty;
            var path = HttpPath(record);
            var host = BestHost(record);
            var registryLike =
                path.StartsWith("/v2/", StringComparison.OrdinalIgnoreCase)
                || HeaderContains(record, "Docker-Distribution-Api-Version", "registry/2.0")
                || ContainsAny(record.Info, "docker-registry", "docker-content-digest", "application/vnd.docker");
            if (!registryLike || string.IsNullOrWhiteSpace(host) || !IsExternalAddress(host))
                return false;

            if ((HasMethod(record, "POST", "PATCH", "PUT") && ContainsAny(path, "/blobs/uploads", "/manifests/"))
                || ContainsAny(record.Info, "blobs/uploads"))
            {
                operation = "push";
                artifactKey = TryGetDigestToken(path, out var digest) ? digest : path;
                return true;
            }

            if ((HasMethod(record, "GET", "HEAD") && ContainsAny(path, "/blobs/", "/manifests/", "/tags/list"))
                || ContainsAny(record.Info, "docker-content-digest"))
            {
                operation = "pull";
                artifactKey = TryGetDigestToken(path, out var digest) ? digest : path;
                return true;
            }

            return false;
        }

        protected static bool IsTerraformStatePath(TrafficRecord record, out string statePath)
        {
            statePath = string.Empty;
            var path = HttpPath(record);
            var candidate = string.IsNullOrWhiteSpace(path) ? record.HttpUri ?? string.Empty : path;
            if (ContainsAny(candidate, "terraform.tfstate", ".tfstate", ".tfstate.backup"))
            {
                statePath = candidate;
                return true;
            }

            return false;
        }

        protected static bool TryGetCiCdSecretQueryParameter(TrafficRecord record, out string parameterName)
        {
            parameterName = string.Empty;
            foreach (var pair in QueryParameters(record))
            {
                var name = pair.Key.Trim();
                if (!ContainsAny(name, "gitlab-ci-token", "gitlab_token", "github_token", "ci_job_token", "job_token", "circle_token", "circle-token", "buildkite_token", "buildkite-agent-access-token"))
                    continue;

                if (pair.Value.Length < 12 && !ContainsAny(pair.Value, "ghp_", "ghs_", "glpat-", "glrt-"))
                    continue;

                parameterName = name;
                return true;
            }

            return false;
        }

        protected static bool IsGitCloneRequest(TrafficRecord record)
        {
            var path = HttpPath(record);
            return (path.EndsWith("/info/refs", StringComparison.OrdinalIgnoreCase) && TryGetQueryParameter(record, "service", out var service) && string.Equals(service, "git-upload-pack", StringComparison.OrdinalIgnoreCase))
                   || path.EndsWith("/git-upload-pack", StringComparison.OrdinalIgnoreCase)
                   || ContainsAny(record.Info, "git clone", "git fetch");
        }

        protected static bool IsGitPushRequest(TrafficRecord record)
        {
            var path = HttpPath(record);
            return (path.EndsWith("/info/refs", StringComparison.OrdinalIgnoreCase) && TryGetQueryParameter(record, "service", out var service) && string.Equals(service, "git-receive-pack", StringComparison.OrdinalIgnoreCase))
                   || path.EndsWith("/git-receive-pack", StringComparison.OrdinalIgnoreCase)
                   || ContainsAny(record.Info, "git push");
        }

        protected static bool TryClassifyPackageRegistryRequest(TrafficRecord record, out string ecosystem)
        {
            ecosystem = string.Empty;
            var path = HttpPath(record);
            var host = BestHost(record);
            if (string.IsNullOrWhiteSpace(host) || !IsExternalAddress(host) || !LooksLikePackageManagerClient(record))
                return false;

            if (ContainsAny(record.ProcessName, "npm", "pnpm", "yarn", "node") || ContainsAny(UserAgent(record), "npm/", "pnpm/", "yarn/"))
            {
                if (ContainsAny(path, "/@",
                        "/-/package/",
                        "/-/v1/search",
                        "/package/",
                        "/tarballs/",
                        "/download/"))
                {
                    ecosystem = "npm";
                    return true;
                }
            }

            if (ContainsAny(record.ProcessName, "pip", "python", "poetry") || ContainsAny(UserAgent(record), "pip/", "poetry/", "python-requests"))
            {
                if (ContainsAny(path, "/simple/", "/packages/", ".whl", ".tar.gz", ".zip"))
                {
                    ecosystem = "pypi";
                    return true;
                }
            }

            if (ContainsAny(record.ProcessName, "dotnet", "nuget") || ContainsAny(UserAgent(record), "nuget"))
            {
                if (ContainsAny(path, "/v3/index.json", "/query", "/flatcontainer/", ".nupkg"))
                {
                    ecosystem = "nuget";
                    return true;
                }
            }

            if (ContainsAny(record.ProcessName, "maven", "gradle", "java") || ContainsAny(UserAgent(record), "maven", "gradle"))
            {
                if (ContainsAny(path, "/maven2/", ".pom", ".jar"))
                {
                    ecosystem = "maven";
                    return true;
                }
            }

            if (ContainsAny(record.ProcessName, "gem", "bundle", "ruby") || ContainsAny(UserAgent(record), "rubygems"))
            {
                if (ContainsAny(path, "/gems/", ".gem"))
                {
                    ecosystem = "rubygems";
                    return true;
                }
            }

            return false;
        }

        protected static bool LooksLikeNpmInstallScriptBeacon(TrafficRecord record)
        {
            if (!ContainsAny(record.ProcessName, "npm", "pnpm", "yarn", "node") && !ContainsAny(UserAgent(record), "npm/", "pnpm/", "yarn/"))
                return false;

            if (!ContainsAny(Text(record), "postinstall", "preinstall", "prepare", "npm_config", "node -e", "node%20-e", "install script"))
                return false;

            var host = BestHost(record);
            return IsExternalAddress(host) && !IsOfficialPackageRegistryHost(host);
        }

        protected static bool LooksLikePypiArtifactRequest(TrafficRecord record)
        {
            if (!(ContainsAny(record.ProcessName, "pip", "python", "poetry") || ContainsAny(UserAgent(record), "pip/", "poetry/", "python-requests")))
                return false;

            var path = HttpPath(record);
            return ContainsAny(path, "/simple/", "/packages/", ".whl", ".tar.gz", ".zip");
        }

        protected static bool IsPowerShellScriptPull(TrafficRecord record)
        {
            if (!ContainsAny(record.ProcessName, "powershell", "pwsh"))
                return false;

            var host = BestHost(record);
            var path = HttpPath(record);
            if (string.IsNullOrWhiteSpace(host) || !IsExternalAddress(host) || IsOfficialPowerShellGalleryHost(host))
                return false;

            return HasMethod(record, "GET", "POST")
                   && (path.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)
                       || ContainsAny(Text(record), "downloadstring", "invoke-webrequest", "invoke-restmethod", "iex", "save-script", "install-script", "install-module"));
        }

        protected static bool IsCurlWgetScriptToShell(TrafficRecord record)
        {
            var text = Text(record);
            var path = HttpPath(record);
            var host = BestHost(record);
            var curlOrWget = ContainsAny(record.ProcessName, "curl", "wget")
                             || ContainsAny(UserAgent(record), "curl/", "wget/")
                             || ContainsAny(text, "curl ", "wget ");
            if (!curlOrWget || string.IsNullOrWhiteSpace(host) || !IsExternalAddress(host))
                return false;

            var pipeline = ContainsAny(text, "| sh", "| bash", "bash -c", "sh -c");
            var rawScript = IsRawScriptHost(host)
                            || path.EndsWith(".sh", StringComparison.OrdinalIgnoreCase)
                            || path.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)
                            || ContainsAny(path, "/raw/", "/-/raw/");
            return pipeline && rawScript;
        }

        protected static bool IsPasteOrDropHost(string? host)
            => HostMatchesAny(host, PasteOrDropHosts);

        protected static bool TryClassifyDiscordWebhookUpload(TrafficRecord record, out string classifier)
        {
            classifier = string.Empty;
            var host = BestHost(record);
            var path = HttpPath(record);
            if (!HasMethod(record, "POST") || string.IsNullOrWhiteSpace(host))
                return false;

            if (!(HostMatches(host, "discord.com") || HostMatches(host, "discordapp.com")))
                return false;

            if (path.StartsWith("/api/webhooks/", StringComparison.OrdinalIgnoreCase))
            {
                classifier = "discord-webhook";
                return true;
            }

            if (path.StartsWith("/api/v", StringComparison.OrdinalIgnoreCase)
                && ContainsAny(path, "/messages", "/attachments"))
            {
                classifier = "discord-channel-upload";
                return true;
            }

            return false;
        }

        protected static bool TryClassifyTelegramDocumentSend(TrafficRecord record, out string classifier)
        {
            classifier = string.Empty;
            var host = BestHost(record);
            var path = HttpPath(record);
            if (!HasMethod(record, "POST") || !HostMatches(host, "api.telegram.org"))
                return false;

            if (ContainsAny(path, "/bot") && path.Contains("/sendDocument", StringComparison.OrdinalIgnoreCase))
            {
                classifier = "telegram-senddocument";
                return true;
            }

            return false;
        }

        protected static bool TryClassifyRemoteDesktopSaas(TrafficRecord record, out string vendor, out string signal)
        {
            vendor = string.Empty;
            signal = string.Empty;
            var host = NormalizeHostToken(BestHost(record)) ?? string.Empty;
            if ((!IsExternalAddress(host) && !IsExternalAddress(record.Destination)) || string.IsNullOrWhiteSpace(host))
                return false;

            var processVendor = MatchHint(record.ProcessName, RemoteDesktopVendorHints);
            var hostVendor = MatchHint(host, RemoteDesktopVendorHints);
            var textVendor = MatchHint(string.Join(" ", new[] { record.Info, record.ApplicationService, record.ApplicationProtocol, record.Sni }.Where(static value => !string.IsNullOrWhiteSpace(value))), RemoteDesktopVendorHints);
            if (string.IsNullOrWhiteSpace(processVendor) && string.IsNullOrWhiteSpace(hostVendor) && string.IsNullOrWhiteSpace(textVendor))
                return false;

            if (IsLikelyBrowserProcess(record.ProcessName) && string.IsNullOrWhiteSpace(processVendor) && string.IsNullOrWhiteSpace(textVendor))
                return false;

            var signals = new List<string>();
            if (!string.IsNullOrWhiteSpace(processVendor)) signals.Add("process");
            if (!string.IsNullOrWhiteSpace(hostVendor)) signals.Add("host");
            if (!string.IsNullOrWhiteSpace(textVendor)) signals.Add("service");
            if (signals.Count == 0 || (signals.Count == 1 && string.IsNullOrWhiteSpace(processVendor)))
                return false;

            vendor = SelectFirstNonEmpty(processVendor, hostVendor, textVendor);
            signal = string.Join("+", signals);
            return true;
        }

        protected static bool TryClassifyOverlayNetworkEgress(TrafficRecord record, out string vendor, out string signal)
        {
            vendor = string.Empty;
            signal = string.Empty;
            var host = NormalizeHostToken(BestHost(record)) ?? string.Empty;
            if (!IsExternalAddress(host) && !IsExternalAddress(record.Destination))
                return false;

            var processVendor = MatchHint(record.ProcessName, OverlayVendorHints);
            var hostVendor = MatchHint(string.Join(" ", new[] { host, record.Sni, record.WhoisOrganization, record.Info }.Where(static value => !string.IsNullOrWhiteSpace(value))), OverlayVendorHints);
            var portHint = record.DestinationPort.HasValue && OverlayNetworkPorts.Contains(record.DestinationPort.Value);
            if (IsLikelyBrowserProcess(record.ProcessName) && string.IsNullOrWhiteSpace(processVendor) && !portHint)
                return false;

            if (string.IsNullOrWhiteSpace(processVendor) && string.IsNullOrWhiteSpace(hostVendor) && !portHint)
                return false;

            if (string.IsNullOrWhiteSpace(processVendor) && string.IsNullOrWhiteSpace(hostVendor))
                return false;

            var signals = new List<string>();
            if (!string.IsNullOrWhiteSpace(processVendor)) signals.Add("process");
            if (!string.IsNullOrWhiteSpace(hostVendor)) signals.Add("host");
            if (portHint) signals.Add("port");
            if (signals.Count == 1 && string.IsNullOrWhiteSpace(processVendor) && !portHint)
                return false;

            vendor = SelectFirstNonEmpty(processVendor, hostVendor, portHint ? "overlay-port" : string.Empty);
            signal = string.Join("+", signals);
            return true;
        }

        protected static bool TryGetPresignedUrlProvider(TrafficRecord record, out string provider, out string signatureMarker)
        {
            provider = string.Empty;
            signatureMarker = string.Empty;
            var host = BestHost(record);
            if (!IsCloudStorageHost(host))
                return false;

            if (TryGetQueryParameter(record, "X-Amz-Signature", out var awsSig)
                || TryGetQueryParameter(record, "X-Amz-Algorithm", out awsSig)
                || TryGetQueryParameter(record, "X-Amz-Credential", out awsSig))
            {
                provider = "aws-presigned";
                signatureMarker = awsSig;
                return true;
            }

            if (TryGetQueryParameter(record, "X-Goog-Signature", out var gcsSig)
                || TryGetQueryParameter(record, "X-Goog-Algorithm", out gcsSig))
            {
                provider = "gcs-signed";
                signatureMarker = gcsSig;
                return true;
            }

            if (TryGetQueryParameter(record, "sig", out var azureSig)
                && TryGetQueryParameter(record, "se", out _)
                && TryGetQueryParameter(record, "sp", out _))
            {
                provider = "azure-sas";
                signatureMarker = azureSig;
                return true;
            }

            return false;
        }

        protected static bool IsS3BucketListingRequest(TrafficRecord record)
        {
            var host = BestHost(record);
            if (!LooksLikeAmazonS3Host(host) || !HasMethod(record, "GET"))
                return false;

            var path = HttpPath(record);
            return TryGetQueryParameter(record, "list-type", out var listType) && string.Equals(listType, "2", StringComparison.OrdinalIgnoreCase)
                   || (!string.IsNullOrWhiteSpace(path) && (TryGetQueryParameter(record, "prefix", out _) || TryGetQueryParameter(record, "delimiter", out _)));
        }

        protected static bool IsAzureBlobEnumerationRequest(TrafficRecord record)
        {
            var host = BestHost(record);
            return HostMatches(host, "blob.core.windows.net")
                   && HasMethod(record, "GET")
                   && TryGetQueryParameter(record, "comp", out var comp) && string.Equals(comp, "list", StringComparison.OrdinalIgnoreCase)
                   && TryGetQueryParameter(record, "restype", out var restType) && string.Equals(restType, "container", StringComparison.OrdinalIgnoreCase);
        }

        protected static bool IsGoogleStorageEnumerationRequest(TrafficRecord record)
        {
            var host = BestHost(record);
            var path = HttpPath(record);
            if (!HasMethod(record, "GET"))
                return false;

            if ((string.Equals(host, "storage.googleapis.com", StringComparison.OrdinalIgnoreCase) || string.Equals(host, "storage.cloud.google.com", StringComparison.OrdinalIgnoreCase))
                && (TryGetQueryParameter(record, "prefix", out _) || TryGetQueryParameter(record, "delimiter", out _)))
            {
                return true;
            }

            var jsonApiList = path.StartsWith("/storage/v1/b/", StringComparison.OrdinalIgnoreCase)
                              && path.Contains("/o", StringComparison.OrdinalIgnoreCase);
            if (!jsonApiList)
                return false;

            return !TryGetQueryParameter(record, "alt", out var alt)
                   || !string.Equals(alt, "media", StringComparison.OrdinalIgnoreCase);
        }

        protected static bool TryClassifySlackRequest(TrafficRecord record, out string classifier)
        {
            classifier = string.Empty;
            var host = BestHost(record);
            var path = HttpPath(record);
            if (!HasMethod(record, "POST") || string.IsNullOrWhiteSpace(host) || !IsOfficialSlackHost(host))
                return false;

            if (HostMatches(host, "hooks.slack.com") && path.StartsWith("/services/", StringComparison.OrdinalIgnoreCase))
            {
                classifier = "slack-webhook";
                return true;
            }

            if (HostMatches(host, "slack.com") && ContainsAny(path, "/api/files.upload", "/api/chat.postmessage", "/api/files.completeuploadexternal"))
            {
                classifier = "slack-api";
                return true;
            }

            return false;
        }

        protected static bool HasSlackExfilHint(TrafficRecord record)
            => ContainsAny(Text(record), "files.upload", "chat.postmessage", "completeuploadexternal", "payload=", "text=", "attachments", "filename=", "multipart/form-data");

        protected static string RootDomain(string? host)
        {
            var normalized = NormalizeHostToken(host) ?? string.Empty;
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

        protected static bool HostMatches(string? host, string suffix)
        {
            var normalizedHost = NormalizeHostToken(host) ?? string.Empty;
            var normalizedSuffix = NormalizeHostToken(suffix) ?? string.Empty;
            if (string.IsNullOrWhiteSpace(normalizedHost) || string.IsNullOrWhiteSpace(normalizedSuffix))
                return false;

            return string.Equals(normalizedHost, normalizedSuffix, StringComparison.OrdinalIgnoreCase)
                   || normalizedHost.EndsWith("." + normalizedSuffix, StringComparison.OrdinalIgnoreCase);
        }

        protected static bool HostMatchesAny(string? host, IEnumerable<string> suffixes)
        {
            foreach (var suffix in suffixes)
            {
                if (HostMatches(host, suffix))
                    return true;
            }

            return false;
        }

        protected static string? NormalizeHostToken(string? host)
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

        protected static bool TryGetDigestToken(string path, out string digest)
        {
            digest = string.Empty;
            if (string.IsNullOrWhiteSpace(path))
                return false;

            var marker = "sha256:";
            var start = path.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
                return false;

            start += marker.Length;
            var remainder = path[start..];
            var token = remainder.Split(new[] { '/', '?', '&' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
            if (token.Length < 16)
                return false;

            digest = "sha256:" + token;
            return true;
        }

        private static bool LooksLikeAmazonS3Host(string? host)
        {
            var normalized = NormalizeHostToken(host) ?? string.Empty;
            return normalized.EndsWith(".amazonaws.com", StringComparison.OrdinalIgnoreCase)
                   && (normalized.StartsWith("s3.", StringComparison.OrdinalIgnoreCase)
                       || normalized.Contains(".s3.", StringComparison.OrdinalIgnoreCase)
                       || normalized.Equals("s3.amazonaws.com", StringComparison.OrdinalIgnoreCase));
        }

        private static bool LooksLikeAwsEcrHost(string? host)
        {
            var normalized = NormalizeHostToken(host) ?? string.Empty;
            return normalized.EndsWith(".amazonaws.com", StringComparison.OrdinalIgnoreCase)
                   && normalized.Contains(".dkr.ecr.", StringComparison.OrdinalIgnoreCase);
        }

        private static string MatchHint(string? value, IEnumerable<string> hints)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            foreach (var hint in hints)
            {
                if (value.Contains(hint, StringComparison.OrdinalIgnoreCase))
                    return hint;
            }

            return string.Empty;
        }

        private static string SelectFirstNonEmpty(params string[] values)
            => values.FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;


        public new static void ResetSharedStateForReplay()
        {
            ByteWindows.Clear();
            CooldownWindows.Clear();
            SeenValues.Clear();
        }

        private static bool IsSuppressedByCooldown(string key, DateTime now, TimeSpan cooldown, out TimeSpan remaining)
        {
            remaining = TimeSpan.Zero;
            var last = CooldownWindows.GetOrAdd(key, now);
            if (last != now)
            {
                var delta = now - last;
                if (delta < cooldown)
                {
                    remaining = cooldown - delta;
                    return true;
                }
            }

            CooldownWindows[key] = now;
            return false;
        }
    }
}
