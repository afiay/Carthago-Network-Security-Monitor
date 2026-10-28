// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/HttpApiPrecisionDetectionRuleBase.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class HttpApiPrecisionDetectionRuleBase : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly ConcurrentDictionary<string, DateTime> CooldownWindows = new(StringComparer.OrdinalIgnoreCase);

        private static readonly string[] ScannerUserAgents =
        {
            "sqlmap", "nikto", "nuclei", "gobuster", "dirbuster", "ffuf", "zgrab", "masscan", "nmap", "wpscan", "feroxbuster"
        };

        private static readonly string[] BrowserUserAgents =
        {
            "mozilla/", "chrome/", "safari/", "firefox/", "edg/", "opr/", "applewebkit"
        };

        private static readonly string[] SwaggerHosts =
        {
            "swagger.io", "editor.swagger.io", "petstore.swagger.io", "openapis.org", "redoc.ly", "readme.com"
        };

        private static readonly string[] SwaggerPaths =
        {
            "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui/", "/swagger-ui.html",
            "/swagger.json", "/openapi.json", "/v3/api-docs", "/v2/api-docs", "/api-docs"
        };

        private static readonly string[] ActuatorSensitiveSegments =
        {
            "/actuator/env", "/actuator/heapdump", "/actuator/jolokia", "/actuator/metrics", "/actuator/prometheus",
            "/actuator/threaddump", "/actuator/loggers", "/actuator/beans", "/actuator/mappings", "/actuator/configprops",
            "/actuator/scheduledtasks"
        };

        private static readonly string[] ActuatorBenignSegments =
        {
            "/actuator/health", "/actuator/info"
        };

        private static readonly string[] KubernetesPaths =
        {
            "/api/v1/namespaces", "/api/v1/secrets", "/api/v1/serviceaccounts", "/apis/apps", "/apis/rbac.authorization.k8s.io"
        };

        private static readonly string[] DockerPaths =
        {
            "/containers/json", "/containers/create", "/images/json", "/images/create", "/version", "/volumes",
            "/networks", "/swarm", "/plugins"
        };

        private static readonly string[] MetadataHosts =
        {
            "169.254.169.254", "169.254.170.2", "100.100.100.200", "metadata.google.internal"
        };

        private static readonly string[] MetadataPaths =
        {
            "/latest/meta-data", "/iam/security-credentials", "/metadata/identity/oauth2/token",
            "/computeMetadata/v1", "/latest/user-data", "/latest/dynamic/instance-identity"
        };

        private static readonly string[] KnownMetadataProcesses =
        {
            "waagent", "amazon-ssm-agent", "google-guest-agent", "cloud-init", "imds", "metadata", "kubelet"
        };

        private static readonly string[] RedirectParameterNames =
        {
            "redirect", "return", "returnurl", "return_url", "next", "url", "continue", "dest", "destination", "redirect_uri"
        };

        private static readonly string[] AdminLoginPaths =
        {
            "/admin/login", "/wp-login.php", "/administrator", "/user/login", "/manager/html", "/signin", "/session", "/authenticate"
        };

        private static readonly string[] SensitiveEnvironmentPaths =
        {
            "/.env", "/.env.local", "/.env.production", "/.env.prod", "/.env.development",
            "/.aws/credentials", "/appsettings.json", "/appsettings.production.json", "/config/secrets.yml", "/database.yml"
        };

        private static readonly string[] GitExposurePaths =
        {
            "/.git/config", "/.git/head", "/.git/index", "/.git/packed-refs", "/.git/refs", "/.git/objects/info/packs"
        };

        private static readonly string[] HighRiskUploadExtensions =
        {
            ".jsp", ".jspx", ".php", ".phtml", ".phar", ".asp", ".aspx", ".ashx", ".cfm", ".war", ".jar"
        };

        private static readonly string[] UploadPathHints =
        {
            "/upload", "/uploads", "/file", "/files", "/import", "/attachments", "/media", "/avatar", "/admin/upload"
        };

        private static readonly Regex JwtCandidateRegex = new(
            @"(?<token>eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9._-]{4,}\.[A-Za-z0-9._-]{2,})",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex JwtAlgNoneRegex = new(
            @"""alg""\s*:\s*""none""",
            RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

        private static readonly Regex FilenameRegex = new(
            @"(?i)\bfilename\*?=(?:UTF-8''|""?)(?<name>[^"";\r\n]+)",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        protected HttpApiPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }

        protected RuleEvaluationResult MatchHttpApi(
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
            // R153-R155 may carry tokens or personal identifiers in resource
            // paths; do not emit them through the shared event builder.
            var path = Descriptor.RuleId is "R153" or "R154" or "R155" or "R156" or "R157" or "R158" or "R159" or "R160" or "R161" or "R162" or "R163" or "R164" or "R165" or "R166" or "R167" or "R168" or "R169" or "R170" or "R171" or "R172" or "R173" or "R174" or "R175" or "R176" or "R177" or "R194" or "R198" or "R199" or "R200" or "R201" or "R202" or "R203" or "R204" or "R205" or "R206" or "R207" or "R208" or "R209" or "R210" or "R211" or "R212" or "R213" or "R214" or "R215" or "R216" or "R217" or "R218" or "R219" or "R220"
                ? "[REDACTED]" : HttpPath(record);
            var items = new List<DetectionEvidenceItem>
            {
                new("httpapi.family", detectionFamily, "http-api"),
                new("httpapi.host", Descriptor.RuleId is "R194" or "R201" or "R202" or "R203" or "R204" or "R205" or "R206" or "R207" or "R208" or "R209" or "R210" or "R211" or "R212" or "R213" or "R214" or "R215" or "R216" or "R217" or "R218" or "R219" or "R220" ? "[REDACTED]" : string.IsNullOrWhiteSpace(host) ? record.Destination ?? "unknown" : host, "http-api")
            };

            if (!string.IsNullOrWhiteSpace(path))
                items.Add(new DetectionEvidenceItem("http.path", path, "http"));
            if (!string.IsNullOrWhiteSpace(record.HttpMethod))
                items.Add(new DetectionEvidenceItem("http.method", record.HttpMethod!, "http"));
            if (record.DestinationPort.HasValue)
                items.Add(new DetectionEvidenceItem("network.destinationPort", record.DestinationPort.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), "network"));
            if (!string.IsNullOrWhiteSpace(record.ProcessName))
                items.Add(new DetectionEvidenceItem("process.name", record.ProcessName!, "process"));

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

        protected static RulePrecisionProfile CreateHttpApiProfile(
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
                new HashSet<string>(new[] { "process.name", "http.user_agent", "geo.country" }, StringComparer.OrdinalIgnoreCase),
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

        protected static bool HasMethod(TrafficRecord record, params string[] methods)
            => !string.IsNullOrWhiteSpace(record.HttpMethod)
               && methods.Any(method => string.Equals(record.HttpMethod, method, StringComparison.OrdinalIgnoreCase));

        protected static bool HasHeader(TrafficRecord record, string headerName)
            => GetHeaderValues(record, headerName).Count > 0;

        protected static bool TryGetHeaderValue(TrafficRecord record, string headerName, out string value)
        {
            var values = GetHeaderValues(record, headerName);
            value = values.FirstOrDefault() ?? string.Empty;
            return !string.IsNullOrWhiteSpace(value);
        }

        protected static IReadOnlyList<string> GetHeaderValues(TrafficRecord record, string headerName)
        {
            var values = new List<string>();
            if (string.IsNullOrWhiteSpace(headerName) || string.IsNullOrWhiteSpace(record.HttpRequestHeaders))
                return values;

            foreach (var line in record.HttpRequestHeaders.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                var separator = line.IndexOf(':');
                if (separator <= 0)
                    continue;

                var name = line[..separator].Trim();
                if (!string.Equals(name, headerName, StringComparison.OrdinalIgnoreCase))
                    continue;

                values.Add(line[(separator + 1)..].Trim());
            }

            return values;
        }

        protected static bool HeaderContains(TrafficRecord record, string headerName, params string[] needles)
            => GetHeaderValues(record, headerName).Any(value => ContainsAny(value, needles));

        protected static string UserAgent(TrafficRecord record)
        {
            if (!string.IsNullOrWhiteSpace(record.HttpUserAgent))
                return record.HttpUserAgent!;

            return TryGetHeaderValue(record, "User-Agent", out var headerValue) ? headerValue : string.Empty;
        }

        protected static IEnumerable<KeyValuePair<string, string>> QueryParameters(TrafficRecord record)
        {
            var uri = ParseHttpUri(record.HttpUri);
            if (uri == null)
                yield break;

            var query = uri.Query.TrimStart('?');
            if (string.IsNullOrWhiteSpace(query))
                yield break;

            foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = pair.Split('=', 2);
                var name = Uri.UnescapeDataString(parts[0]).Trim();
                var value = parts.Length > 1 ? Uri.UnescapeDataString(parts[1]).Trim() : string.Empty;
                if (!string.IsNullOrWhiteSpace(name))
                    yield return new KeyValuePair<string, string>(name, value);
            }
        }

        protected static bool TryGetQueryParameter(TrafficRecord record, string parameterName, out string value)
        {
            foreach (var pair in QueryParameters(record))
            {
                if (string.Equals(pair.Key, parameterName, StringComparison.OrdinalIgnoreCase))
                {
                    value = pair.Value;
                    return true;
                }
            }

            value = string.Empty;
            return false;
        }

        protected static bool IsGraphqlPath(TrafficRecord record)
        {
            var path = HttpPath(record);
            return ContainsAny(path, "graphql")
                   || (ContainsAny(path, "/api") && ContainsAny(Text(record), "graphql"));
        }

        protected static bool HasGraphqlIntrospectionIndicator(TrafficRecord record)
            => ContainsAny(record.HttpUri, "__schema", "__type", "IntrospectionQuery", "%5F%5Fschema", "%5f%5fschema", "%5F%5Ftype", "%5f%5ftype")
               || ContainsAny(record.HttpRequestHeaders, "__schema", "__type", "IntrospectionQuery")
               || ContainsAny(record.Info, "__schema", "__type", "IntrospectionQuery");

        protected static bool HasGraphqlBatchingIndicator(TrafficRecord record)
            => ContainsAny(record.HttpUri, "batch=", "batched=", "operationName=", "extensions=")
               || ContainsAny(record.Info, "[{\"query", "[{\"operationName", "graphql batch", "batched request", "operationName")
               || HeaderContains(record, "X-Graphql-Batch", "1", "true");

        protected static bool IsLikelyApiPath(TrafficRecord record)
        {
            var path = HttpPath(record);
            return ContainsAny(path, "/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql", "/admin/api")
                   || PathContainsAny(record, "/users", "/accounts", "/projects", "/repos", "/objects", "/members", "/tokens");
        }

        protected static string ApiProbeKey(TrafficRecord record)
        {
            var uri = ParseHttpUri(record.HttpUri);
            if (uri == null)
                return HttpPath(record).ToLowerInvariant();

            var keys = QueryParameters(record)
                .Select(pair => pair.Key.Trim().ToLowerInvariant())
                .Where(static key => !string.IsNullOrWhiteSpace(key))
                .OrderBy(static key => key, StringComparer.OrdinalIgnoreCase);

            return $"{uri.AbsolutePath.ToLowerInvariant()}?{string.Join("&", keys)}";
        }

        protected static bool LooksLikeJwt(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            var trimmed = value.Trim();
            return trimmed.Count(character => character == '.') == 2
                   && trimmed.StartsWith("eyJ", StringComparison.Ordinal)
                   && trimmed.Length >= 24;
        }

        protected static bool TryFindJwtWithNoneAlgorithm(TrafficRecord record, out string source)
        {
            foreach (var candidate in EnumerateJwtCandidates(record))
            {
                if (TryDecodeJwtHeader(candidate.Token, out var header) && JwtAlgNoneRegex.IsMatch(header))
                {
                    source = candidate.Source;
                    return true;
                }
            }

            source = string.Empty;
            return false;
        }

        protected static bool TryGetJwtQueryParameter(TrafficRecord record, out string parameterName)
        {
            foreach (var pair in QueryParameters(record))
            {
                if (pair.Key.IndexOf("token", StringComparison.OrdinalIgnoreCase) < 0
                    && pair.Key.IndexOf("jwt", StringComparison.OrdinalIgnoreCase) < 0
                    && pair.Key.IndexOf("assertion", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    continue;
                }

                if (LooksLikeJwt(pair.Value))
                {
                    parameterName = pair.Key;
                    return true;
                }
            }

            parameterName = string.Empty;
            return false;
        }

        protected static bool IsSwaggerExposurePath(TrafficRecord record)
        {
            var path = HttpPath(record);
            return SwaggerPaths.Any(candidate => path.Equals(candidate, StringComparison.OrdinalIgnoreCase) || path.StartsWith(candidate + "/", StringComparison.OrdinalIgnoreCase));
        }

        protected static bool IsBenignSwaggerHost(TrafficRecord record)
            => SwaggerHosts.Any(host => BestHost(record).EndsWith(host, StringComparison.OrdinalIgnoreCase));

        protected static bool IsSensitiveActuatorPath(TrafficRecord record)
        {
            var path = HttpPath(record);
            if (!path.StartsWith("/actuator", StringComparison.OrdinalIgnoreCase))
                return false;

            if (ActuatorBenignSegments.Any(segment => path.Equals(segment, StringComparison.OrdinalIgnoreCase)))
                return false;

            return ActuatorSensitiveSegments.Any(segment => path.StartsWith(segment, StringComparison.OrdinalIgnoreCase));
        }

        protected static bool IsKubernetesApiProbe(TrafficRecord record)
        {
            var path = HttpPath(record);
            var host = BestHost(record);
            var port = record.DestinationPort ?? -1;
            var pathMatch = KubernetesPaths.Any(candidate => path.StartsWith(candidate, StringComparison.OrdinalIgnoreCase));
            var environmentMatch = port is 6443 or 8443 or 443 || ContainsAny(host, "kubernetes", "k8s", "cluster.local");
            return pathMatch && environmentMatch;
        }

        protected static bool IsDockerApiProbe(TrafficRecord record)
        {
            var path = HttpPath(record);
            var host = BestHost(record);
            var port = record.DestinationPort ?? -1;
            var pathMatch = DockerPaths.Any(candidate => path.StartsWith(candidate, StringComparison.OrdinalIgnoreCase));
            return pathMatch && (port is 2375 or 2376 || ContainsAny(host, "docker"));
        }

        protected static bool IsRedisMemcachedProbe(TrafficRecord record)
        {
            var path = HttpPath(record);
            var port = record.DestinationPort ?? -1;
            var targetMatch = port is 6379 or 11211 || ContainsAny(Text(record), "redis", "memcached");
            var commandMatch = ContainsAny(path, "/stats", "/slabs", "/items", "/flush_all", "/redis", "/memcached")
                               || ContainsAny(record.Info, "stats", "flush_all", "stats items", "redis", "memcached");
            return targetMatch && commandMatch;
        }

        protected static bool IsMetadataServiceProbe(TrafficRecord record)
        {
            var host = BestHost(record);
            var destination = record.Destination ?? string.Empty;
            var path = HttpPath(record);
            var targetMatch = MetadataHosts.Contains(host, StringComparer.OrdinalIgnoreCase)
                              || MetadataHosts.Contains(destination, StringComparer.OrdinalIgnoreCase);
            if (!targetMatch)
                return false;

            return MetadataPaths.Any(candidate => path.StartsWith(candidate, StringComparison.OrdinalIgnoreCase))
                   || HeaderContains(record, "Metadata", "true")
                   || HeaderContains(record, "Metadata-Flavor", "Google");
        }

        protected static bool IsKnownMetadataProcess(TrafficRecord record)
            => ContainsAny(record.ProcessName, KnownMetadataProcesses);

        protected static bool TryGetSuspiciousRedirectTarget(TrafficRecord record, out string parameterName, out string target)
        {
            parameterName = string.Empty;
            target = string.Empty;
            var requestHost = BestHost(record);

            foreach (var pair in QueryParameters(record))
            {
                if (!RedirectParameterNames.Contains(pair.Key, StringComparer.OrdinalIgnoreCase))
                    continue;

                if (!TryNormalizeRedirectTarget(pair.Value, out var normalizedTarget))
                    continue;

                if (string.Equals(pair.Key, "redirect_uri", StringComparison.OrdinalIgnoreCase))
                {
                    if (IsAuthenticationCallbackPath(record))
                        continue;

                    if (!IsPlainHttpUrl(normalizedTarget) && !TargetsInternalHost(normalizedTarget))
                        continue;
                }
                else if (!TargetsInternalHost(normalizedTarget) && SameRootHost(requestHost, normalizedTarget))
                {
                    continue;
                }

                parameterName = pair.Key;
                target = normalizedTarget;
                return true;
            }

            return false;
        }

        protected static bool IsPhpInfoProbe(TrafficRecord record)
        {
            var path = HttpPath(record);
            return path.Equals("/phpinfo.php", StringComparison.OrdinalIgnoreCase)
                   || path.Equals("/phpinfo", StringComparison.OrdinalIgnoreCase)
                   || ContainsAny(record.HttpUri, "phpinfo=1", "?phpinfo");
        }

        protected static bool IsEnvironmentFileProbe(TrafficRecord record)
        {
            var path = HttpPath(record);
            if (path.StartsWith("/.env", StringComparison.OrdinalIgnoreCase))
                return true;

            return SensitiveEnvironmentPaths.Any(candidate => path.Equals(candidate, StringComparison.OrdinalIgnoreCase));
        }

        protected static bool IsGitExposurePath(TrafficRecord record)
        {
            var path = HttpPath(record).ToLowerInvariant();
            return GitExposurePaths.Any(candidate => path.StartsWith(candidate, StringComparison.OrdinalIgnoreCase));
        }

        protected static bool IsSuspiciousBackupArchivePath(TrafficRecord record)
        {
            var path = HttpPath(record).ToLowerInvariant();
            var fileName = path.Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(fileName))
                return false;

            var extensionMatch =
                fileName.EndsWith(".bak", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".backup", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".old", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".sql", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".sql.gz", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".7z", StringComparison.OrdinalIgnoreCase);

            if (!extensionMatch)
                return false;

            return ContainsAny(fileName, "backup", "dump", "db", "database", "site", "www", "config");
        }

        protected static bool IsAdminLoginPath(TrafficRecord record)
        {
            var path = HttpPath(record);
            return AdminLoginPaths.Any(candidate => path.StartsWith(candidate, StringComparison.OrdinalIgnoreCase))
                   || (HasAdminPortalPath(record) && ContainsAny(path, "login", "signin", "session", "authenticate"));
        }

        protected static bool HasXmlContentType(TrafficRecord record)
            => HeaderContains(record, "Content-Type", "application/xml", "text/xml", "application/soap+xml");

        protected static bool HasXxeIndicator(TrafficRecord record)
            => ContainsAny(record.HttpUri, "<!DOCTYPE", "<!ENTITY", "%3C!DOCTYPE", "%3C!ENTITY", "/etc/passwd", "win.ini", "php://filter", "expect://")
               || ContainsAny(record.HttpRequestHeaders, "<!DOCTYPE", "<!ENTITY", "SYSTEM \"file://", "SYSTEM 'file://", "/etc/passwd", "win.ini", "php://filter", "expect://")
               || ContainsAny(record.Info, "<!DOCTYPE", "<!ENTITY", "SYSTEM \"file://", "SYSTEM 'file://", "/etc/passwd", "win.ini", "php://filter", "expect://", "%xxe;");

        protected static bool HasSoapContext(TrafficRecord record)
        {
            var path = HttpPath(record);
            return HasHeader(record, "SOAPAction")
                   || HasXmlContentType(record)
                   || path.EndsWith(".asmx", StringComparison.OrdinalIgnoreCase)
                   || path.EndsWith(".svc", StringComparison.OrdinalIgnoreCase)
                   || path.Contains("/services", StringComparison.OrdinalIgnoreCase);
        }

        protected static bool TryGetSuspiciousSoapAction(TrafficRecord record, out string action)
        {
            action = string.Empty;
            if (!TryGetHeaderValue(record, "SOAPAction", out var headerValue))
                return false;

            if (!ContainsAny(headerValue, "execute", "run", "command", "shell", "upload", "download", "runtime", "process", "invoke", "jndi"))
                return false;

            action = headerValue;
            return true;
        }

        protected static bool HasScannerUserAgentWithBrowserClaimMismatch(TrafficRecord record)
        {
            var userAgent = UserAgent(record);
            return ContainsAny(userAgent, ScannerUserAgents) && ContainsAny(userAgent, BrowserUserAgents);
        }

        protected static bool IsBrowserLikeUserAgent(TrafficRecord record)
            => ContainsAny(UserAgent(record), BrowserUserAgents);

        protected static bool IsScannerUserAgent(TrafficRecord record)
            => ContainsAny(UserAgent(record), ScannerUserAgents);

        protected static bool IsAdminApiPreflight(TrafficRecord record)
        {
            if (!HasMethod(record, "OPTIONS") || !HasHeader(record, "Access-Control-Request-Method"))
                return false;

            var path = HttpPath(record);
            var adminApi = ContainsAny(path, "/admin", "/wp-admin", "/manager", "/api/admin", "/admin/api", "/management")
                           || (ContainsAny(path, "/api/") && ContainsAny(path, "admin", "manage", "config"));
            if (!adminApi)
                return false;

            if (HeaderContains(record, "Access-Control-Request-Headers", "authorization", "cookie", "x-api-key", "x-amz-security-token"))
                return true;

            if (!TryGetHeaderValue(record, "Origin", out var origin))
                return false;

            return !SameRootHost(BestHost(record), origin);
        }

        protected static bool IsSuspiciousWebDavMethod(TrafficRecord record)
        {
            if (!HasMethod(record, "PROPFIND", "PROPPATCH", "MKCOL", "LOCK", "UNLOCK", "MOVE", "COPY", "SEARCH"))
                return false;

            var path = HttpPath(record);
            if (path.StartsWith("/.well-known/caldav", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/.well-known/carddav", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.Equals(record.HttpMethod, "PROPFIND", StringComparison.OrdinalIgnoreCase))
                return true;

            return HeaderContains(record, "Depth", "infinity")
                   || ContainsAny(path, "/webdav", "/dav", "/remote.php/dav", "/admin", "/share")
                   || HasAuthFailureContext(record);
        }

        protected static bool HasRequestSmugglingIndicators(TrafficRecord record, out string mode)
        {
            mode = string.Empty;
            var contentLengths = GetHeaderValues(record, "Content-Length");
            var transferEncodings = GetHeaderValues(record, "Transfer-Encoding");
            if (contentLengths.Count > 1 && contentLengths.Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1)
            {
                mode = "multiple-content-length";
                return true;
            }

            if (contentLengths.Count > 0 && transferEncodings.Any(value => value.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0))
            {
                mode = "cl-plus-te";
                return true;
            }

            if (ContainsAny(record.HttpRequestHeaders, "cl.te", "te.cl"))
            {
                mode = "cl-te-annotation";
                return true;
            }

            return false;
        }

        protected static bool TryGetHostHeaderInjectionDetail(TrafficRecord record, out string detail)
        {
            detail = string.Empty;
            var requestHost = BestHost(record);

            if (TryGetHeaderValue(record, "Host", out var hostHeader) && TargetsInternalHost(hostHeader))
            {
                detail = "internal-host-header";
                return true;
            }

            if (TryGetHeaderValue(record, "X-Forwarded-Host", out var forwardedHost)
                && (TargetsInternalHost(forwardedHost) || !SameRootHost(requestHost, forwardedHost)))
            {
                detail = "forwarded-host-mismatch";
                return true;
            }

            if ((TryGetHeaderValue(record, "X-Original-URL", out var originalUrl) && TargetsSensitiveRewriteTarget(originalUrl))
                || (TryGetHeaderValue(record, "X-Rewrite-URL", out var rewriteUrl) && TargetsSensitiveRewriteTarget(rewriteUrl)))
            {
                detail = "rewrite-target-abuse";
                return true;
            }

            return false;
        }

        protected static bool TryGetHighRiskUploadName(TrafficRecord record, out string fileName)
        {
            fileName = string.Empty;
            if (!HasMethod(record, "POST", "PUT", "PATCH"))
                return false;

            var uploadContext = HeaderContains(record, "Content-Type", "multipart/form-data")
                                || ContainsAny(HttpPath(record), UploadPathHints)
                                || ContainsAny(record.Info, "multipart/form-data", "filename=");
            if (!uploadContext)
                return false;

            var text = string.Join("\n", new[] { record.HttpRequestHeaders, record.Info }.Where(static value => !string.IsNullOrWhiteSpace(value)));
            var match = FilenameRegex.Match(text);
            if (match.Success)
            {
                var candidate = match.Groups["name"].Value.Trim().Trim('"', '\'');
                if (HasHighRiskUploadExtension(candidate))
                {
                    fileName = candidate;
                    return true;
                }
            }

            foreach (var pair in QueryParameters(record))
            {
                if ((pair.Key.IndexOf("file", StringComparison.OrdinalIgnoreCase) >= 0
                    || pair.Key.IndexOf("name", StringComparison.OrdinalIgnoreCase) >= 0)
                    && HasHighRiskUploadExtension(pair.Value))
                {
                    fileName = pair.Value;
                    return true;
                }
            }

            var path = HttpPath(record);
            if (HasHighRiskUploadExtension(path))
            {
                fileName = path.Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? path;
                return true;
            }

            return false;
        }

        private static IEnumerable<(string Source, string Token)> EnumerateJwtCandidates(TrafficRecord record)
        {
            foreach (var pair in QueryParameters(record))
            {
                if (LooksLikeJwt(pair.Value))
                    yield return ($"query:{pair.Key}", pair.Value);
            }

            if (TryGetHeaderValue(record, "Authorization", out var authorization))
            {
                var parts = authorization.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2 && parts[0].Equals("Bearer", StringComparison.OrdinalIgnoreCase) && LooksLikeJwt(parts[1]))
                    yield return ("header:authorization", parts[1]);
            }

            var text = string.Join("\n", new[] { record.Info, record.HttpRequestHeaders }.Where(static value => !string.IsNullOrWhiteSpace(value)));
            foreach (Match match in JwtCandidateRegex.Matches(text))
            {
                if (match.Success)
                    yield return ("text", match.Groups["token"].Value);
            }
        }

        private static bool TryDecodeJwtHeader(string token, out string headerJson)
        {
            headerJson = string.Empty;
            if (!LooksLikeJwt(token))
                return false;

            var header = token.Split('.')[0];
            try
            {
                header = header.Replace('-', '+').Replace('_', '/');
                switch (header.Length % 4)
                {
                    case 2:
                        header += "==";
                        break;
                    case 3:
                        header += "=";
                        break;
                }

                headerJson = Encoding.UTF8.GetString(Convert.FromBase64String(header));
                return !string.IsNullOrWhiteSpace(headerJson);
            }
            catch
            {
                return false;
            }
        }

        private static bool TryNormalizeRedirectTarget(string value, out string target)
        {
            target = string.Empty;
            if (string.IsNullOrWhiteSpace(value))
                return false;

            var trimmed = Uri.UnescapeDataString(value).Trim();
            if (trimmed.StartsWith("//", StringComparison.Ordinal))
                trimmed = "https:" + trimmed;

            if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var absolute))
                return false;

            if (!absolute.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
                && !absolute.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            target = absolute.ToString();
            return true;
        }

        private static bool SameRootHost(string left, string right)
        {
            var leftHost = NormalizeHostValue(left);
            var rightHost = NormalizeHostValue(right);
            if (string.IsNullOrWhiteSpace(leftHost) || string.IsNullOrWhiteSpace(rightHost))
                return false;

            return string.Equals(RootDomain(leftHost), RootDomain(rightHost), StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsPlainHttpUrl(string value)
            => Uri.TryCreate(value, UriKind.Absolute, out var absolute) && absolute.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase);

        private static bool TargetsInternalHost(string value)
        {
            var host = NormalizeHostValue(value);
            if (string.IsNullOrWhiteSpace(host))
                return false;

            return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
                   || string.Equals(host, "0.0.0.0", StringComparison.OrdinalIgnoreCase)
                   || IsInternalAddress(host)
                   || host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase);
        }

        private static bool TargetsSensitiveRewriteTarget(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            return TargetsInternalHost(value)
                   || ContainsAny(value, "/admin", "/manager", "/api/admin", "localhost", "127.0.0.1");
        }

        private static bool IsAuthenticationCallbackPath(TrafficRecord record)
            => ContainsAny(HttpPath(record), "oauth", "oidc", "saml", "signin-oidc", "callback", "acs");

        private static bool HasHighRiskUploadExtension(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            var normalized = value.Trim().Trim('"', '\'').ToLowerInvariant();
            return HighRiskUploadExtensions.Any(extension => normalized.EndsWith(extension, StringComparison.OrdinalIgnoreCase));
        }

        private static Uri? ParseHttpUri(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;

            var trimmed = value.Trim();
            if (Uri.TryCreate(trimmed, UriKind.Absolute, out var absolute))
                return absolute;

            if (Uri.TryCreate("https://placeholder" + (trimmed.StartsWith("/", StringComparison.Ordinal) ? string.Empty : "/") + trimmed, UriKind.Absolute, out var relative))
                return relative;

            return null;
        }

        private static string NormalizeHostValue(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            var trimmed = value.Trim().Trim('"', '\'');
            if (Uri.TryCreate(trimmed, UriKind.Absolute, out var absolute))
                return absolute.Host.Trim().TrimEnd('.').ToLowerInvariant();

            if (trimmed.StartsWith("//", StringComparison.Ordinal) && Uri.TryCreate("https:" + trimmed, UriKind.Absolute, out var schemeless))
                return schemeless.Host.Trim().TrimEnd('.').ToLowerInvariant();

            var candidate = trimmed;
            var colon = candidate.LastIndexOf(':');
            if (colon > 0 && candidate.Count(character => character == ':') == 1)
                candidate = candidate[..colon];

            return candidate.Trim().TrimEnd('.').ToLowerInvariant();
        }

        private static string RootDomain(string host)
        {
            var normalized = NormalizeHostValue(host);
            if (string.IsNullOrWhiteSpace(normalized))
                return string.Empty;

            var labels = normalized.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (labels.Length <= 2)
                return normalized;

            var lastTwo = $"{labels[^2]}.{labels[^1]}";
            var lastThree = $"{labels[^3]}.{lastTwo}";
            if (lastTwo is "co.uk" or "org.uk" or "gov.uk" or "com.au" or "co.jp")
                return lastThree;

            return lastTwo;
        }


        public new static void ResetSharedStateForReplay()
        {
            CooldownWindows.Clear();
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
