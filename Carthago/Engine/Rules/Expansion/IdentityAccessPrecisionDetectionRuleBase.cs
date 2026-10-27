// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/IdentityAccessPrecisionDetectionRuleBase.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class IdentityAccessPrecisionDetectionRuleBase : PrecisionTelemetryDetectionRuleBase
    {
        private static readonly ConcurrentDictionary<string, List<DateTime>> TimeWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> DistinctWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, DateTime> CooldownWindows = new(StringComparer.OrdinalIgnoreCase);

        private static readonly HashSet<int> CleartextHttpPorts = new() { 80, 8080, 8000, 8008, 8880 };
        private static readonly HashSet<int> TlsHttpPorts = new() { 443, 8443, 9443, 10443, 5986 };

        private static readonly string[] VpnKeywords =
        {
            "vpn", "sslvpn", "webvpn", "anyconnect", "fortinet", "fortigate", "globalprotect", "pulse secure",
            "pulse", "netscaler", "citrix adc", "sonicwall", "remote access", "forticlient", "palo alto"
        };

        private static readonly string[] ApplianceKeywords =
        {
            "fortinet", "fortigate", "globalprotect", "anyconnect", "pulse secure", "sonicwall", "netscaler",
            "citrix adc", "pfsense", "opnsense", "checkpoint", "firewall", "router", "switch", "mikrotik",
            "ubiquiti", "unifi", "meraki", "sophos", "f5", "big-ip", "appliance"
        };

        private static readonly string[] AdminPathKeywords =
        {
            "/admin", "/administrator", "/wp-admin", "/manager/html", "/console", "/manage", "/supervisor",
            "/control", "/config", "/settings", "/system", "/setup", "/ui/"
        };

        private static readonly string[] LoginKeywords =
        {
            "login", "signin", "sign-in", "authenticate", "authentication", "password", "username",
            "session", "oauth", "oidc", "saml", "mfa", "totp", "webauthn"
        };

        private static readonly string[] ResetKeywords =
        {
            "reset password", "forgot password", "password-reset", "password reset", "account recovery",
            "recover account", "enroll", "enrollment", "mfa enroll", "totp enroll", "webauthn", "reset token"
        };

        private static readonly string[] SessionCookieNames =
        {
            "sessionid", "phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid"
        };

        private static readonly string[] StaticAssetExtensions =
        {
            ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"
        };

        private static readonly string[] DocumentationPathHints =
        {
            "/docs", "/documentation", "/manual", "/guide", "/guides", "/help", "/support", "/kb", "/knowledgebase",
            "/article", "/articles", "/download", "/downloads", "/product-guides", "/release-notes"
        };

        private static readonly string[] DocumentationHostHints =
        {
            "docs.", "support.", "help.", "kb.", "community.", "download."
        };

        private static readonly string[] CallbackPathKeywords =
        {
            "callback", "signin-oidc", "/acs", "/oauth2/callback", "/saml/acs"
        };

        private static readonly Regex IdentityRegex = new(
            @"(?i)\b(?:user(?:name)?|login|email|upn|account|principal|identity|member)\s*[:=]\s*(?<value>[A-Za-z0-9_.+\-@\\]+)\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex EmailRegex = new(
            @"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        protected IdentityAccessPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }

        protected RuleEvaluationResult NoMatch()
            => RuleEvaluationResult.NoMatch(Descriptor.RuleId);

        protected RuleEvaluationResult NoMatch(RuleNoMatchReasonCategory category, string code, string message)
            => RuleEvaluationResult.NoMatch(Descriptor.RuleId, category, code, message);

        protected RuleEvaluationResult MatchIdentityAccess(
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
            var items = new List<DetectionEvidenceItem>
            {
                new("identity.family", detectionFamily, "identity-access"),
                new("identity.host", string.IsNullOrWhiteSpace(host) ? record.Destination ?? "unknown" : host, "identity-access")
            };

            // R123 may carry authentication tokens in path segments. Its rule
            // emits only a fixed, non-sensitive route category instead.
            if (!string.IsNullOrWhiteSpace(path) && Descriptor.RuleId != "R123"
                && Descriptor.RuleId is not ("R127" or "R128" or "R129" or "R130" or "R131" or "R132" or "R133" or "R134" or "R135"))
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

        protected static string BestHost(TrafficRecord record)
            => NormalizeHost(FirstNonEmpty(record.HttpHost, record.Sni, record.DnsQname, record.Destination)) ?? string.Empty;

        protected static string Text(TrafficRecord record)
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
                record.SrcCountryIso2,
                record.SrcCountry,
                record.WhoisCountry
            }.Where(static value => !string.IsNullOrWhiteSpace(value))!);

        protected static bool HasHttpContext(TrafficRecord record)
            => HasAny(record.HttpMethod, record.HttpHost, record.HttpUri, record.HttpRequestHeaders, record.HttpUserAgent)
               || ContainsAny(record.ApplicationProtocol, "http", "https")
               || ContainsAny(record.ApplicationService, "http", "https")
               || Port(record, 80, 443, 8080, 8443, 9443, 8000, 8008, 10443);

        protected static bool IsCleartextHttp(TrafficRecord record)
        {
            if (!HasHttpContext(record))
                return false;

            if (IsTlsProtected(record))
                return false;

            return CleartextHttpPorts.Contains(record.SourcePort ?? -1)
                   || CleartextHttpPorts.Contains(record.DestinationPort ?? -1)
                   || ContainsAny(record.Protocol, "http")
                   || ContainsAny(record.ApplicationProtocol, "http")
                   || ContainsAny(record.ApplicationService, "http");
        }

        protected static bool IsTlsProtected(TrafficRecord record)
            => HasAny(record.Sni, record.TlsVersion, record.Alpn, record.CertIssuer, record.CertSubject)
               || TlsHttpPorts.Contains(record.SourcePort ?? -1)
               || TlsHttpPorts.Contains(record.DestinationPort ?? -1)
               || ContainsAny(record.Protocol, "https", "tls")
               || ContainsAny(record.ApplicationProtocol, "https", "tls")
               || ContainsAny(record.ApplicationService, "https", "tls");

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
            => !string.IsNullOrWhiteSpace(ipOrHost) && !IsMulticastOrBroadcast(ipOrHost) && !IsInternalAddress(ipOrHost);

        protected static bool IsCrossBoundary(TrafficRecord record, out bool outboundToExternal, out bool inboundFromExternal)
        {
            outboundToExternal = IsInternalAddress(record.Source) && IsExternalAddress(BestHost(record));
            inboundFromExternal = IsExternalAddress(record.Source) && IsInternalAddress(record.Destination);
            return outboundToExternal || inboundFromExternal;
        }

        protected static bool IsRdpContext(TrafficRecord record)
            => record.IsTcp
               && (Port(record, 3389)
                   || ContainsAny(record.ApplicationProtocol, "rdp")
                   || ContainsAny(record.ApplicationService, "rdp")
                   || ((ContainsAny(Text(record), "remote desktop", "mstsc", "mstshash") || ContainsAny(record.ProcessName, "mstsc", "remote desktop"))
                       && !string.IsNullOrWhiteSpace(record.ProcessName)));

        protected static bool IsWinrmContext(TrafficRecord record)
            => record.IsTcp
               && (Port(record, 5985, 5986)
                   || ContainsAny(record.ApplicationProtocol, "winrm", "wsman")
                   || ContainsAny(record.ApplicationService, "winrm", "wsman")
                   || ((ContainsAny(Text(record), "winrm", "wsman", "powershell remoting") || ContainsAny(record.ProcessName, "powershell", "pwsh", "wsmprovhost"))
                       && !string.IsNullOrWhiteSpace(record.ProcessName)));

        protected static bool IsSshContext(TrafficRecord record)
            => record.IsTcp
               && (Port(record, 22)
                   || ContainsAny(record.ApplicationProtocol, "ssh")
                   || ContainsAny(record.ApplicationService, "ssh")
                   || HasAny(record.Hassh, record.Ja4SSH)
                   || ContainsAny(Text(record), "ssh", "openssh", "failed password", "invalid user"));

        protected static bool HasLoginContext(TrafficRecord record)
        {
            if (!HasHttpContext(record) || IsLikelyStaticAssetPath(record) || IsLikelyDocumentationOrDownloadSurface(record))
                return false;

            var path = HttpPath(record);
            var interactivePath = PathContainsAny(record, "/login", "/signin", "/sign-in", "/session", "/auth", "/authenticate", "/oauth", "/oidc", "/saml", "/token");
            var callbackLike = ContainsAny(path, CallbackPathKeywords);
            var headerContext = HasAuthHeaderContext(record);
            var credentialMaterial = ContainsAny(record.HttpUri, "password=", "username=", "grant_type=password", "passwd=", "user=")
                                     || ContainsAny(record.HttpRequestHeaders, "password=", "username=", "grant_type=password", "passwd=", "user=")
                                     || ContainsAny(record.Info, "password=", "username=", "grant_type=password", "passwd=", "user=");
            var textLoginContext = ContainsAny(record.Info, LoginKeywords)
                                   || ContainsAny(record.HttpRequestHeaders, LoginKeywords)
                                   || ContainsAny(record.HttpUri, LoginKeywords);

            if (interactivePath && !callbackLike)
                return true;

            if (callbackLike && !headerContext && !credentialMaterial && !UsesCredentialSubmissionMethod(record))
                return false;

            return (textLoginContext || headerContext || credentialMaterial)
                   && (UsesCredentialSubmissionMethod(record) || interactivePath || headerContext);
        }

        protected static bool HasAuthFailureContext(TrafficRecord record)
        {
            if (HasHttpContext(record))
            {
                var explicitHttpFailure =
                    ContainsAny(record.Info, "401 unauthorized", "403 forbidden", "status 401", "status 403", "http 401", "http 403")
                    || ContainsAny(record.HttpUri, "status=401", "status=403")
                    || ContainsAny(record.Info, "authentication failed", "login failed", "invalid password", "bad credentials", "invalid user", "user not found", "access denied", "invalid grant")
                    || ContainsAny(record.HttpRequestHeaders, "authentication failed", "login failed", "invalid password", "bad credentials", "invalid user", "user not found", "access denied", "invalid grant");

                if (!explicitHttpFailure)
                    return false;

                return HasAuthHeaderContext(record)
                       || HasLoginContext(record)
                       || PathContainsAny(record, "/auth", "/login", "/signin", "/session", "/token", "/oauth");
            }

            return ContainsAny(Text(record), "authentication failed", "login failed", "invalid password", "bad credentials", "invalid user", "user not found", "access denied", "failed password", "permission denied");
        }

        protected static bool HasAuthHeaderContext(TrafficRecord record)
            => ContainsAny(record.HttpRequestHeaders, "authorization:", "www-authenticate", "proxy-authorization", "negotiate", "ntlm", "basic", "bearer")
               || ContainsAny(record.Info, "authorization:", "www-authenticate", "proxy-authorization");

        protected static bool HasResetOrEnrollmentContext(TrafficRecord record)
        {
            if (!HasHttpContext(record) || IsLikelyStaticAssetPath(record) || IsLikelyDocumentationOrDownloadSurface(record))
                return false;

            return ContainsAny(Text(record), ResetKeywords)
                   || PathContainsAny(record, "/password-reset", "/reset-password", "/forgot-password", "/recover", "/enroll", "/mfa", "/totp", "/webauthn");
        }

        protected static bool HasVpnLoginPath(TrafficRecord record)
        {
            if (!HasHttpContext(record) || IsLikelyStaticAssetPath(record) || IsLikelyDocumentationOrDownloadSurface(record))
                return false;

            var path = HttpPath(record);
            var host = BestHost(record);
            var text = Text(record);
            var vpnContext = ContainsAny(text, VpnKeywords) || ContainsAny(host, VpnKeywords);
            if (!vpnContext)
                return false;

            return PathContainsAny(record, "/remote/login", "/sslvpn", "/global-protect", "/globalprotect", "/webvpn", "/+cscoe+/", "/vpn/", "/remote/", "/auth/saml")
                   || (ContainsAny(path, "login", "auth", "saml", "oauth", "signin")
                       && (ContainsAny(path, "/vpn", "/remote", "/webvpn", "/sslvpn", "/global") || vpnContext));
        }

        protected static bool HasAdminPortalPath(TrafficRecord record)
        {
            if (!HasHttpContext(record) || IsLikelyStaticAssetPath(record) || IsLikelyDocumentationOrDownloadSurface(record))
                return false;

            return PathContainsAny(record, AdminPathKeywords)
                   || (PathContainsAny(record, "/login", "/signin", "/session", "/authenticate")
                       && ContainsAny(Text(record), "admin portal", "admin console", "administrator", "manager/html", "control panel", "supervisor", "management console"));
        }

        protected static bool IsApplianceManagementPortal(TrafficRecord record)
        {
            if (IsLikelyStaticAssetPath(record) || IsLikelyDocumentationOrDownloadSurface(record))
                return false;

            var path = HttpPath(record);
            var host = BestHost(record);
            var text = Text(record);
            var applianceContext = ContainsAny(text, ApplianceKeywords) || ContainsAny(host, ApplianceKeywords);
            return applianceContext
                   && (HasAdminPortalPath(record)
                       || PathContainsAny(record, "/remote/login", "/sslvpn", "/global-protect", "/webvpn", "/ui", "/cgi-bin", "/manager")
                       || (ContainsAny(path, "login", "admin", "manage", "config") && applianceContext));
        }

        protected static bool HasSuspiciousSamlOidcCallback(TrafficRecord record)
        {
            if (!HasHttpContext(record))
                return false;

            var path = HttpPath(record);
            var uri = record.HttpUri ?? string.Empty;
            if (!ContainsAny(path, "callback", "signin-oidc", "oauth2", "oidc", "saml", "acs", "assertion"))
                return false;

            return ContainsAny(uri, "SAMLResponse=", "SAMLRequest=", "id_token=", "access_token=", "#id_token=", "#access_token=", "redirect_uri=http://", "post_logout_redirect_uri=http://", "RelayState=http");
        }

        protected static bool UsesCredentialSubmissionMethod(TrafficRecord record)
            => string.Equals(record.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase)
               || string.Equals(record.HttpMethod, "PUT", StringComparison.OrdinalIgnoreCase)
               || string.Equals(record.HttpMethod, "PATCH", StringComparison.OrdinalIgnoreCase)
               || ContainsAny(record.HttpUri, "password=", "username=", "grant_type=password", "passwd=", "user=", "credential=")
               || ContainsAny(record.HttpRequestHeaders, "password=", "username=", "grant_type=password", "passwd=", "user=", "credential=")
               || ContainsAny(record.Info, "password=", "username=", "grant_type=password", "passwd=", "user=", "credential=");

        protected static string ExtractIdentity(TrafficRecord record)
        {
            var text = string.Join(" ", new[]
            {
                record.Info,
                record.HttpUri,
                record.HttpRequestHeaders
            }.Where(static value => !string.IsNullOrWhiteSpace(value))!);

            var match = IdentityRegex.Match(text);
            if (match.Success)
                return match.Groups["value"].Value.Trim().ToLowerInvariant();

            match = EmailRegex.Match(text);
            return match.Success ? match.Value.Trim().ToLowerInvariant() : string.Empty;
        }

        protected static string SourceCountry(TrafficRecord record)
            => FirstNonEmpty(record.SrcCountryIso2, record.SrcCountry) ?? string.Empty;

        protected static bool TryGetSensitiveQueryParameter(TrafficRecord record, out string parameterName, out string parameterValue)
        {
            parameterName = string.Empty;
            parameterValue = string.Empty;

            var uri = ParseHttpUri(record.HttpUri);
            if (uri == null)
                return false;

            var query = uri.Query.TrimStart('?');
            if (string.IsNullOrWhiteSpace(query))
                return false;

            foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var pieces = part.Split('=', 2);
                var name = Uri.UnescapeDataString(pieces[0]).Trim();
                var value = pieces.Length > 1 ? Uri.UnescapeDataString(pieces[1]).Trim() : string.Empty;
                if (LooksSensitiveQueryParameter(name, value))
                {
                    parameterName = name;
                    parameterValue = value;
                    return true;
                }
            }

            return false;
        }

        protected static bool TryGetBasicAuthorization(TrafficRecord record, out string token)
        {
            foreach (var headerValue in GetHeaderValuesFromRecord(record, "Authorization").Concat(GetHeaderValuesFromRecord(record, "Proxy-Authorization")))
            {
                if (!headerValue.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                    continue;

                token = headerValue["Basic ".Length..].Trim();
                if (LooksLikeBasicToken(token))
                    return true;
            }

            token = string.Empty;
            return false;
        }

        protected static bool TryGetBearerAuthorization(TrafficRecord record, out string token)
        {
            foreach (var headerValue in GetHeaderValuesFromRecord(record, "Authorization").Concat(GetHeaderValuesFromRecord(record, "Proxy-Authorization")))
            {
                if (!headerValue.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    continue;

                token = headerValue["Bearer ".Length..].Trim();
                if (LooksOpaqueToken(token))
                    return true;
            }

            token = string.Empty;
            return false;
        }

        protected static bool TryGetSessionCookie(TrafficRecord record, out string cookieName)
        {
            foreach (var headerName in new[] { "Cookie", "Set-Cookie" })
            {
                foreach (var headerValue in GetHeaderValuesFromRecord(record, headerName))
                {
                    foreach (var segment in headerValue.Split(';', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var pieces = segment.Split('=', 2);
                        var name = pieces[0].Trim();
                        var value = pieces.Length > 1 ? pieces[1].Trim() : string.Empty;
                        if (!SessionCookieNames.Contains(name, StringComparer.OrdinalIgnoreCase))
                            continue;

                        if (LooksOpaqueToken(value))
                        {
                            cookieName = name;
                            return true;
                        }
                    }
                }
            }

            cookieName = string.Empty;
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

        protected static int IntSetting(string ruleId, string key, int defaultValue, int min, int max)
            => RuleEngine.GetRuleIntSetting(ruleId, key, defaultValue, min, max);

        protected static RulePrecisionProfile CreateIdentityAccessProfile(
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
                new HashSet<string>(new[] { "process.name", "geo.country", "whois.organization" }, StringComparer.OrdinalIgnoreCase),
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

        protected static string HttpPath(TrafficRecord record)
        {
            var uri = ParseHttpUri(record.HttpUri);
            if (uri != null)
                return string.IsNullOrWhiteSpace(uri.AbsolutePath) ? "/" : uri.AbsolutePath;

            return string.Empty;
        }

        protected static bool PathContainsAny(TrafficRecord record, params string[] needles)
            => ContainsAny(HttpPath(record), needles);

        protected static bool IsLikelyStaticAssetPath(TrafficRecord record)
        {
            var path = HttpPath(record);
            return !string.IsNullOrWhiteSpace(path)
                   && StaticAssetExtensions.Any(extension => path.EndsWith(extension, StringComparison.OrdinalIgnoreCase));
        }

        protected static bool IsLikelyDocumentationOrDownloadSurface(TrafficRecord record)
        {
            var path = HttpPath(record);
            var host = BestHost(record);
            return DocumentationPathHints.Any(candidate => path.StartsWith(candidate, StringComparison.OrdinalIgnoreCase))
                   || DocumentationHostHints.Any(candidate => host.StartsWith(candidate, StringComparison.OrdinalIgnoreCase))
                   || ContainsAny(host, "docs.", "support.", "help.", "kb.", "community.", "download.");
        }

        private static bool LooksSensitiveQueryParameter(string name, string value)
        {
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(value))
                return false;

            var normalizedName = name.Trim().ToLowerInvariant();
            if (normalizedName.Contains("csrf", StringComparison.Ordinal)
                || normalizedName.Contains("xsrf", StringComparison.Ordinal)
                || normalizedName.Contains("state", StringComparison.Ordinal)
                || normalizedName.Contains("nonce", StringComparison.Ordinal)
                || normalizedName.Contains("code_verifier", StringComparison.Ordinal)
                || normalizedName.Contains("page_token", StringComparison.Ordinal)
                || normalizedName.Contains("next_token", StringComparison.Ordinal)
                || normalizedName.Contains("reset_token", StringComparison.Ordinal)
                || normalizedName.Contains("verification_token", StringComparison.Ordinal))
            {
                return false;
            }

            var strongName =
                normalizedName is "api_key" or "apikey" or "access_token" or "auth_token" or "bearer_token" or "client_secret" or "secret_key"
                || normalizedName.EndsWith("_api_key", StringComparison.Ordinal)
                || normalizedName.EndsWith("_token", StringComparison.Ordinal)
                || normalizedName.EndsWith("_secret", StringComparison.Ordinal);

            if (!strongName)
                return false;

            return LooksOpaqueToken(value) || value.Length >= 12;
        }

        private static bool LooksOpaqueToken(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            var trimmed = value.Trim();
            if (trimmed.Length < 12)
                return false;

            if (trimmed.Count(character => character == '.') == 2 && trimmed.StartsWith("eyJ", StringComparison.Ordinal))
                return true;

            return trimmed.All(character => char.IsLetterOrDigit(character) || character is '-' or '_' or '=' or '.' or '~')
                   && trimmed.Any(char.IsDigit)
                   && trimmed.Any(char.IsLetter);
        }

        private static bool LooksLikeBasicToken(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            var trimmed = value.Trim();
            return trimmed.Length >= 8
                   && trimmed.All(character => char.IsLetterOrDigit(character) || character is '+' or '/' or '=' or '-' or '_');
        }

        protected static bool ContainsAny(string? value, IEnumerable<string> needles)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            foreach (var needle in needles)
            {
                if (!string.IsNullOrWhiteSpace(needle) && value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        protected static bool ContainsAny(string? value, params string[] needles)
            => ContainsAny(value, (IEnumerable<string>)needles);

        private static bool HasAny(params string?[] values)
            => values.Any(static value => !string.IsNullOrWhiteSpace(value));

        private static IReadOnlyList<string> GetHeaderValuesFromRecord(TrafficRecord record, string headerName)
        {
            var values = new List<string>();
            if (string.IsNullOrWhiteSpace(headerName))
                return values;

            foreach (var block in EnumerateHeaderBlocks(record))
            {
                foreach (var line in block.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var separator = line.IndexOf(':');
                    if (separator <= 0)
                        continue;

                    var name = line[..separator].Trim();
                    if (!string.Equals(name, headerName, StringComparison.OrdinalIgnoreCase))
                        continue;

                    values.Add(line[(separator + 1)..].Trim());
                }
            }

            return values;
        }

        private static bool Port(TrafficRecord record, params int[] ports)
        {
            if (ports == null || ports.Length == 0)
                return false;

            return (record.SourcePort.HasValue && ports.Contains(record.SourcePort.Value))
                   || (record.DestinationPort.HasValue && ports.Contains(record.DestinationPort.Value));
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

        private static bool IsMulticastOrBroadcast(string? ipOrHost)
        {
            if (string.IsNullOrWhiteSpace(ipOrHost))
                return false;

            if (!IPAddress.TryParse(ipOrHost.Trim(), out var ip))
                return ContainsAny(ipOrHost, "255.255.255.255");

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var bytes = ip.GetAddressBytes();
                return (bytes[0] >= 224 && bytes[0] <= 239) || ip.Equals(IPAddress.Broadcast);
            }

            return ip.IsIPv6Multicast;
        }

        private static string? NormalizeHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host))
                return null;

            var trimmed = host.Trim().TrimEnd('.').ToLowerInvariant();
            if ((trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                && Uri.TryCreate(trimmed, UriKind.Absolute, out var absolute))
            {
                return absolute.Host.Trim().TrimEnd('.').ToLowerInvariant();
            }

            if (trimmed.Contains('/') && Uri.TryCreate("https://" + trimmed, UriKind.Absolute, out var partial))
                return partial.Host.Trim().TrimEnd('.').ToLowerInvariant();

            if (trimmed.Count(character => character == ':') == 1
                && trimmed.Contains('.')
                && trimmed.LastIndexOf(':') > trimmed.LastIndexOf(']'))
            {
                trimmed = trimmed[..trimmed.LastIndexOf(':')];
            }

            return trimmed;
        }

        private static IEnumerable<string> EnumerateHeaderBlocks(TrafficRecord record)
        {
            if (!string.IsNullOrWhiteSpace(record.HttpRequestHeaders))
                yield return record.HttpRequestHeaders!;

            if (!string.IsNullOrWhiteSpace(record.Info)
                && (HasHeaderLine(record.Info, "Authorization:")
                    || HasHeaderLine(record.Info, "Cookie:")
                    || HasHeaderLine(record.Info, "Set-Cookie:")
                    || HasHeaderLine(record.Info, "Proxy-Authorization:")))
            {
                yield return record.Info!;
            }
        }

        private static bool HasHeaderLine(string? value, string headerPrefix)
        {
            if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(headerPrefix))
                return false;

            return value.StartsWith(headerPrefix, StringComparison.OrdinalIgnoreCase)
                   || value.IndexOf("\r\n" + headerPrefix, StringComparison.OrdinalIgnoreCase) >= 0
                   || value.IndexOf("\n" + headerPrefix, StringComparison.OrdinalIgnoreCase) >= 0;
        }


        public static void ResetSharedStateForReplay()
        {
            TimeWindows.Clear();
            DistinctWindows.Clear();
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
