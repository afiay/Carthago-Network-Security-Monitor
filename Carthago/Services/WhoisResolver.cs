// File: Services/WhoisResolver.cs
// SPDX-License-Identifier: MIT

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services
{
    /// <summary>
    /// Advanced RDAP-backed WHOIS resolver for IPs (and optional domains).
    /// - Tries multiple RDAP bases, follows handoffs, obeys ETag/Cache-Control.
    /// - Concurrency-limited with jittered retry on 429/5xx.
    /// - Private/bogon IPs short-circuited (no network trip).
    /// - Returns *whois-like* text so your existing regex helpers continue to work.
    /// - Adds NetRange/CIDR, Abuse, and OriginAS when available.
    /// </summary>
    public static class WhoisResolver
    {
        private static readonly bool DebugMode = false; // set true for console debug
        private const int MAX_CONCURRENCY = 6;
        private static readonly SemaphoreSlim Gate = new(MAX_CONCURRENCY, MAX_CONCURRENCY);

        // Primary RDAP bases for IP lookups (client follows 3xx handoffs automatically).
        private static readonly string[] RdapIpBases = new[]
        {
            "https://rdap.arin.net/registry/ip/",
            "https://rdap.ripe.net/ip/",
            "https://rdap.apnic.net/ip/",
            "https://rdap.lacnic.net/rdap/ip/",
            "https://rdap.afrinic.net/rdap/ip/"
        };

        // Simple domain support via RDAP aggregator (falls back silently if disabled or fails).
        // You can disable by setting EnableDomainRdap = false.
        public static bool EnableDomainRdap { get; set; } = true;
        private static readonly string[] RdapDomainBases = new[]
        {
            // rdap.org proxies to the correct registry per ICANN bootstrap
            "https://rdap.org/domain/"
        };

        // Typed result cache with TTL + ETag. Key = lower(queryType + ":" + query)
        private sealed class CacheEntry
        {
            public string Text { get; init; } = "";
            public DateTimeOffset Expires { get; init; }
            public string? ETag { get; init; }
            public string? SourceUrl { get; init; }
            public bool IsFresh => DateTimeOffset.UtcNow < Expires;
        }
        private static readonly ConcurrentDictionary<string, CacheEntry> Cache = new(StringComparer.OrdinalIgnoreCase);

        private static readonly HttpClient Http = new()
        {
            Timeout = TimeSpan.FromSeconds(6)
        };

        static WhoisResolver()
        {
            // Identify the client (some RDAP servers like nicer User-Agents)
            Http.DefaultRequestHeaders.UserAgent.ParseAdd("Carthago/1.0 (+rdap; security tooling)");
            Http.DefaultRequestHeaders.Accept.ParseAdd("application/rdap+json, application/json");
        }

        // ---------- Public API ----------

        /// <summary>Async lookup. Accepts IP (v4/v6). If EnableDomainRdap, also accepts domain FQDNs.</summary>
        public static async Task<string> LookupRawAsync(string query, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(query))
                return "WHOIS lookup failed: empty query";

            query = query.Trim();

            // PRIVATE/Bogon short-circuit
            if (TryPrivateBogon(query, out var privateText))
                return privateText;

            // Cache key derives from flavor
            var (kind, norm) = ClassifyQuery(query);
            var cacheKey = $"{kind}:{norm}";

            if (Cache.TryGetValue(cacheKey, out var ce) && ce.IsFresh)
                return ce.Text;

            try
            {
                await Gate.WaitAsync(ct).ConfigureAwait(false);

                // If we had ETag but expired TTL, attempt conditional GET from last source first
                if (ce is { SourceUrl: not null, ETag: not null })
                {
                    var cond = await TryConditionalFetch(ce.SourceUrl!, ce.ETag!, ct).ConfigureAwait(false);
                    if (cond is not null)
                    {
                        Cache[cacheKey] = cond;
                        return cond.Text;
                    }
                }

                // Otherwise fan-out over bases for the kind
                var bases = kind == "ip" ? RdapIpBases : RdapDomainBases;

                foreach (var baseUrl in bases)
                {
                    var url = baseUrl + norm;
                    var res = await FetchRdapAsWhois(url, ct).ConfigureAwait(false);
                    if (res is not null)
                    {
                        Cache[cacheKey] = res;
                        return res.Text;
                    }
                }

                return $"WHOIS lookup failed: no RDAP server responded for {norm}";
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                return $"WHOIS lookup failed: {ex.Message}";
            }
            finally
            {
                if (Gate.CurrentCount < MAX_CONCURRENCY) Gate.Release();
            }
        }

        /// <summary>Synchronous shim (avoid on hot path).</summary>
        public static string LookupRaw(string query) =>
            LookupRawAsync(query).GetAwaiter().GetResult();

        // ---------- Internals ----------

        private static (string kind, string normalized) ClassifyQuery(string q)
        {
            if (IPAddress.TryParse(q, out var ip))
                return ("ip", ip.ToString()); // normalized presentation

            if (EnableDomainRdap && IsLikelyDomain(q))
                return ("domain", q.ToLowerInvariant());

            // Fall back to "ip" error path to keep behavior consistent
            return ("ip", q);
        }

        private static bool IsLikelyDomain(string q)
        {
            // very permissive domain check
            return Regex.IsMatch(q, @"^[A-Za-z0-9][A-Za-z0-9\-\._]{1,253}$")
                   && q.Contains('.');
        }

        private static bool TryPrivateBogon(string q, out string whoisText)
        {
            whoisText = "";
            if (!IPAddress.TryParse(q, out var ip)) return false;

            if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal)
            {
                whoisText = "Registry: PRIVATE\nNetName: LOOPBACK/LINKLOCAL\nCountry: ZZ\n";
                return true;
            }

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var b = ip.GetAddressBytes();
                // RFC1918, 169.254/16, multicast 224/4, TEST-NETs, 0.0.0.0/8, 127/8, 240/4
                bool isPrivate = b[0] == 10
                                 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                                 || (b[0] == 192 && b[1] == 168)
                                 || (b[0] == 169 && b[1] == 254)
                                 || b[0] == 0 || b[0] == 127 || (b[0] >= 224);
                if (isPrivate)
                {
                    whoisText = "Registry: PRIVATE\nNetName: RFC1918/Local\nCountry: ZZ\n";
                    return true;
                }
            }
            else
            {
                var s = ip.ToString().ToLowerInvariant();
                if (s.StartsWith("fc") || s.StartsWith("fd") || s.StartsWith("fe80") || s == "::1" || s.StartsWith("ff"))
                {
                    whoisText = "Registry: PRIVATE\nNetName: ULA/LinkLocal\nCountry: ZZ\n";
                    return true;
                }
            }

            return false;
        }

        private static async Task<CacheEntry?> FetchRdapAsWhois(string url, CancellationToken ct)
        {
            // Up to 3 attempts with backoff on 429/5xx.
            var delayBase = TimeSpan.FromMilliseconds(180);
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, url);
                    using var resp = await Http.SendAsync(req, ct).ConfigureAwait(false);

                    if ((int)resp.StatusCode == 304)
                    {
                        // not expected here (we didn't send If-None-Match in this path),
                        // but treat as miss and retry
                        continue;
                    }

                    if (!resp.IsSuccessStatusCode)
                    {
                        if ((int)resp.StatusCode is 429 or >= 500)
                        {
                            await Task.Delay(Jitter(delayBase, attempt), ct).ConfigureAwait(false);
                            continue;
                        }
                        return null;
                    }

                    var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                    string whois = RdapJsonToWhoisText(json, url);

                    var ttl = ParseCacheHeaders(resp, fallback: TimeSpan.FromHours(12));
                    var etag = resp.Headers.ETag?.Tag?.Trim('"');

                    return new CacheEntry
                    {
                        Text = Normalize(whois),
                        Expires = DateTimeOffset.UtcNow.Add(ttl),
                        ETag = etag,
                        SourceUrl = url
                    };
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    if (DebugMode) Console.WriteLine($"[WHOIS DEBUG] fetch {url} attempt {attempt + 1}: {ex.Message}");
                    await Task.Delay(Jitter(delayBase, attempt), ct).ConfigureAwait(false);
                }
            }
            return null;
        }

        private static async Task<CacheEntry?> TryConditionalFetch(string url, string etag, CancellationToken ct)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                req.Headers.IfNoneMatch.ParseAdd($"\"{etag}\"");
                using var resp = await Http.SendAsync(req, ct).ConfigureAwait(false);

                if ((int)resp.StatusCode == 304)
                {
                    // Not Modified: keep old ETag; extend modestly
                    return new CacheEntry
                    {
                        Text = Cache.Values.First(v => v.SourceUrl == url && v.ETag == etag).Text,
                        Expires = DateTimeOffset.UtcNow.Add(TimeSpan.FromHours(6)),
                        ETag = etag,
                        SourceUrl = url
                    };
                }

                if (!resp.IsSuccessStatusCode) return null;

                var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                string whois = RdapJsonToWhoisText(json, url);

                var ttl = ParseCacheHeaders(resp, fallback: TimeSpan.FromHours(12));
                var newEtag = resp.Headers.ETag?.Tag?.Trim('"');

                return new CacheEntry
                {
                    Text = Normalize(whois),
                    Expires = DateTimeOffset.UtcNow.Add(ttl),
                    ETag = newEtag,
                    SourceUrl = url
                };
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                if (DebugMode) Console.WriteLine($"[WHOIS DEBUG] conditional fetch {url}: {ex.Message}");
                return null;
            }
        }

        private static TimeSpan ParseCacheHeaders(HttpResponseMessage resp, TimeSpan fallback)
        {
            // RFC 7234 Cache-Control: max-age
            if (resp.Headers.CacheControl?.MaxAge is TimeSpan ccAge && ccAge > TimeSpan.Zero)
                return ccAge > TimeSpan.FromDays(3) ? TimeSpan.FromDays(3) : ccAge;

            if (resp.Content.Headers.Expires is DateTimeOffset exp)
            {
                var ttl = exp - DateTimeOffset.UtcNow;
                if (ttl > TimeSpan.Zero && ttl < TimeSpan.FromDays(3)) return ttl;
            }
            return fallback;
        }

        private static TimeSpan Jitter(TimeSpan baseDelay, int attempt)
        {
            var rand = Random.Shared.NextDouble() * 0.35 + 0.65; // 0.65–1.0x
            var backoff = Math.Pow(2, attempt);
            var ms = Math.Min(4000, baseDelay.TotalMilliseconds * backoff * rand);
            return TimeSpan.FromMilliseconds(ms);
        }

        // ---------- RDAP → whois-like text ----------

        private static string RdapJsonToWhoisText(string json, string sourceUrl)
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            string registry = GuessRegistryFromUrl(sourceUrl);
            string netName = TryGetString(root, "name") ?? "";
            string country = TryGetString(root, "country") ?? "";

            // CIDR / NetRange (startAddress/endAddress or cidr0_cidrs extension)
            (string? start, string? end) = (TryGetString(root, "startAddress"), TryGetString(root, "endAddress"));
            string? cidr = TryGetCidr(root);
            var sb = new StringBuilder();

            if (!string.IsNullOrEmpty(registry)) sb.AppendLine($"Registry: {registry}");
            if (!string.IsNullOrEmpty(netName)) sb.AppendLine($"NetName: {netName}");
            if (!string.IsNullOrEmpty(country)) sb.AppendLine($"Country: {country}");
            if (!string.IsNullOrEmpty(cidr)) sb.AppendLine($"CIDR: {cidr}");
            if (!string.IsNullOrEmpty(start) || !string.IsNullOrEmpty(end))
                sb.AppendLine($"NetRange: {start ?? "?"} - {end ?? "?"}");

            // Entities → org + abuse
            (string? orgName, string? abuseEmail) = ExtractOrgAndAbuse(root);
            if (!string.IsNullOrEmpty(orgName)) sb.AppendLine($"OrgName: {orgName}");
            if (!string.IsNullOrEmpty(abuseEmail)) sb.AppendLine($"OrgAbuseEmail: {abuseEmail}");

            // Origin AS (some RIRs include indirect hints)
            var asn = TryFindAsn(root);
            if (!string.IsNullOrWhiteSpace(asn)) sb.AppendLine($"OriginAS: {asn}");

            return sb.ToString();
        }

        private static string GuessRegistryFromUrl(string url) =>
            url.Contains("arin", StringComparison.OrdinalIgnoreCase) ? "ARIN" :
            url.Contains("ripe", StringComparison.OrdinalIgnoreCase) ? "RIPE" :
            url.Contains("apnic", StringComparison.OrdinalIgnoreCase) ? "APNIC" :
            url.Contains("lacnic", StringComparison.OrdinalIgnoreCase) ? "LACNIC" :
            url.Contains("afrinic", StringComparison.OrdinalIgnoreCase) ? "AFRINIC" :
            url.Contains("rdap.org", StringComparison.OrdinalIgnoreCase) ? "RDAP.ORG" :
            "RDAP";

        private static (string? org, string? abuse) ExtractOrgAndAbuse(JsonElement root)
        {
            string? orgName = null;
            string? abuseEmail = null;

            if (root.TryGetProperty("entities", out var ents) && ents.ValueKind == JsonValueKind.Array)
            {
                foreach (var ent in ents.EnumerateArray())
                {
                    var roles = ent.TryGetProperty("roles", out var r) && r.ValueKind == JsonValueKind.Array
                        ? r.EnumerateArray().Select(x => x.GetString() ?? "").ToArray()
                        : Array.Empty<string>();

                    if (roles.Length == 0) continue;

                    if (ent.TryGetProperty("vcardArray", out var vc) && vc.ValueKind == JsonValueKind.Array)
                    {
                        orgName ??= TryExtractVcard(vc, new[] { "org", "fn" });
                        abuseEmail ??= TryExtractEmail(vc);
                    }

                    // abuse contacts can also be listed via "publicIds" or "remarks"; optional future work
                }
            }
            return (orgName, abuseEmail);
        }

        private static string? TryExtractVcard(JsonElement vcardArray, IEnumerable<string> prefer)
        {
            if (vcardArray.ValueKind != JsonValueKind.Array || vcardArray.GetArrayLength() < 2) return null;
            foreach (var item in vcardArray[1].EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Array || item.GetArrayLength() < 4) continue;
                var key = item[0].GetString();
                if (prefer.Contains(key ?? "", StringComparer.OrdinalIgnoreCase))
                    return item[3].GetString();
            }
            return null;
        }

        private static string? TryExtractEmail(JsonElement vcardArray)
        {
            if (vcardArray.ValueKind != JsonValueKind.Array || vcardArray.GetArrayLength() < 2) return null;
            foreach (var item in vcardArray[1].EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Array || item.GetArrayLength() < 4) continue;
                var key = item[0].GetString();
                if (string.Equals(key, "email", StringComparison.OrdinalIgnoreCase))
                    return item[3].GetString();
            }
            return null;
        }

        private static string? TryGetCidr(JsonElement root)
        {
            // Many RIRs use the cidr0 extension:
            // "cidr0_cidrs":[{"v4prefix":"203.0.113.0","length":24}, ...]
            if (root.TryGetProperty("cidr0_cidrs", out var cidrs) && cidrs.ValueKind == JsonValueKind.Array)
            {
                var parts = new List<string>();
                foreach (var c in cidrs.EnumerateArray())
                {
                    string? v4 = TryGetString(c, "v4prefix");
                    string? v6 = TryGetString(c, "v6prefix");
                    if (v4 is not null && c.TryGetProperty("length", out var ln) && ln.TryGetInt32(out int l4))
                        parts.Add($"{v4}/{l4}");
                    if (v6 is not null && c.TryGetProperty("length", out var l6) && l6.TryGetInt32(out int l6i))
                        parts.Add($"{v6}/{l6i}");
                }
                if (parts.Count > 0) return string.Join(", ", parts);
            }
            return null;
        }

        private static string? TryFindAsn(JsonElement root)
        {
            // heuristics: scan text for "AS12345"
            var text = root.ToString();
            var m = Regex.Match(text, @"\bAS(\d{1,7})\b", RegexOptions.IgnoreCase);
            return m.Success ? "AS" + m.Groups[1].Value : null;
        }

        private static string? TryGetString(JsonElement elem, string name) =>
            elem.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.String ? prop.GetString() : null;

        private static string Normalize(string s) => s.Replace("\r\n", "\n").Replace('\r', '\n').Trim() + "\n";

        // ---------- Existing regex helpers (unchanged signature) ----------

        private static string? TryRegex(string text, string pattern)
        {
            if (string.IsNullOrWhiteSpace(text)) return null;
            var m = Regex.Match(text, pattern, RegexOptions.Multiline | RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value.Trim() : null;
        }

        public static string? GetRegistrar(string raw) => TryRegex(raw, @"(?im)^\s*(?:Registrar|Registry):\s*(.+)$");
        public static string? GetOrganization(string raw) => TryRegex(raw, @"(?im)^\s*(?:OrgName|org|owner|responsible):\s*(.+)$");
        public static string? GetCountry(string raw) => TryRegex(raw, @"(?im)^\s*(?:Country|country):\s*([A-Z]{2})\b");
        public static string? GetASN(string raw) => TryRegex(raw, @"(?im)^\s*(?:OriginAS|originas|origin-as|originasnumber):\s*(AS?\d+)\b");
        public static string? GetAbuseContact(string raw) => TryRegex(raw, @"(?im)^\s*(?:OrgAbuseEmail|abuse-mailbox|abuse-c|abuse):\s*([^\s]+)");
    }
}
