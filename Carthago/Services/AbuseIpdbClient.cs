// File: Services/AbuseIpdbClient.cs
// SPDX-License-Identifier: MIT
// .NET 8–friendly: single HttpClient, retry with jitter, Retry-After honoring.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services
{
    public sealed class AbuseIpdbClient : IDisposable
    {
        private readonly HttpClient _http;
        private readonly JsonSerializerOptions _json = new()
        {
            PropertyNameCaseInsensitive = true
        };

        private const int DefaultTimeoutSeconds = 10;
        private const int MaxRetries = 5;
        private static readonly TimeSpan BaseBackoff = TimeSpan.FromMilliseconds(300);
        private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(10);

        public AbuseIpdbClient(string apiKey, HttpMessageHandler? handler = null)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                throw new InvalidOperationException("ABUSEIPDB_API_KEY is missing.");

            _http = handler is null ? new HttpClient() : new HttpClient(handler);
            _http.BaseAddress = new Uri("https://api.abuseipdb.com/api/v2/");
            _http.DefaultRequestHeaders.Add("Key", apiKey);
            _http.Timeout = TimeSpan.FromSeconds(DefaultTimeoutSeconds);
            _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("Carthago/1.0 (+https://example.invalid)");
        }

        public async Task<AbuseCheck?> CheckAsync(string ip, int maxAgeInDays = 90, bool verbose = false, CancellationToken ct = default)
        {
            var url = $"check?ipAddress={Uri.EscapeDataString(ip)}&maxAgeInDays={maxAgeInDays}{(verbose ? "&verbose" : "")}";
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            using var resp = await SendWithRetryAsync(req, ct).ConfigureAwait(false);
            await EnsureSuccessWithContext(resp).ConfigureAwait(false);
            return await DeserializeDataAsync<AbuseCheck>(resp.Content, ct).ConfigureAwait(false);
        }

        public async Task<BlacklistResponse?> GetBlacklistJsonAsync(
            int? confidenceMinimum = null,
            int? limit = null,
            string? onlyCountries = null,
            string? exceptCountries = null,
            int? ipVersion = null,
            CancellationToken ct = default)
        {
            var qs = new List<string>(5);
            if (confidenceMinimum.HasValue) qs.Add($"confidenceMinimum={confidenceMinimum.Value}");
            if (limit.HasValue) qs.Add($"limit={limit.Value}");
            if (!string.IsNullOrWhiteSpace(onlyCountries)) qs.Add($"onlyCountries={Uri.EscapeDataString(onlyCountries)}");
            if (!string.IsNullOrWhiteSpace(exceptCountries)) qs.Add($"exceptCountries={Uri.EscapeDataString(exceptCountries)}");
            if (ipVersion.HasValue) qs.Add($"ipVersion={ipVersion.Value}");
            var url = "blacklist" + (qs.Count > 0 ? "?" + string.Join("&", qs) : "");

            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            using var resp = await SendWithRetryAsync(req, ct).ConfigureAwait(false);
            await EnsureSuccessWithContext(resp).ConfigureAwait(false);
            await using var s = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<BlacklistResponse>(s, _json, ct).ConfigureAwait(false);
        }

        public async Task<string> GetBlacklistPlainAsync(
            int? confidenceMinimum = null,
            int? limit = null,
            string? onlyCountries = null,
            string? exceptCountries = null,
            int? ipVersion = null,
            CancellationToken ct = default)
        {
            var qs = new List<string>(5);
            if (confidenceMinimum.HasValue) qs.Add($"confidenceMinimum={confidenceMinimum.Value}");
            if (limit.HasValue) qs.Add($"limit={limit.Value}");
            if (!string.IsNullOrWhiteSpace(onlyCountries)) qs.Add($"onlyCountries={Uri.EscapeDataString(onlyCountries)}");
            if (!string.IsNullOrWhiteSpace(exceptCountries)) qs.Add($"exceptCountries={Uri.EscapeDataString(exceptCountries)}");
            if (ipVersion.HasValue) qs.Add($"ipVersion={ipVersion.Value}");
            var url = "blacklist" + (qs.Count > 0 ? "?" + string.Join("&", qs) : "");

            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/plain"));
            using var resp = await SendWithRetryAsync(req, ct).ConfigureAwait(false);
            await EnsureSuccessWithContext(resp).ConfigureAwait(false);
            return await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        }

        public async Task<CheckBlockResponse?> CheckBlockAsync(string cidr, int maxAgeDays = 30, CancellationToken ct = default)
        {
            var url = $"check-block?network={Uri.EscapeDataString(cidr)}&maxAgeInDays={maxAgeDays}";
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            using var resp = await SendWithRetryAsync(req, ct).ConfigureAwait(false);
            await EnsureSuccessWithContext(resp).ConfigureAwait(false);
            return await DeserializeDataAsync<CheckBlockResponse>(resp.Content, ct).ConfigureAwait(false);
        }

        public async Task<ReportsPage?> GetReportsAsync(string ip, int page = 1, int perPage = 25, int maxAgeDays = 30, CancellationToken ct = default)
        {
            var url = $"reports?ipAddress={Uri.EscapeDataString(ip)}&page={page}&perPage={perPage}&maxAgeInDays={maxAgeDays}";
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            using var resp = await SendWithRetryAsync(req, ct).ConfigureAwait(false);
            await EnsureSuccessWithContext(resp).ConfigureAwait(false);
            return await DeserializeDataAsync<ReportsPage>(resp.Content, ct).ConfigureAwait(false);
        }

        public async Task<ReportResult?> ReportAsync(string ip, string categoriesCsv, string comment, DateTimeOffset? when = null, CancellationToken ct = default)
        {
            var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["ip"] = ip,
                ["categories"] = categoriesCsv,
                ["comment"] = comment,
                ["timestamp"] = (when ?? DateTimeOffset.UtcNow).ToString("o", CultureInfo.InvariantCulture)
            });

            using var req = new HttpRequestMessage(HttpMethod.Post, "report") { Content = content };
            using var resp = await SendWithRetryAsync(req, ct).ConfigureAwait(false);
            await EnsureSuccessWithContext(resp).ConfigureAwait(false);
            return await DeserializeDataAsync<ReportResult>(resp.Content, ct).ConfigureAwait(false);
        }

        public async Task<int> BulkReportAsync(string csvFilePath, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(csvFilePath))
                throw new ArgumentNullException(nameof(csvFilePath), "CSV file path cannot be null or empty.");
            if (!File.Exists(csvFilePath))
                throw new FileNotFoundException("CSV file not found.", csvFilePath);

            using var form = new MultipartFormDataContent();
            await using var stream = File.OpenRead(csvFilePath);
            form.Add(new StreamContent(stream), "csv", Path.GetFileName(csvFilePath)!);

            using var req = new HttpRequestMessage(HttpMethod.Post, "bulk-report") { Content = form };
            using var resp = await SendWithRetryAsync(req, ct).ConfigureAwait(false);
            await EnsureSuccessWithContext(resp).ConfigureAwait(false);

            var result = await DeserializeDataAsync<BulkReportResult>(resp.Content, ct).ConfigureAwait(false);
            return result is null ? 0 : result.SavedReports;
        }

        // ---------------- Resilience helpers ----------------

        private async Task<HttpResponseMessage> SendWithRetryAsync(HttpRequestMessage req, CancellationToken ct)
        {
            var attempt = 0;

            while (true)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var resp = await _http.SendAsync(req.Clone(), HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

                    if (IsTransient(resp.StatusCode))
                    {
                        var delay = GetRetryDelay(resp) ?? JitteredBackoff(attempt);
                        if (++attempt > MaxRetries) return resp; // surface the 429/5xx to caller
                        await ConsumeAndDispose(resp).ConfigureAwait(false);
                        await Task.Delay(delay, ct).ConfigureAwait(false);
                        continue;
                    }

                    return resp;
                }
                catch (OperationCanceledException) { throw; }
                catch (HttpRequestException)
                {
                    var delay = JitteredBackoff(attempt++);
                    if (attempt > MaxRetries) throw;
                    await Task.Delay(delay, ct).ConfigureAwait(false);
                }
                catch
                {
                    var delay = JitteredBackoff(attempt++);
                    if (attempt > MaxRetries) throw;
                    await Task.Delay(delay, ct).ConfigureAwait(false);
                }
            }
        }

        private static bool IsTransient(HttpStatusCode code)
            => code == HttpStatusCode.TooManyRequests || (int)code >= 500;

        private static TimeSpan JitteredBackoff(int attempt)
        {
            var pow = Math.Pow(2, Math.Max(0, attempt));
            var backoff = TimeSpan.FromMilliseconds(Math.Min(BaseBackoff.TotalMilliseconds * pow, MaxBackoff.TotalMilliseconds));
            var jitter = TimeSpan.FromMilliseconds(Random.Shared.Next(25, 125));
            var jittered = backoff + jitter;
            return jittered <= MaxBackoff ? jittered : MaxBackoff;
        }

        private static TimeSpan? GetRetryDelay(HttpResponseMessage resp)
        {
            if (resp.Headers.TryGetValues("Retry-After", out var values))
            {
                foreach (var v in values)
                {
                    if (int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds) && seconds >= 0)
                        return TimeSpan.FromSeconds(Math.Min(seconds, (int)MaxBackoff.TotalSeconds));

                    if (DateTimeOffset.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var when))
                    {
                        var delta = when - DateTimeOffset.UtcNow;
                        if (delta > TimeSpan.Zero)
                            return delta > MaxBackoff ? MaxBackoff : delta;
                    }
                }
            }
            return null;
        }

        private static async Task ConsumeAndDispose(HttpResponseMessage resp)
        {
            try { _ = await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false); }
            catch { /* ignore */ }
            finally { resp.Dispose(); }
        }

        // NOTE: Constrain T to class so we can return T? (nullable reference type) without CS8978.
        private async Task<T?> DeserializeDataAsync<T>(HttpContent content, CancellationToken ct) where T : class
        {
            await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            var wrapper = await JsonSerializer.DeserializeAsync<DataWrapper<T>>(stream, _json, ct).ConfigureAwait(false);
            return wrapper?.Data;
        }

        private async Task EnsureSuccessWithContext(HttpResponseMessage resp)
        {
            if (resp.IsSuccessStatusCode) return;

            string body = "";
            try { body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false); } catch { /* ignore */ }

            resp.Dispose();
            throw new HttpRequestException($"AbuseIPDB API error {(int)resp.StatusCode} {resp.ReasonPhrase}. Body: {body}", null, resp.StatusCode);
        }

        // ---------------- DTOs & helpers ----------------

        // Constrain to class; Data may be null if API wraps { "data": null }.
        private sealed class DataWrapper<T> where T : class
        {
            public T? Data { get; set; }
        }

        public sealed class AbuseCheck
        {
            public string? IpAddress { get; set; }
            public int AbuseConfidenceScore { get; set; }
            public int TotalReports { get; set; }
            public string? CountryCode { get; set; }
            public string? UsageType { get; set; }
            public string? Isp { get; set; }
            public string? Domain { get; set; }
            public string? LastReportedAt { get; set; }
        }

        public sealed class BlacklistResponse
        {
            public List<BlacklistItem> Data { get; set; } = new();
        }

        public sealed class BlacklistItem
        {
            public string IpAddress { get; set; } = "";
            public int AbuseConfidenceScore { get; set; }
            public string? LastReportedAt { get; set; }
            public string? CountryCode { get; set; }
        }

        public sealed class CheckBlockResponse
        {
            public string? NetworkAddress { get; set; }
            public string? Netmask { get; set; }
            public int NumPossibleHosts { get; set; }
            public List<ReportedAddress> ReportedAddresses { get; set; } = new();

            public sealed class ReportedAddress
            {
                public string IpAddress { get; set; } = "";
                public int NumReports { get; set; }
                public string? MostRecentReport { get; set; }
                public int AbuseConfidenceScore { get; set; }
                public string? CountryCode { get; set; }
            }
        }

        public sealed class ReportsPage
        {
            public int Total { get; set; }
            public int Page { get; set; }
            public int PerPage { get; set; }
            public int LastPage { get; set; }
            public List<ReportRow> Results { get; set; } = new();

            public sealed class ReportRow
            {
                public string? ReportedAt { get; set; }
                public string? Comment { get; set; }
                public int[] Categories { get; set; } = Array.Empty<int>();
                public int ReporterId { get; set; }
                public string? ReporterCountryCode { get; set; }
                public string? ReporterCountryName { get; set; }
            }
        }

        public sealed class ReportResult
        {
            public string IpAddress { get; set; } = "";
            public int AbuseConfidenceScore { get; set; }
        }

        public sealed class BulkReportResult
        {
            public int SavedReports { get; set; }
        }

        public void Dispose() => _http.Dispose();
    }

    internal static class HttpRequestMessageExtensions
    {
        internal static HttpRequestMessage Clone(this HttpRequestMessage req)
        {
            var clone = new HttpRequestMessage(req.Method, req.RequestUri)
            {
                Version = req.Version,
                VersionPolicy = req.VersionPolicy
            };

            foreach (var h in req.Headers)
                clone.Headers.TryAddWithoutValidation(h.Key, h.Value);

            if (req.Content is not null)
            {
                var bytes = req.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
                var contentClone = new ByteArrayContent(bytes);
                foreach (var h in req.Content.Headers)
                    contentClone.Headers.TryAddWithoutValidation(h.Key, h.Value);
                clone.Content = contentClone;
            }

            return clone;
        }
    }
}
