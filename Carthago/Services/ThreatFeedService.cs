// File: Services/ThreatFeedService.cs
// SPDX-License-Identifier: MIT

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services
{
    // ==============================
    // Public DTOs / API
    // ==============================

    public enum IndicatorKind { Host, Domain, Url, IPv4, IPv6, Hash }

    public sealed record ThreatIndicator(
        string Value,
        IndicatorKind Kind,
        string Source,
        DateTimeOffset FirstSeen,
        DateTimeOffset LastSeen,
        int Confidence = 70,
        string[]? Tags = null
    );

    public sealed record MatchInfo(
        IndicatorKind Kind,
        string Value,
        int Confidence,
        string[] Sources,
        string[] Tags
    );

    public sealed class ThreatSnapshot
    {
        public DateTimeOffset BuiltAt { get; init; }
        public string ContentHashHex { get; init; } = string.Empty;

        // High-speed membership (Frozen* + Bloom prefilter)
        public FrozenSet<string> Hosts { get; init; } = FrozenSet.ToFrozenSet(Array.Empty<string>());
        public FrozenSet<string> Domains { get; init; } = FrozenSet.ToFrozenSet(Array.Empty<string>());
        public FrozenSet<string> Urls { get; init; } = FrozenSet.ToFrozenSet(Array.Empty<string>());
        public FrozenSet<string> Ip4 { get; init; } = FrozenSet.ToFrozenSet(Array.Empty<string>());
        public FrozenSet<string> Ip6 { get; init; } = FrozenSet.ToFrozenSet(Array.Empty<string>());

        // Value -> merged meta for UX/explanations
        public FrozenDictionary<string, IndicatorMeta> Meta { get; init; } =
            FrozenDictionary.ToFrozenDictionary(Array.Empty<KeyValuePair<string, IndicatorMeta>>());

        // Probabilistic prefilter
        public BloomFilter Bloom { get; init; } = BloomFilter.Empty();

        // Novelty estimator (for “first time seen” / rare domains)
        public HllSketch Novelty { get; init; } = HllSketch.Create();

        public long IndicatorCount { get; init; }
        public int SourceCount { get; init; }

        public sealed record IndicatorMeta(int Confidence, FrozenSet<string> Sources, FrozenSet<string> Tags);
    }

    // ==============================
    // ThreatFeedService (public API)
    // ==============================

    public static class ThreatFeedService
    {
        // ---------- Directories ----------
        private static readonly string ThreatDir = Path.Combine(AppContext.BaseDirectory, "Data", "ThreatIntel");
        private static readonly string SnapshotDir = Path.Combine(ThreatDir, "Snapshots");        // CAS snapshots
        private static readonly string StatePath = Path.Combine(ThreatDir, "feeds_state.json");   // checkpoints
        private static readonly string CompatCachePath = Path.Combine(ThreatDir, "threatfeed_cache.json"); // legacy

        // ---------- HTTP client ----------
        private static readonly HttpClient Http = new(
            new SocketsHttpHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
                PooledConnectionLifetime = TimeSpan.FromMinutes(10),
                ConnectTimeout = TimeSpan.FromSeconds(8),
                AllowAutoRedirect = true
            })
        { Timeout = TimeSpan.FromSeconds(30) };

        // ---------- Feeds (pluggable) ----------
        private static readonly List<IThreatFeed> _feeds = new()
        {
            new UrlHausRecentFeed(Http),
            // new PlainTextListFeed(Http, "https://example.com/bad-hosts.txt", "SampleList", IndicatorKind.Host),
        };

        // ---------- Scheduler ----------
        private static CancellationTokenSource? _cts;
        private static Task? _runner;

        // ---------- Snapshot (immutable, atomically swapped) ----------
        private static volatile ThreatSnapshot _snapshot = EmptySnapshot();

        // Back-compat: expose a HashSet<string> of hosts after each refresh
        public static HashSet<string> MaliciousHosts { get; private set; } =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Live stats
        public sealed record Stats(DateTimeOffset LastBuild, long Indicators, int Feeds, double BloomFpr, long HostCount, long DomainCount, long UrlCount, long IpCount);
        public static Stats CurrentStats =>
            new(
                _snapshot.BuiltAt,
                _snapshot.IndicatorCount,
                _snapshot.SourceCount,
                _snapshot.Bloom.EstimatedFalsePositiveRate,
                _snapshot.Hosts.Count,
                _snapshot.Domains.Count,
                _snapshot.Urls.Count,
                _snapshot.Ip4.Count + _snapshot.Ip6.Count
            );

        // ======== Public lifecycle ========

        public static async Task InitializeAsync(CancellationToken token)
        {
            Directory.CreateDirectory(ThreatDir);
            Directory.CreateDirectory(SnapshotDir);

            // Try load most recent snapshot (content-addressed), else build an empty
            TryLoadLatestSnapshot();

            // Warm legacy cache for older code paths (hosts only)
            SaveLegacyCompatCache();

            // Start background scheduler
            _cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            _runner = Task.Run(() => SchedulerLoop(_cts.Token));
            await Task.Yield();
        }

        public static async Task ForceRefreshAsync(CancellationToken ct = default)
        {
            var state = LoadFeedState();
            var (indicators, updatedState) = await FetchAllFeedsAsync(state, ct).ConfigureAwait(false);
            BuildAndSwapSnapshot(indicators);
            SaveFeedState(updatedState);
            SaveLegacyCompatCache();
            RuleEngine.ReportThreatFeedUpdated(DateTime.UtcNow);
        }

        public static void Stop()
        {
            try { _cts?.Cancel(); } catch { }
            try { _runner?.Wait(1000); } catch { }
            try { _cts?.Dispose(); } catch { }
        }

        // ======== Queries ========

        public static bool TryMatch(string value, out MatchInfo info)
        {
            info = default!;
            if (string.IsNullOrWhiteSpace(value)) return false;
            var v = NormalizeValue(value);

            // Bloom prefilter: cheap fast-fail
            if (!_snapshot.Bloom.MightContain(v))
                return false;

            // Exact meta
            if (_snapshot.Meta.TryGetValue(v, out var meta))
            {
                var kind = ClassifyStringKind(v);
                info = new MatchInfo(kind, v, meta.Confidence, meta.Sources.ToArray(), meta.Tags.ToArray());
                return true;
            }

            // For backward host-only callers
            if (_snapshot.Hosts.Contains(v) && _snapshot.Meta.TryGetValue(v, out meta))
            {
                info = new MatchInfo(IndicatorKind.Host, v, meta.Confidence, meta.Sources.ToArray(), meta.Tags.ToArray());
                return true;
            }

            return false;
        }

        public static bool IsBadHost(string host) => TryMatch(host, out _);

        // ==============================
        // Internal: Scheduler & Build
        // ==============================

        private static async Task SchedulerLoop(CancellationToken ct)
        {
            var state = LoadFeedState();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var (indicators, newState) = await FetchAllFeedsAsync(state, ct).ConfigureAwait(false);
                    if (indicators.Count > 0)
                    {
                        BuildAndSwapSnapshot(indicators);
                        SaveLegacyCompatCache();
                        RuleEngine.ReportThreatFeedUpdated(DateTime.UtcNow);
                    }

                    SaveFeedState(newState);
                    state = newState;
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[ThreatFeed] scheduler error: {ex.Message}");
                }

                // Sleep with jitter between 45–75 minutes
                var delay = TimeSpan.FromMinutes(45 + Random.Shared.Next(0, 30));
                try { await Task.Delay(delay, ct); } catch (OperationCanceledException) { break; }
            }
        }

        private static async Task<(List<ThreatIndicator> indicators, FeedState newState)> FetchAllFeedsAsync(FeedState state, CancellationToken ct)
        {
            var outputs = new ConcurrentBag<ThreatIndicator>();
            var newState = new FeedState { Checkpoints = new Dictionary<string, FeedCheckpoint>(state.Checkpoints, StringComparer.Ordinal) };

            using var sem = new SemaphoreSlim(3);
            var tasks = _feeds.Select(async feed =>
            {
                await sem.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    state.Checkpoints.TryGetValue(feed.Name, out var cp);
                    var (batch, checkpoint) = await feed.FetchAsync(cp, ct).ConfigureAwait(false);
                    foreach (var ind in batch) outputs.Add(ind);
                    if (checkpoint is not null)
                        newState.Checkpoints[feed.Name] = checkpoint;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[ThreatFeed] feed {feed.Name} failed: {ex.Message}");
                }
                finally { sem.Release(); }
            });

            await Task.WhenAll(tasks).ConfigureAwait(false);

            var merged = MergeIndicators(outputs);
            return (merged, newState);
        }

        // NOTE: local types inside methods cause CS1519/CS1513; keep this struct at type scope
        private struct MergeAccum
        {
            public string Value;
            public IndicatorKind Kind;
            public DateTimeOffset First, Last;
            public int Confidence;
            public HashSet<string> Sources;
            public HashSet<string> Tags;
        }

        private static List<ThreatIndicator> MergeIndicators(IEnumerable<ThreatIndicator> indicators)
        {
            var byVal = new Dictionary<string, MergeAccum>(StringComparer.Ordinal);

            foreach (var ind in indicators)
            {
                var key = CanonicalKey(ind.Value, ind.Kind);
                if (!byVal.TryGetValue(key, out var m))
                {
                    m = new MergeAccum
                    {
                        Value = key,
                        Kind = ind.Kind,
                        First = ind.FirstSeen,
                        Last = ind.LastSeen,
                        Confidence = ind.Confidence,
                        Sources = new HashSet<string>(StringComparer.Ordinal) { ind.Source },
                        Tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    };
                    if (ind.Tags is { Length: > 0 }) foreach (var t in ind.Tags) m.Tags.Add(t);
                    byVal[key] = m;
                }
                else
                {
                    if (ind.FirstSeen < m.First) m.First = ind.FirstSeen;
                    if (ind.LastSeen > m.Last) m.Last = ind.LastSeen;
                    if (ind.Confidence > m.Confidence) m.Confidence = ind.Confidence;
                    m.Sources.Add(ind.Source);
                    if (ind.Tags is { Length: > 0 }) foreach (var t in ind.Tags) m.Tags.Add(t);
                    byVal[key] = m;
                }
            }

            return byVal.Values.Select(m =>
                new ThreatIndicator(m.Value, m.Kind, string.Join(",", m.Sources), m.First, m.Last, m.Confidence, m.Tags.ToArray())
            ).ToList();
        }

        private static void BuildAndSwapSnapshot(List<ThreatIndicator> indicators)
        {
            var hosts = new HashSet<string>(StringComparer.Ordinal);
            var domains = new HashSet<string>(StringComparer.Ordinal);
            var urls = new HashSet<string>(StringComparer.Ordinal);
            var ip4 = new HashSet<string>(StringComparer.Ordinal);
            var ip6 = new HashSet<string>(StringComparer.Ordinal);

            // temp meta builder
            var tempMeta = new Dictionary<string, TempMeta>(StringComparer.Ordinal);

            // Novelty sketch (domain focused)
            var hll = HllSketch.Create();

            foreach (var ind in indicators)
            {
                var v = CanonicalKey(ind.Value, ind.Kind);
                switch (ind.Kind)
                {
                    case IndicatorKind.Host:
                        hosts.Add(v);
                        AccumulateMeta(v, ind);
                        hll.Add(EtldPlusOne(v));
                        break;
                    case IndicatorKind.Domain:
                        domains.Add(v);
                        AccumulateMeta(v, ind);
                        hll.Add(EtldPlusOne(v));
                        break;
                    case IndicatorKind.Url:
                        urls.Add(v);
                        AccumulateMeta(v, ind);
                        break;
                    case IndicatorKind.IPv4:
                        ip4.Add(v);
                        AccumulateMeta(v, ind);
                        break;
                    case IndicatorKind.IPv6:
                        ip6.Add(v);
                        AccumulateMeta(v, ind);
                        break;
                    case IndicatorKind.Hash:
                        AccumulateMeta(v, ind);
                        break;
                }
            }

            // Build Frozen* structures
            var fHosts = FrozenSet.ToFrozenSet(hosts);
            var fDomains = FrozenSet.ToFrozenSet(domains);
            var fUrls = FrozenSet.ToFrozenSet(urls);
            var fIp4 = FrozenSet.ToFrozenSet(ip4);
            var fIp6 = FrozenSet.ToFrozenSet(ip6);

            // Build Bloom sized to ~n items, target FPR ~0.1%
            long n = hosts.Count + domains.Count + urls.Count + ip4.Count + ip6.Count;
            var bloom = BloomFilter.Create(capacity: Math.Max(1024, (int)n), targetFpr: 0.001);
            foreach (var s in hosts) bloom.Add(s);
            foreach (var s in domains) bloom.Add(s);
            foreach (var s in urls) bloom.Add(s);
            foreach (var s in ip4) bloom.Add(s);
            foreach (var s in ip6) bloom.Add(s);

            // Freeze meta
            var fMeta = FrozenDictionary.ToFrozenDictionary(
                tempMeta.Select(kv => new KeyValuePair<string, ThreatSnapshot.IndicatorMeta>(
                    kv.Key,
                    new ThreatSnapshot.IndicatorMeta(
                        kv.Value.Confidence,
                        FrozenSet.ToFrozenSet(kv.Value.Sources),
                        FrozenSet.ToFrozenSet(kv.Value.Tags)
                    ))),
                StringComparer.Ordinal
            );

            // Content-address snapshot payload (stable order)
            var joined = string.Join("\n",
                hosts.OrderBy(x => x, StringComparer.Ordinal)
                     .Concat(domains.OrderBy(x => x, StringComparer.Ordinal))
                     .Concat(urls.OrderBy(x => x, StringComparer.Ordinal))
                     .Concat(ip4.OrderBy(x => x, StringComparer.Ordinal))
                     .Concat(ip6.OrderBy(x => x, StringComparer.Ordinal))
            );
            string hex = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(joined)));

            var snap = new ThreatSnapshot
            {
                BuiltAt = DateTimeOffset.UtcNow,
                ContentHashHex = hex,
                Hosts = fHosts,
                Domains = fDomains,
                Urls = fUrls,
                Ip4 = fIp4,
                Ip6 = fIp6,
                Meta = fMeta,
                Bloom = bloom,
                Novelty = hll,
                IndicatorCount = indicators.Count,
                SourceCount = _feeds.Count
            };

            // Persist snapshot (CAS)
            TrySaveSnapshot(snap);

            // Atomic swap
            _snapshot = snap;

            // Back-compat: refresh host HashSet
            MaliciousHosts = new HashSet<string>(_snapshot.Hosts, StringComparer.OrdinalIgnoreCase);

            // local helper
            void AccumulateMeta(string key, ThreatIndicator ind)
            {
                if (!tempMeta.TryGetValue(key, out var tm))
                {
                    tm = new TempMeta
                    {
                        Confidence = ind.Confidence,
                        Sources = new HashSet<string>(StringComparer.Ordinal),
                        Tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    };
                }
                tm.Confidence = Math.Max(tm.Confidence, ind.Confidence);
                tm.Sources.Add(ind.Source);
                if (ind.Tags is { Length: > 0 })
                    foreach (var t in ind.Tags) tm.Tags.Add(t);
                tempMeta[key] = tm;
            }
        }

        private struct TempMeta
        {
            public int Confidence;
            public HashSet<string> Sources;
            public HashSet<string> Tags;
        }

        private static IndicatorKind ClassifyStringKind(string v)
        {
            if (IPAddress.TryParse(v, out var ip))
                return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? IndicatorKind.IPv4 : IndicatorKind.IPv6;

            if (v.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                v.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                return IndicatorKind.Url;

            if (v.Contains('/')) return IndicatorKind.Url;
            if (v.Contains(':')) return IndicatorKind.Url;
            if (v.Contains('.')) return IndicatorKind.Host;

            return IndicatorKind.Hash;
        }

        // ==============================
        // Persistence
        // ==============================

        private static void TrySaveSnapshot(ThreatSnapshot snap)
        {
            try
            {
                var path = Path.Combine(SnapshotDir, $"snapshot-{snap.BuiltAt:yyyyMMdd-HHmmss}-{snap.ContentHashHex[..12]}.json");
                var opt = new JsonSerializerOptions { WriteIndented = false, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
                File.WriteAllText(path, JsonSerializer.Serialize(new SerializableSnapshot(snap), opt));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ThreatFeed] save snapshot failed: {ex.Message}");
            }
        }

        private static void TryLoadLatestSnapshot()
        {
            try
            {
                Directory.CreateDirectory(SnapshotDir);
                var file = Directory.EnumerateFiles(SnapshotDir, "snapshot-*.json").OrderByDescending(Path.GetFileName).FirstOrDefault();
                if (file is null) return;
                var s = JsonSerializer.Deserialize<SerializableSnapshot>(File.ReadAllText(file));
                if (s is null) return;
                _snapshot = s.ToRuntime();
                MaliciousHosts = new HashSet<string>(_snapshot.Hosts, StringComparer.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ThreatFeed] load snapshot failed: {ex.Message}");
                _snapshot = EmptySnapshot();
            }
        }

        private static void SaveLegacyCompatCache()
        {
            try
            {
                var tmp = CompatCachePath + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(MaliciousHosts));
#if NET6_0_OR_GREATER
                File.Move(tmp, CompatCachePath, overwrite: true);
#else
                if (File.Exists(CompatCachePath)) File.Delete(CompatCachePath);
                File.Move(tmp, CompatCachePath);
#endif
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ThreatFeed] legacy cache save failed: {ex.Message}");
            }
        }

        private static ThreatSnapshot EmptySnapshot() => new ThreatSnapshot
        {
            BuiltAt = DateTimeOffset.UtcNow,
            ContentHashHex = string.Empty
        };

        // ==============================
        // Feed plumbing
        // ==============================

        private interface IThreatFeed
        {
            string Name { get; }
            Task<(IReadOnlyList<ThreatIndicator> items, FeedCheckpoint? checkpoint)> FetchAsync(FeedCheckpoint? last, CancellationToken ct);
        }

        private sealed record FeedCheckpoint(string? ETag, DateTimeOffset? LastModifiedUtc);
        private sealed class FeedState { public Dictionary<string, FeedCheckpoint> Checkpoints { get; set; } = new(StringComparer.Ordinal); }

        private static FeedState LoadFeedState()
        {
            try
            {
                if (!File.Exists(StatePath)) return new FeedState();
                var json = File.ReadAllText(StatePath);
                var d = JsonSerializer.Deserialize<Dictionary<string, FeedCheckpoint>>(json) ?? new();
                return new FeedState { Checkpoints = d };
            }
            catch { return new FeedState(); }
        }

        private static void SaveFeedState(FeedState s)
        {
            try
            {
                Directory.CreateDirectory(ThreatDir);
                var tmp = StatePath + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(s.Checkpoints));
#if NET6_0_OR_GREATER
                File.Move(tmp, StatePath, overwrite: true);
#else
                if (File.Exists(StatePath)) File.Delete(StatePath);
                File.Move(tmp, StatePath);
#endif
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ThreatFeed] save feed state failed: {ex.Message}");
            }
        }

        // -------- URLHaus adapter (streaming parse) --------
        private sealed class UrlHausRecentFeed : IThreatFeed
        {
            public string Name => "urlhaus_recent";
            private readonly HttpClient _http;
            private const string Url = "https://urlhaus.abuse.ch/downloads/urlhaus_recent.json";

            public UrlHausRecentFeed(HttpClient http) => _http = http;

            public async Task<(IReadOnlyList<ThreatIndicator> items, FeedCheckpoint? checkpoint)> FetchAsync(FeedCheckpoint? last, CancellationToken ct)
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, Url);
                if (last?.ETag is not null) req.Headers.TryAddWithoutValidation("If-None-Match", last.ETag);
                if (last?.LastModifiedUtc is not null) req.Headers.IfModifiedSince = last.LastModifiedUtc;

                using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                if (resp.StatusCode == HttpStatusCode.NotModified)
                    return (Array.Empty<ThreatIndicator>(), last);

                resp.EnsureSuccessStatusCode();

                var eTag = resp.Headers.ETag?.Tag?.Trim('"');
                var lm = resp.Content.Headers.LastModified?.UtcDateTime;

                var now = DateTimeOffset.UtcNow;
                var list = new List<ThreatIndicator>(1024);

                await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                using var doc = await JsonDocument.ParseAsync(stream, default, ct).ConfigureAwait(false);
                if (!doc.RootElement.TryGetProperty("urls", out var urls) || urls.ValueKind != JsonValueKind.Array)
                    return (Array.Empty<ThreatIndicator>(), new FeedCheckpoint(eTag, lm));

                foreach (var u in urls.EnumerateArray())
                {
                    string? host = u.TryGetProperty("host", out var h) && h.ValueKind == JsonValueKind.String ? h.GetString() : null;
                    string? url = u.TryGetProperty("url", out var urlEl) && urlEl.ValueKind == JsonValueKind.String ? urlEl.GetString() : null;
                    string[] tags = u.TryGetProperty("tags", out var t) && t.ValueKind == JsonValueKind.Array
                        ? t.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToArray()
                        : Array.Empty<string>();

                    if (!string.IsNullOrWhiteSpace(host))
                    {
                        var v = CanonicalKey(host, IndicatorKind.Host);
                        list.Add(new ThreatIndicator(v, IndicatorKind.Host, Name, now, now, 75, tags));
                        // Also promote registrable domain if different
                        var root = EtldPlusOne(v);
                        if (!string.Equals(root, v, StringComparison.Ordinal))
                            list.Add(new ThreatIndicator(root, IndicatorKind.Domain, Name, now, now, 65, tags));
                    }
                    if (!string.IsNullOrWhiteSpace(url))
                    {
                        var vv = CanonicalKey(url, IndicatorKind.Url);
                        list.Add(new ThreatIndicator(vv, IndicatorKind.Url, Name, now, now, 80, tags));
                    }
                }

                return (list, new FeedCheckpoint(eTag, lm));
            }
        }

        // Example plain-text list adapter (one indicator per line)
        private sealed class PlainTextListFeed : IThreatFeed
        {
            public string Name { get; }
            private readonly HttpClient _http;
            private readonly string _url;
            private readonly IndicatorKind _kind;

            public PlainTextListFeed(HttpClient http, string url, string name, IndicatorKind kind)
            { _http = http; _url = url; Name = name; _kind = kind; }

            public async Task<(IReadOnlyList<ThreatIndicator> items, FeedCheckpoint? checkpoint)> FetchAsync(FeedCheckpoint? last, CancellationToken ct)
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, _url);
                if (last?.ETag is not null) req.Headers.TryAddWithoutValidation("If-None-Match", last.ETag);
                if (last?.LastModifiedUtc is not null) req.Headers.IfModifiedSince = last.LastModifiedUtc;

                using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                if (resp.StatusCode == HttpStatusCode.NotModified) return (Array.Empty<ThreatIndicator>(), last);
                resp.EnsureSuccessStatusCode();

                var eTag = resp.Headers.ETag?.Tag?.Trim('"');
                var lm = resp.Content.Headers.LastModified?.UtcDateTime;

                var now = DateTimeOffset.UtcNow;
                var list = new List<ThreatIndicator>(1024);

                using var sr = new StreamReader(await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false), Encoding.UTF8, true, 8192, leaveOpen: false);
                string? line;
                while ((line = await sr.ReadLineAsync()) is not null)
                {
                    line = line.Trim();
                    if (line.Length == 0 || line.StartsWith('#')) continue;
                    var v = CanonicalKey(line, _kind);
                    list.Add(new ThreatIndicator(v, _kind, Name, now, now, 60, null));
                }

                return (list, new FeedCheckpoint(eTag, lm));
            }
        }

        // ==============================
        // Normalization helpers
        // ==============================

        private static string CanonicalKey(string value, IndicatorKind kind)
        {
            var v = NormalizeValue(value);
            if (kind == IndicatorKind.Host || kind == IndicatorKind.Domain)
                v = v.TrimEnd('.'); // drop trailing dot
            return v;
        }

        private static string NormalizeValue(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return string.Empty;
            value = value.Trim();

            // URLs → lower scheme/host, keep path as-is
            if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                if (Uri.TryCreate(value, UriKind.Absolute, out var uri))
                {
                    var idn = new IdnMapping();
                    var host = idn.GetAscii(uri.Host).ToLowerInvariant();
                    var scheme = uri.Scheme.ToLowerInvariant();
                    var port = uri.IsDefaultPort ? "" : $":{uri.Port}";
                    var path = uri.PathAndQuery; // keep case
                    return $"{scheme}://{host}{port}{path}";
                }
                return value.ToLowerInvariant();
            }

            // IPs/domains/hosts → IDN to ASCII + lowercase
            if (IPAddress.TryParse(value, out _)) return value; // keep textual IP
            try
            {
                var idn = new IdnMapping();
                return idn.GetAscii(value).ToLowerInvariant();
            }
            catch
            {
                return value.ToLowerInvariant();
            }
        }

        // Very light eTLD+1 approximation (safe fallback when PSL not present)
        private static string EtldPlusOne(string host)
        {
            try
            {
                var parts = host.Split('.', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length <= 2) return host;
                return string.Join('.', parts.Skip(parts.Length - 2));
            }
            catch { return host; }
        }

        // ==============================
        // Serializable snapshot (compact)
        // ==============================

        private sealed class SerializableSnapshot
        {
            public DateTimeOffset BuiltAt { get; set; }
            public string Hash { get; set; } = "";
            public string[] H { get; set; } = Array.Empty<string>(); // hosts
            public string[] D { get; set; } = Array.Empty<string>(); // domains
            public string[] U { get; set; } = Array.Empty<string>(); // urls
            public string[] A { get; set; } = Array.Empty<string>(); // ipv4
            public string[] V { get; set; } = Array.Empty<string>(); // ipv6
            public Dictionary<string, MiniMeta> M { get; set; } = new(StringComparer.Ordinal);
            public BloomWire B { get; set; } = new();
            public HllWire L { get; set; } = new();
            public long N { get; set; }
            public int S { get; set; }

            public SerializableSnapshot() { }

            public SerializableSnapshot(ThreatSnapshot s)
            {
                BuiltAt = s.BuiltAt;
                Hash = s.ContentHashHex;
                H = s.Hosts.ToArray();
                D = s.Domains.ToArray();
                U = s.Urls.ToArray();
                A = s.Ip4.ToArray();
                V = s.Ip6.ToArray();
                M = s.Meta.ToDictionary(k => k.Key, v => new MiniMeta
                {
                    C = v.Value.Confidence,
                    S = v.Value.Sources.ToArray(),
                    T = v.Value.Tags.ToArray()
                }, StringComparer.Ordinal);
                // Build wire models without exposing private types publicly
                B = BloomWire.From(s.Bloom);
                L = HllWire.FromSketch(s.Novelty);
                N = s.IndicatorCount;
                S = s.SourceCount;
            }

            public ThreatSnapshot ToRuntime()
            {
                return new ThreatSnapshot
                {
                    BuiltAt = BuiltAt,
                    ContentHashHex = Hash,
                    Hosts = FrozenSet.ToFrozenSet(H),
                    Domains = FrozenSet.ToFrozenSet(D),
                    Urls = FrozenSet.ToFrozenSet(U),
                    Ip4 = FrozenSet.ToFrozenSet(A),
                    Ip6 = FrozenSet.ToFrozenSet(V),
                    Meta = FrozenDictionary.ToFrozenDictionary(
                        M.Select(kv => new KeyValuePair<string, ThreatSnapshot.IndicatorMeta>(
                            kv.Key,
                            new ThreatSnapshot.IndicatorMeta(kv.Value.C, FrozenSet.ToFrozenSet(kv.Value.S), FrozenSet.ToFrozenSet(kv.Value.T))
                        )), StringComparer.Ordinal),
                    Bloom = BloomWire.ToRuntime(B),
                    Novelty = HllWire.ToRuntime(L),
                    IndicatorCount = N,
                    SourceCount = S
                };
            }

            public sealed class MiniMeta
            {
                public int C { get; set; }
                public string[] S { get; set; } = Array.Empty<string>();
                public string[] T { get; set; } = Array.Empty<string>();
            }
        }

        // ==============================
        // Bloom Filter wire (compact)
        // ==============================

        internal sealed class BloomWire
        {
            public int M { get; set; }
            public int K { get; set; }
            public double F { get; set; }
            public uint[] W { get; set; } = Array.Empty<uint>();

            internal static BloomWire From(BloomFilter b) =>
                new BloomWire { M = b.MBits, K = b.K, F = b.EstimatedFalsePositiveRate, W = b.Raw };

            internal static BloomFilter ToRuntime(BloomWire w)
            {
                if (w.W is null || w.W.Length == 0 || w.M <= 0) return BloomFilter.Empty();
                return BloomFilter.FromWire(w.M, w.K, w.W, w.F);
            }
        }

        // ==============================
        // HyperLogLog wire (novelty estimator)
        // ==============================

        internal sealed class HllWire
        {
            public byte[] R { get; set; } = Array.Empty<byte>();
            internal static HllWire FromSketch(HllSketch h) => new HllWire { R = h.Export() };
            internal static HllSketch ToRuntime(HllWire w) => w.R is { Length: > 0 } ? HllSketch.FromBytes(w.R) : HllSketch.Create();
        }
    }

    // ==============================
    // Standalone Bloom Filter
    // ==============================

    public sealed class BloomFilter
    {
        private readonly int _m;        // bits
        private readonly int _k;        // hash functions
        private readonly uint[] _bits;  // bitset
        private readonly double _fpr;

        public int MBits => _m;
        public int K => _k;
        public double EstimatedFalsePositiveRate => _fpr;
        public uint[] Raw => _bits;

        private BloomFilter(int mBits, int k, uint[] words, double fpr)
        {
            _m = mBits; _k = k; _bits = words; _fpr = fpr;
        }

        public static BloomFilter Empty() => Create(1024, 0.01);

        public static BloomFilter Create(int capacity, double targetFpr = 0.001)
        {
            capacity = Math.Max(1, capacity);
            targetFpr = Math.Clamp(targetFpr, 1e-6, 0.2);

            // m = - (n * ln f) / (ln 2)^2
            var ln2 = Math.Log(2.0);
            int m = (int)Math.Ceiling(-(capacity * Math.Log(targetFpr)) / (ln2 * ln2));
            // k = (m/n) * ln 2
            int k = Math.Max(1, (int)Math.Round((m / Math.Max(1.0, capacity)) * ln2));
            int words = (m + 31) / 32;
            return new BloomFilter(words * 32, k, new uint[words], Math.Pow(1 - Math.Exp(-k * (capacity / (double)m)), k));
        }

        public static BloomFilter FromWire(int mBits, int k, uint[] words, double fpr)
            => new BloomFilter(mBits, Math.Max(1, k), words ?? Array.Empty<uint>(), fpr);

        public void Add(string s)
        {
            var (h1, h2) = Hash64(s);
            for (int i = 0; i < _k; i++)
            {
                ulong h = h1 + (ulong)i * h2;
                int bit = (int)(h % (ulong)_m);
                _bits[bit >> 5] |= 1u << (bit & 31);
            }
        }

        public bool MightContain(string s)
        {
            var (h1, h2) = Hash64(s);
            for (int i = 0; i < _k; i++)
            {
                ulong h = h1 + (ulong)i * h2;
                int bit = (int)(h % (ulong)_m);
                if (((_bits[bit >> 5] >> (bit & 31)) & 1u) == 0) return false;
            }
            return true;
        }

        private static (ulong, ulong) Hash64(string s)
        {
            Span<byte> bytes = stackalloc byte[32];
            SHA256.HashData(Encoding.UTF8.GetBytes(s), bytes);
            ulong a = BinaryPrimitives.ReadUInt64LittleEndian(bytes[..8]);
            ulong b = BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(8, 8));
            return (a ^ RotR(b, 13) ^ 0x9E3779B97F4A7C15UL, b ^ RotR(a, 7) ^ 0xC2B2AE3D27D4EB4FUL);
        }

        private static ulong RotR(ulong x, int r) => (x >> r) | (x << (64 - r));
    }

    // ==============================
    // Standalone HyperLogLog
    // ==============================

    public sealed class HllSketch
    {
        private readonly byte[] _reg; // m = 1024 registers (p = 10)
        private const int P = 10;
        private const int M = 1 << P;
        private const double Alpha = 0.7213 / (1 + 1.079 / M);

        private HllSketch(byte[] r) { _reg = r; }

        public static HllSketch Create() => new(new byte[M]);

        public static HllSketch FromBytes(byte[] r)
        {
            if (r is null || r.Length != M) return Create();
            return new HllSketch((byte[])r.Clone());
        }

        public byte[] Export() => (byte[])_reg.Clone();

        public void Add(string s)
        {
            Span<byte> h = stackalloc byte[32];
            SHA256.HashData(Encoding.UTF8.GetBytes(s), h); // 32 bytes
            ulong x = BinaryPrimitives.ReadUInt64LittleEndian(h); // first 8B
            int idx = (int)(x & (M - 1));
            ulong w = x >> P;
            byte rho = (byte)(LeadingZerosPlusOne(w));
            if (rho > _reg[idx]) _reg[idx] = rho;
        }

        public double Estimate()
        {
            double sum = 0.0;
            int zeros = 0;
            for (int i = 0; i < M; i++)
            {
                sum += Math.Pow(2.0, -_reg[i]);
                if (_reg[i] == 0) zeros++;
            }
            double raw = Alpha * M * M / sum;
            return zeros != 0 ? M * Math.Log(M / (double)zeros) : raw;
        }

        private static int LeadingZerosPlusOne(ulong x)
        {
            if (x == 0) return 65;
            int n = 1;
            if ((x >> 32) == 0) { n += 32; x <<= 32; }
            if ((x >> 48) == 0) { n += 16; x <<= 16; }
            if ((x >> 56) == 0) { n += 8; x <<= 8; }
            if ((x >> 60) == 0) { n += 4; x <<= 4; }
            if ((x >> 62) == 0) { n += 2; x <<= 2; }
            n -= (int)(x >> 63);
            return n;
        }
    }
}
