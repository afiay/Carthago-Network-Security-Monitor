// File: Services/PortServiceResolver.cs
// SPDX-License-Identifier: MIT

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services
{
    /// <summary>
    /// Port Intelligence Engine:
    /// - Deterministic resolver (IANA + custom) with reverse lookup
    /// - Self-learning inference on non-standard ports using lightweight features (hints)
    /// - Anomaly scoring for policy/detection use-cases
    /// - Cryptographic integrity for snapshot (SHA-256 + Merkle root)
    /// - Adaptive background refresh (conditional GET, jitter, backoff)
    /// </summary>
    public static class PortServiceResolver
    {
        // ===== Public model =====

        public sealed record ServiceInfo(
            int Port,
            string Protocol,                   // TCP/UDP/SCTP/DCCP
            string Name,                       // IANA Service Name (or learned/custom)
            string? Description = null,
            string? Reference = null,
            string? AssignmentNotes = null,
            string Source = "IANA"             // "IANA", "Hardcoded", "Custom", "Learned"
        );

        /// <summary>
        /// Optional L7/L5 hints gathered by your capture pipeline.
        /// All fields are safe to leave null/false; the inferencer uses what it gets.
        /// </summary>
        public sealed record Hints(
            int? Port,
            string? Protocol = null,      // tcp/udp/sctp/dccp
            bool? IsTls = null,           // true if TLS observed
            bool? IsQuic = null,          // true if QUIC observed
            string? Alpn = null,          // e.g., "h2", "http/1.1", "h3", "imap", "smtp"
            string? Banner = null,        // e.g., "SSH-2.0-OpenSSH_9.2", "220 mail.example"
            bool? DnsLike = null,         // short UDP q/a, QR flags etc.
            bool? SipLike = null,         // "SIP/2.0", "INVITE", etc.
            bool? RdpLike = null,         // "Cookie: mstshash=" etc.
            bool? SmtpLike = null,        // lines starting with "220 ", "HELO", "EHLO"
            bool? SshLike = null,         // "SSH-2.0" preface
            bool? HttpLike = null,        // GET/POST/HEAD etc. preface
            string? PrimaryHostOrSni = null // SNI/Host header (domain)
        );

        /// <summary>
        /// Ranked inference result for non-standard ports or weakly-typed flows.
        /// </summary>
        public sealed record InferenceCandidate(string Name, string Protocol, double Probability, string[] Reasons);

        public sealed record Explanation(string Name, string Protocol, string Source, double Confidence, string[] Reasons);

        // ===== Config / paths =====

        private const string IanaCsvUrl =
            "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv";

        private static readonly TimeSpan RefreshInterval = TimeSpan.FromDays(7);
        private static readonly string DataDir = Path.Combine(AppContext.BaseDirectory, "Data", "IANA");
        private static readonly string CsvPath = Path.Combine(DataDir, "service-names-port-numbers.csv");
        private static readonly string SnapshotPath = Path.Combine(DataDir, "port-services.snapshot.json");
        private static readonly string SnapshotShaPath = SnapshotPath + ".sha256";
        private static readonly string SnapshotMerklePath = SnapshotPath + ".merkle";
        private static readonly string LearnedPath = Path.Combine(DataDir, "port-services.learned.json"); // counts

        // ===== HTTP =====

        private static readonly HttpClient Http = new()
        {
            Timeout = TimeSpan.FromSeconds(15)
        };

        // ===== State (atomic snapshot) =====

        private static readonly object _gate = new();
        private static volatile IndexSnapshot _idx = IndexSnapshot.Empty();
        private static int _scheduledRefresh;
        private static long _nextRefreshAttemptTicks;
        private static DateTimeOffset _lastRefresh = DateTimeOffset.MinValue;

        // Lightweight learned frequencies: (port,proto,name) -> count
        // Stored separately to keep deterministic snapshot clean.
        private static volatile Dictionary<(int, string, string), int> _learned = new();

        // ===== Hardcoded minimal fallback =====

        private static readonly Dictionary<int, string> HardcodedMap = new()
        {
            { 22,  "ssh" }, { 25,  "smtp" }, { 53,  "dns" }, { 67,  "dhcp/bootp" },
            { 68,  "dhcp/bootp" }, { 80,  "http" }, { 110, "pop3" }, { 123, "ntp" },
            { 135, "msrpc" }, { 137, "netbios-ns" }, { 138, "netbios-dgm" }, { 139, "netbios-ssn" },
            { 143, "imap" }, { 161, "snmp" }, { 389, "ldap" }, { 443, "https" },
            { 445, "microsoft-ds" }, { 465, "submissions" }, { 587, "submission" }, { 993, "imaps" },
            { 995, "pop3s" }, { 1900, "ssdp" }, { 3306, "mysql" }, { 3389, "ms-wbt-server" },
            { 5060, "sip" }, { 5432, "postgresql" }
        };

        // ===== Public API =====

        /// <summary>
        /// Eager warmup. Optional — lookups will lazily trigger refresh if stale.
        /// </summary>
        public static async Task InitializeAsync(CancellationToken ct = default)
        {
            Directory.CreateDirectory(DataDir);
            TryLoadSnapshot();
            TryLoadLearned();

            if (DateTimeOffset.UtcNow - _lastRefresh >= RefreshInterval || _idx.IsEmpty)
            {
                await RefreshFromIanaAsync(ct).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Deterministic resolve (IANA/custom/learned aliasing) for (port, protocol).
        /// Fast, non-blocking; returns false if truly unknown.
        /// </summary>
        public static bool TryGetServiceInfo(int? port, string? protocol, out ServiceInfo info)
        {
            info = default!;
            if (!ValidatePort(port)) return false;

            MaybeScheduleRefresh();
            var proto = NormalizeProto(protocol);
            var snap = _idx;

            // Exact hit
            if (snap.ByPortProto.TryGetValue((port!.Value, proto), out var s))
            {
                info = s;
                return true;
            }

            // Sibling transport fallback
            var alt = proto == "TCP" ? "UDP" : "TCP";
            if (snap.ByPortProto.TryGetValue((port.Value, alt), out var altInfo))
            {
                info = altInfo with { Protocol = proto, Source = altInfo.Source + " (alt-transport)" };
                return true;
            }

            // Hardcoded minimal snapshot
            if (HardcodedMap.TryGetValue(port.Value, out var name))
            {
                info = new ServiceInfo(port.Value, proto, name, Source: "Hardcoded");
                return true;
            }

            // Ephemeral heuristic
            if (port.Value is >= 49152 and <= 65535)
            {
                info = new ServiceInfo(port.Value, proto, "ephemeral/dynamic", Source: "Heuristic");
                return true;
            }

            return false;
        }

        /// <summary> Convenience: returns a human name (or "Unknown"). </summary>
        public static string GetServiceName(int? port, string? protocol = null)
            => TryGetServiceInfo(port, protocol, out var si) ? si.Name : "Unknown";

        /// <summary>
        /// Returns all known labels for a port across transports (TCP/UDP/SCTP/DCCP).
        /// Includes hardcoded/heuristic when applicable.
        /// </summary>
        public static IEnumerable<ServiceInfo> GetAllServicesForPort(int port)
        {
            if (!ValidatePort(port)) yield break;
            var snap = _idx;

            if (snap.ByPortProto.TryGetValue((port, "TCP"), out var tcp)) yield return tcp;
            if (snap.ByPortProto.TryGetValue((port, "UDP"), out var udp)) yield return udp;
            if (snap.ByPortProto.TryGetValue((port, "SCTP"), out var sctp)) yield return sctp;
            if (snap.ByPortProto.TryGetValue((port, "DCCP"), out var dccp)) yield return dccp;

            if (HardcodedMap.TryGetValue(port, out var hc))
                yield return new ServiceInfo(port, "TCP", hc, Source: "Hardcoded");
        }

        /// <summary>
        /// Reverse lookup: (port, protocol) pairs for a service name (case-insensitive).
        /// </summary>
        public static IReadOnlyList<(int Port, string Protocol)> GetPortsForService(string serviceName)
        {
            if (string.IsNullOrWhiteSpace(serviceName)) return Array.Empty<(int, string)>();
            var snap = _idx;
            return snap.ByName.TryGetValue(CanonName(serviceName), out var list)
                ? list.AsReadOnly()
                : Array.Empty<(int, string)>();
        }

        /// <summary>
        /// Add or override a mapping at runtime (e.g., internal conventions).
        /// </summary>
        public static void AddCustomMapping(int port, string protocol, string name, string? description = null, bool overrideExisting = false)
        {
            if (!ValidatePort(port)) return;
            var proto = NormalizeProto(protocol);
            var nm = name?.Trim();
            if (string.IsNullOrEmpty(nm)) return;

            lock (_gate)
            {
                var cur = _idx.CloneMutable();
                var key = (port, proto);
                if (!overrideExisting && cur.ByPortProto.ContainsKey(key))
                    return;

                var info = new ServiceInfo(port, proto, nm, description, Source: "Custom");
                cur.ByPortProto[key] = info;

                var cname = CanonName(nm);
                if (!cur.ByName.TryGetValue(cname, out var vec))
                {
                    vec = new List<(int, string)>(2);
                    cur.ByName[cname] = vec;
                }
                if (!vec.Contains(key)) vec.Add(key);

                _idx = cur.Freeze();
                PersistSnapshotUnsafe();
            }
        }

        /// <summary> Add an alias for an existing service name (e.g., "mail" → "smtp"). </summary>
        public static void AddAlias(string existingServiceName, string alias)
        {
            if (string.IsNullOrWhiteSpace(existingServiceName) || string.IsNullOrWhiteSpace(alias)) return;
            var snap = _idx;
            var srcCanon = CanonName(existingServiceName);
            if (!snap.ByName.TryGetValue(srcCanon, out var entries)) return;

            lock (_gate)
            {
                var cur = _idx.CloneMutable();
                cur.ByName[CanonName(alias)] = new List<(int, string)>(entries);
                _idx = cur.Freeze();
                PersistSnapshotUnsafe();
            }
        }

        /// <summary> Last time we refreshed from IANA (or loaded snapshot). </summary>
        public static DateTimeOffset LastUpdatedUtc => _lastRefresh;

        // ======= New: Explanations, Inference & Learning =======

        /// <summary>
        /// Human-readable explanation of what we think runs on (port, proto) and why (sources, confidence).
        /// </summary>
        public static Explanation Explain(int port, string protocol)
        {
            var proto = NormalizeProto(protocol);
            var reasons = new List<string>();
            if (TryGetServiceInfo(port, proto, out var si))
            {
                reasons.Add($"Match in index: {si.Source}");
                if (si.Reference is not null) reasons.Add($"Reference: {si.Reference}");
                if (si.AssignmentNotes is not null) reasons.Add("IANA notes present");
                return new Explanation(si.Name, si.Protocol, si.Source, ConfidenceForSource(si.Source), reasons.ToArray());
            }

            if (HardcodedMap.ContainsKey(port)) reasons.Add("Hardcoded fallback");
            if (port is >= 49152 and <= 65535) reasons.Add("Port in ephemeral range");
            return new Explanation("unknown", proto, "None", 0.15, reasons.ToArray());
        }

        /// <summary>
        /// Score how anomalous a (port, proto, name?) mapping is for your environment (0..1).
        /// - High score means "we rarely/never see this" or "conflicts with known standards".
        /// - If observedName is null, we score the port/proto only.
        /// </summary>
        public static double GetAnomalyScore(int port, string protocol, string? observedName = null)
        {
            var proto = NormalizeProto(protocol);
            var baseScore = 0.0;

            // Standard mapping? Lower anomaly
            if (TryGetServiceInfo(port, proto, out var standard))
            {
                if (observedName is null || CanonName(observedName) == CanonName(standard.Name))
                    return 0.05; // expected
                baseScore += 0.35; // name conflicts with standard on that port
            }
            else
            {
                baseScore += 0.25; // unknown port/proto
            }

            // Learned frequencies decrease anomaly
            var learnedWeight = 0.0;
            var l = _learned;
            if (observedName is not null)
            {
                var key = (port, proto, CanonName(observedName));
                if (l.TryGetValue(key, out var c) && c > 0)
                    learnedWeight = Math.Min(0.35, Math.Log10(c + 1) / 5.0);
            }
            else
            {
                // Any known name on that port? consider a small reduction
                var any = l.Keys.Any(k => k.Item1 == port && k.Item2 == proto);
                if (any) learnedWeight = 0.1;
            }

            // Ephemeral ports increase anomaly slightly for named services
            if (observedName is not null && port is >= 49152 and <= 65535) baseScore += 0.15;

            // Clamp & combine
            var score = Math.Clamp(baseScore - learnedWeight, 0, 1);
            // Smooth a bit
            return 1 - Math.Pow(1 - score, 1.2);
        }

        /// <summary>
        /// Learn a ground-truth mapping from your pipeline (e.g., DPI classified smtp on tcp/2525).
        /// This strengthens future inference and reduces anomaly scores accordingly.
        /// </summary>
        public static void LearnObservation(Hints hints, string serviceName, int weight = 1)
        {
            if (hints is null || hints.Port is null) return;
            var p = hints.Port.Value;
            if (!ValidatePort(p)) return;

            var proto = NormalizeProto(hints.Protocol);
            var name = CanonName(serviceName);

            lock (_gate)
            {
                if (_learned.Count == 0) _learned = new();
                var key = (p, proto, name);
                _learned.TryGetValue(key, out var c);
                _learned[key] = Math.Min(c + Math.Max(1, weight), 1_000_000);
                PersistLearnedUnsafe();
            }
        }

        /// <summary>
        /// Given Hints (even on a non-standard port), return top candidates with probabilities and reasons.
        /// </summary>
        public static IReadOnlyList<InferenceCandidate> InferService(Hints hints, int topK = 5)
        {
            var p = hints.Port ?? 0;
            var proto = NormalizeProto(hints.Protocol);
            var scores = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase); // name -> score
            var reasons = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

            void Bump(string name, double s, string why)
            {
                if (!scores.TryGetValue(name, out var cur)) cur = 0;
                scores[name] = cur + s;
                if (!reasons.TryGetValue(name, out var r)) { r = new List<string>(); reasons[name] = r; }
                r.Add(why);
            }

            // Priors from deterministic resolver (if we have an IANA/custom hit)
            if (TryGetServiceInfo(p, proto, out var si))
            {
                var baseName = CanonName(si.Name);
                Bump(baseName, 3.0, $"IANA/custom mapping for {p}/{proto}");
            }
            else if (HardcodedMap.TryGetValue(p, out var hc))
            {
                Bump(CanonName(hc), 2.0, $"Hardcoded prior for {p}/{proto}");
            }

            // Banner & specific indicators
            if (True(hints.SshLike) || (hints.Banner?.StartsWith("SSH-", StringComparison.OrdinalIgnoreCase) ?? false))
                Bump("ssh", 5.0, "SSH banner");
            if (True(hints.SmtpLike) || (hints.Banner?.StartsWith("220 ", StringComparison.Ordinal) ?? false))
                Bump("smtp", 4.0, "SMTP greeting");
            if (True(hints.RdpLike))
                Bump("ms-wbt-server", 4.0, "RDP cookie");
            if (True(hints.SipLike))
                Bump("sip", 3.0, "SIP markers");
            if (True(hints.DnsLike))
                Bump("dns", 3.0, "DNS shape");
            if (True(hints.HttpLike))
                Bump(True(hints.IsTls) ? "https" : "http", 3.0, "HTTP verbs");

            // ALPN priors
            var alpn = hints.Alpn?.ToLowerInvariant();
            if (!string.IsNullOrEmpty(alpn))
            {
                if (alpn.Contains("h3")) Bump("https", 3.0, "ALPN:h3 (HTTP/3)");
                if (alpn.Contains("h2")) Bump("https", 2.5, "ALPN:h2 (HTTP/2)");
                if (alpn.Contains("http/1.1")) Bump(True(hints.IsTls) ? "https" : "http", 2.0, "ALPN:http/1.1");
                if (alpn.Contains("imap")) Bump(True(hints.IsTls) ? "imaps" : "imap", 2.0, "ALPN:imap");
                if (alpn.Contains("smtp")) Bump(True(hints.IsTls) ? "submissions" : "smtp", 2.0, "ALPN:smtp");
                if (alpn.Contains("pop3")) Bump(True(hints.IsTls) ? "pop3s" : "pop3", 2.0, "ALPN:pop3");
            }

            // QUIC/TLS signals
            if (True(hints.IsQuic)) Bump("https", 2.5, "QUIC observed");
            if (True(hints.IsTls) && (hints.PrimaryHostOrSni?.Length > 0))
                Bump("https", 0.75, "SNI present over TLS");

            // Learned frequencies (environment-specific)
            var learned = _learned;
            if (p > 0)
            {
                foreach (var kv in learned)
                {
                    if (kv.Key.Item1 == p && string.Equals(kv.Key.Item2, proto, StringComparison.Ordinal))
                    {
                        // log scaling avoids domination
                        Bump(kv.Key.Item3, Math.Min(3.0, Math.Log10(kv.Value + 1)), $"learned freq {kv.Value} for {p}/{proto}");
                    }
                }
            }

            // Convert to probabilities via softmax
            if (scores.Count == 0)
                return Array.Empty<InferenceCandidate>();

            var max = scores.Values.Max();
            double sum = 0;
            var exps = new Dictionary<string, double>(scores.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var (k, v) in scores)
            {
                var e = Math.Exp(v - max);
                exps[k] = e;
                sum += e;
            }

            var ranked = exps
                .Select(kv => new InferenceCandidate(
                    Name: kv.Key,
                    Protocol: proto,
                    Probability: kv.Value / sum,
                    Reasons: reasons.TryGetValue(kv.Key, out var rs) ? rs.ToArray() : Array.Empty<string>()))
                .OrderByDescending(c => c.Probability)
                .Take(Math.Max(1, Math.Min(10, topK)))
                .ToList();

            return ranked;
        }

        // ===== Refresh plumbing =====

        private static void MaybeScheduleRefresh()
        {
            if (DateTimeOffset.UtcNow - _lastRefresh < RefreshInterval) return;
            if (DateTime.UtcNow.Ticks < Interlocked.Read(ref _nextRefreshAttemptTicks)) return;
            if (Interlocked.CompareExchange(ref _scheduledRefresh, 1, 0) != 0) return;

            // add jittered backoff if fetch fails repeatedly
            _ = Task.Run(async () =>
            {
                try
                {
                    int attempt = 0;
                    while (true)
                    {
                        try
                        {
                            await RefreshFromIanaAsync().ConfigureAwait(false);
                            Interlocked.Exchange(ref _nextRefreshAttemptTicks, 0);
                            break;
                        }
                        catch (Exception ex)
                        {
                            attempt++;
                            Interlocked.Exchange(ref _nextRefreshAttemptTicks,
                                DateTime.UtcNow.Add(PortRefreshRetryPolicy.FailureCooldown(ex)).Ticks);
                            Console.Error.WriteLine($"[PortServiceResolver] Background refresh attempt {attempt} failed: {ex.Message}");
                            if (!PortRefreshRetryPolicy.ShouldRetry(ex, attempt)) break;

                            await Task.Delay(PortRefreshRetryPolicy.RetryDelay(attempt)
                                + TimeSpan.FromSeconds(Random.Shared.Next(0, 5))).ConfigureAwait(false);
                        }
                    }
                }
                finally
                {
                    Interlocked.Exchange(ref _scheduledRefresh, 0);
                }
            });
        }

        private static async Task RefreshFromIanaAsync(CancellationToken ct = default)
        {
            Directory.CreateDirectory(DataDir);

            using var req = new HttpRequestMessage(HttpMethod.Get, IanaCsvUrl);
            if (File.Exists(CsvPath))
            {
                var last = File.GetLastWriteTimeUtc(CsvPath);
                if (last.Year > 2000) req.Headers.IfModifiedSince = new DateTimeOffset(last);
            }

            using var resp = await Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (resp.StatusCode == HttpStatusCode.NotModified)
            {
                var csv = await File.ReadAllTextAsync(CsvPath, ct).ConfigureAwait(false);
                RebuildFromCsv(csv);
                _lastRefresh = File.GetLastWriteTimeUtc(CsvPath);
                PersistSnapshotUnsafe();
                return;
            }

            resp.EnsureSuccessStatusCode();
            var csvText = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            await File.WriteAllTextAsync(CsvPath, csvText, ct).ConfigureAwait(false);
            RebuildFromCsv(csvText);
            _lastRefresh = resp.Content.Headers.LastModified?.UtcDateTime ?? DateTimeOffset.UtcNow;
            File.SetLastWriteTimeUtc(CsvPath, _lastRefresh.UtcDateTime);
            PersistSnapshotUnsafe();
        }

        private static void RebuildFromCsv(string csv)
        {
            var byPortProto = new Dictionary<(int, string), ServiceInfo>(capacity: 48_000);
            var byName = new Dictionary<string, List<(int, string)>>(StringComparer.OrdinalIgnoreCase);

            using var sr = new StringReader(csv);

            // Parse header → column indices (robust to reordering)
            var headerLine = ReadCsvRecord(sr);
            if (headerLine is null) return;
            var header = CsvSplit(headerLine.AsSpan());
            int idxService = IndexOfHeader(header, "Service Name");
            int idxPort = IndexOfHeader(header, "Port Number");
            int idxProto = IndexOfHeader(header, "Transport Protocol");
            int idxDesc = IndexOfHeader(header, "Description");
            int idxRef = IndexOfHeader(header, "Reference");
            int idxNotes = IndexOfHeader(header, "Assignment Notes");

            // Iterate records
            string? rec;
            while ((rec = ReadCsvRecord(sr)) is not null)
            {
                var fields = CsvSplit(rec.AsSpan());

                string name = SafeField(fields, idxService);
                string portExpr = SafeField(fields, idxPort);
                string proto = NormalizeProto(SafeField(fields, idxProto));
                string desc = SafeField(fields, idxDesc);
                string reference = SafeField(fields, idxRef);
                string notes = SafeField(fields, idxNotes);

                if (string.IsNullOrWhiteSpace(name)) continue;
                if (string.IsNullOrWhiteSpace(portExpr)) continue;
                if (string.IsNullOrWhiteSpace(proto)) continue;

                if (!TryExpandPortExpression(portExpr, out var ports)) continue;

                foreach (var p in ports)
                {
                    var key = (p, proto);
                    // first hit wins (IANA has duplicates/aliases)
                    if (byPortProto.ContainsKey(key)) continue;

                    var info = new ServiceInfo(p, proto, CanonName(name), desc.NullIfEmpty(), reference.NullIfEmpty(), notes.NullIfEmpty(), "IANA");
                    byPortProto[key] = info;

                    var cname = CanonName(name);
                    if (!byName.TryGetValue(cname, out var vec))
                    {
                        vec = new List<(int, string)>(2);
                        byName[cname] = vec;
                    }
                    vec.Add(key);
                }
            }

            lock (_gate)
            {
                _idx = new IndexSnapshot(byPortProto, byName);
            }
        }

        // ===== Persistence: snapshot + integrity + learned =====

        private static void TryLoadSnapshot()
        {
            try
            {
                if (!File.Exists(SnapshotPath)) return;
                if (!VerifySnapshotIntegrity()) { /* leave file; skip load */ return; }

                var json = File.ReadAllText(SnapshotPath);
                var snap = JsonSerializer.Deserialize<SnapshotWire>(json);
                if (snap is null || snap.Entries is null) return;

                var byPortProto = new Dictionary<(int, string), ServiceInfo>(snap.Entries.Count);
                var byName = new Dictionary<string, List<(int, string)>>(StringComparer.OrdinalIgnoreCase);

                foreach (var e in snap.Entries)
                {
                    var proto = NormalizeProto(e.Protocol);
                    var key = (e.Port, proto);
                    var info = new ServiceInfo(e.Port, proto, CanonName(e.Name), e.Description, e.Reference, e.Notes, e.Source ?? "IANA");
                    byPortProto[key] = info;

                    var cname = CanonName(e.Name);
                    if (!byName.TryGetValue(cname, out var vec))
                    {
                        vec = new List<(int, string)>(2);
                        byName[cname] = vec;
                    }
                    vec.Add(key);
                }

                lock (_gate)
                {
                    _idx = new IndexSnapshot(byPortProto, byName);
                    _lastRefresh = snap.LastUpdatedUtc == default ? DateTimeOffset.UtcNow : snap.LastUpdatedUtc;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[PortServiceResolver] Snapshot load failed: {ex.Message}");
            }
        }

        private static void PersistSnapshotUnsafe()
        {
            try
            {
                var snap = _idx;
                var list = new List<EntryWire>(snap.ByPortProto.Count);
                foreach (var kv in snap.ByPortProto)
                {
                    var v = kv.Value;
                    list.Add(new EntryWire
                    {
                        Port = v.Port,
                        Protocol = v.Protocol,
                        Name = v.Name,
                        Description = v.Description,
                        Reference = v.Reference,
                        Notes = v.AssignmentNotes,
                        Source = v.Source
                    });
                }

                var wire = new SnapshotWire
                {
                    Version = 2,
                    LastUpdatedUtc = _lastRefresh,
                    Entries = list
                };

                var json = JsonSerializer.Serialize(wire, new JsonSerializerOptions { WriteIndented = false });
                File.WriteAllText(SnapshotPath, json);

                // Write SHA-256 and Merkle root for integrity
                var hash = SHA256.HashData(Encoding.UTF8.GetBytes(json));
                File.WriteAllText(SnapshotShaPath, Convert.ToHexString(hash));
                var merkle = ComputeMerkleRoot(list.Select(e => $"{e.Port}/{e.Protocol}:{e.Name}"));
                File.WriteAllText(SnapshotMerklePath, merkle);
            }
            catch
            {
                // ignore persistence errors
            }
        }

        /// <summary>
        /// Verify snapshot integrity by both SHA-256 (whole file) and a Merkle root over sorted entries.
        /// </summary>
        public static bool VerifySnapshotIntegrity()
        {
            try
            {
                if (!File.Exists(SnapshotPath) || !File.Exists(SnapshotShaPath) || !File.Exists(SnapshotMerklePath))
                    return false;

                var json = File.ReadAllText(SnapshotPath);
                var expectSha = File.ReadAllText(SnapshotShaPath).Trim();
                var haveSha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))).Trim();
                if (!haveSha.Equals(expectSha, StringComparison.OrdinalIgnoreCase)) return false;

                var sw = JsonSerializer.Deserialize<SnapshotWire>(json);
                if (sw?.Entries is null) return false;
                var merkle = ComputeMerkleRoot(sw.Entries.Select(e => $"{e.Port}/{e.Protocol}:{e.Name}"));
                var expectMerkle = File.ReadAllText(SnapshotMerklePath).Trim();
                return merkle.Equals(expectMerkle, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        private static string ComputeMerkleRoot(IEnumerable<string> items)
        {
            // Deterministic ordering, pairwise hashing to one root
            var hashes = items
                .Select(s => SHA256.HashData(Encoding.UTF8.GetBytes(s)))
                .OrderBy(h => Convert.ToHexString(h), StringComparer.Ordinal)
                .Select(h => h.AsSpan().ToArray())
                .ToList();

            if (hashes.Count == 0) return Convert.ToHexString(SHA256.HashData(Array.Empty<byte>()));

            while (hashes.Count > 1)
            {
                var next = new List<byte[]>(hashes.Count / 2 + 1);
                for (int i = 0; i < hashes.Count; i += 2)
                {
                    if (i + 1 < hashes.Count)
                    {
                        var cat = new byte[hashes[i].Length + hashes[i + 1].Length];
                        Buffer.BlockCopy(hashes[i], 0, cat, 0, hashes[i].Length);
                        Buffer.BlockCopy(hashes[i + 1], 0, cat, hashes[i].Length, hashes[i + 1].Length);
                        next.Add(SHA256.HashData(cat));
                    }
                    else
                    {
                        // carry last up
                        next.Add(hashes[i]);
                    }
                }
                hashes = next;
            }

            return Convert.ToHexString(hashes[0]);
        }

        private static void TryLoadLearned()
        {
            try
            {
                if (!File.Exists(LearnedPath)) { _learned = new(); return; }
                var json = File.ReadAllText(LearnedPath);
                var wire = JsonSerializer.Deserialize<List<LearnedWire>>(json) ?? new();
                var dict = new Dictionary<(int, string, string), int>();
                foreach (var e in wire)
                {
                    dict[(e.Port, NormalizeProto(e.Protocol), CanonName(e.Name))] = Math.Clamp(e.Count, 1, 1_000_000);
                }
                _learned = dict;
            }
            catch
            {
                _learned = new();
            }
        }

        private static void PersistLearnedUnsafe()
        {
            try
            {
                var list = new List<LearnedWire>(_learned.Count);
                foreach (var kv in _learned)
                {
                    list.Add(new LearnedWire
                    {
                        Port = kv.Key.Item1,
                        Protocol = kv.Key.Item2,
                        Name = kv.Key.Item3,
                        Count = kv.Value
                    });
                }
                var json = JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = false });
                File.WriteAllText(LearnedPath, json);
            }
            catch { /* ignore */ }
        }

        // ===== Helpers =====

        private static bool ValidatePort(int? port) => port is >= 1 and <= 65535;
        private static bool ValidatePort(int port) => port is >= 1 and <= 65535;
        private static bool True(bool? b) => b.HasValue && b.Value;

        private static string NormalizeProto(string? p)
        {
            p = (p ?? "TCP").Trim().ToUpperInvariant();
            return p switch
            {
                "TCP" or "UDP" or "SCTP" or "DCCP" => p,
                _ => "TCP"
            };
        }

        private static string CanonName(string s) => s.Trim().ToLowerInvariant();

        private static double ConfidenceForSource(string src)
        {
            if (src.StartsWith("IANA", StringComparison.OrdinalIgnoreCase)) return 0.98;
            if (src.StartsWith("Custom", StringComparison.OrdinalIgnoreCase)) return 0.9;
            if (src.StartsWith("Hardcoded", StringComparison.OrdinalIgnoreCase)) return 0.75;
            return 0.6;
        }

        private static string SafeField(List<string> fields, int idx)
            => (idx >= 0 && idx < fields.Count) ? fields[idx] : string.Empty;

        private static int IndexOfHeader(List<string> header, string name)
        {
            for (int i = 0; i < header.Count; i++)
            {
                if (string.Equals(header[i]?.Trim(), name, StringComparison.OrdinalIgnoreCase))
                    return i;
            }
            return -1;
        }

        private static bool TryExpandPortExpression(string text, out IEnumerable<int> ports)
        {
            ports = Array.Empty<int>();
            if (string.IsNullOrWhiteSpace(text)) return false;
            text = text.Trim();

            // Single number
            if (int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var single)
                && single is >= 1 and <= 65535)
            {
                ports = new[] { single };
                return true;
            }

            // Range: "6000-6063"
            var dash = text.IndexOf('-');
            if (dash > 0 &&
                int.TryParse(text.AsSpan(0, dash), NumberStyles.Integer, CultureInfo.InvariantCulture, out var start) &&
                int.TryParse(text.AsSpan(dash + 1), NumberStyles.Integer, CultureInfo.InvariantCulture, out var end) &&
                start >= 1 && end >= start && end <= 65535)
            {
                var list = new List<int>(end - start + 1);
                for (int p = start; p <= end; p++) list.Add(p);
                ports = list;
                return true;
            }

            // Sometimes: "123 ; 456" or "123  (deprecated)" → take first integer token
            foreach (var token in text.Split(new[] { ';', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) && n is >= 1 and <= 65535)
                {
                    ports = new[] { n };
                    return true;
                }
            }

            return false;
        }

        // RFC4180 CSV splitter that supports quotes, escaped quotes, commas & newlines.
        private static List<string> CsvSplit(ReadOnlySpan<char> line)
        {
            var fields = new List<string>(12);
            var sb = new StringBuilder(line.Length);
            bool inQuotes = false;

            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];

                if (c == '"')
                {
                    if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                    { sb.Append('"'); i++; }
                    else { inQuotes = !inQuotes; }
                }
                else if (c == ',' && !inQuotes)
                {
                    fields.Add(sb.ToString());
                    sb.Clear();
                }
                else
                {
                    sb.Append(c);
                }
            }
            fields.Add(sb.ToString());
            return fields;
        }

        private static string? ReadCsvRecord(StringReader sr)
        {
            string? line = sr.ReadLine();
            if (line is null) return null;

            int quotes = CountQuotes(line);
            if ((quotes & 1) == 0) return line;

            var sb = new StringBuilder(line);
            while (true)
            {
                var next = sr.ReadLine();
                if (next is null) break;
                sb.Append('\n').Append(next);
                quotes += CountQuotes(next);
                if ((quotes & 1) == 0) break;
            }
            return sb.ToString();
        }

        private static int CountQuotes(string s)
        {
            int n = 0; foreach (var ch in s) if (ch == '"') n++; return n;
        }

        // ===== Snapshot wire model =====

        private sealed class SnapshotWire
        {
            public int Version { get; set; }
            public DateTimeOffset LastUpdatedUtc { get; set; }
            public List<EntryWire>? Entries { get; set; }
        }

        private sealed class EntryWire
        {
            public int Port { get; set; }
            public string Protocol { get; set; } = "TCP";
            public string Name { get; set; } = "";
            public string? Description { get; set; }
            public string? Reference { get; set; }
            public string? Notes { get; set; }
            public string? Source { get; set; }
        }

        private sealed class LearnedWire
        {
            public int Port { get; set; }
            public string Protocol { get; set; } = "TCP";
            public string Name { get; set; } = "";
            public int Count { get; set; }
        }

        // ===== In-memory index (immutable) =====

        private sealed class IndexSnapshot
        {
            public readonly Dictionary<(int, string), ServiceInfo> ByPortProto;
            public readonly Dictionary<string, List<(int, string)>> ByName;

            public bool IsEmpty => ByPortProto.Count == 0;

            public IndexSnapshot(Dictionary<(int, string), ServiceInfo> byPortProto, Dictionary<string, List<(int, string)>> byName)
            {
                ByPortProto = byPortProto;
                ByName = byName;
            }

            public static IndexSnapshot Empty() =>
                new(new Dictionary<(int, string), ServiceInfo>(), new Dictionary<string, List<(int, string)>>(StringComparer.OrdinalIgnoreCase));

            public MutableIndex CloneMutable()
            {
                var a = new Dictionary<(int, string), ServiceInfo>(ByPortProto);
                var b = new Dictionary<string, List<(int, string)>>(ByName.Comparer);
                foreach (var kv in ByName)
                    b[kv.Key] = new List<(int, string)>(kv.Value);
                return new MutableIndex(a, b);
            }

            public IndexSnapshot Freeze() => this;

            public sealed class MutableIndex
            {
                public Dictionary<(int, string), ServiceInfo> ByPortProto;
                public Dictionary<string, List<(int, string)>> ByName;

                public MutableIndex(Dictionary<(int, string), ServiceInfo> a, Dictionary<string, List<(int, string)>> b)
                { ByPortProto = a; ByName = b; }

                public IndexSnapshot Freeze() => new(ByPortProto, ByName);
            }
        }
    }

    internal static class _StringExt
    {
        public static string? NullIfEmpty(this string s) => string.IsNullOrWhiteSpace(s) ? null : s;
    }
}
