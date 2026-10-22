// SPDX-License-Identifier: MIT
// File: Engine/AllowListLearner.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using Carthago.Models;

namespace Carthago.Services
{
    /// <summary>
    /// Online learner that "baselines" ports that are common/legit in THIS environment.
    /// - Evidence is per (port, proto) across many internal sources and destinations.
    /// - Uses EWMA-like scoring + sliding recent sets + decay and cooldown after bad signals.
    /// - Persists compact JSON to disk; auto-saves periodically; bounded memory.
    /// - Designed to be consulted by R013 (Uncommon ports) before alerting.
    /// 
    /// Poisoning resistance:
    ///   * Learn only when source is internal (private IP).
    ///   * Require multiple distinct internal sources AND multiple distinct destinations.
    ///   * Any high/critical detection tied to the port puts it in cooldown (not-allowed) for N days.
    ///   * Ignore classic admin/security-sensitive ports completely (AuthPorts etc.) – R013 can still alert on them.
    /// </summary>
    public static class AllowListLearner
    {
        // ======== Public API ========
        public static void Initialize(LearnerConfig? config = null)
        {
            _cfg = config ?? new LearnerConfig();
            Directory.CreateDirectory(Path.GetDirectoryName(_cfg.StoragePath)!);
            Load();
            _persistTimer = new Timer(_ => Save(), null,
                dueTime: TimeSpan.FromSeconds(30),
                period: TimeSpan.FromSeconds(60));
        }

        public static void Shutdown()
        {
            try { Save(); } catch { /* best effort */ }
            _persistTimer?.Dispose();
        }

        /// <summary>Observe a packet/flow. Call once per record (cheap).</summary>
        public static void Observe(DateTime now, TrafficRecord r)
        {
            if (!r.DestinationPort.HasValue) return;
            int port = r.DestinationPort.Value;
            string proto = NormalizeProto(r.Protocol);

            // Gate: learn only non-admin, high ports, internal sources
            if (port <= 1024) return;
            if (IsSensitivePort(port)) return;
            if (string.IsNullOrWhiteSpace(r.Source) || !IsPrivateIp(r.Source)) return;

            // (Optional) prefer UDP banner/service presence, or TCP SYN as "new service" signal
            bool isTcp = string.Equals(proto, "TCP", StringComparison.OrdinalIgnoreCase);
            bool syn = isTcp && (r.Flags?.Contains("SYN") == true);
            bool udpLikelyService = !isTcp && (!string.IsNullOrWhiteSpace(r.ApplicationService) || r.Length > 0);
            if (!(syn || udpLikelyService)) return;

            var key = (port, proto);
            var s = _ports.GetOrAdd(key, _ => new PortStats(now));

            // Bounded distinct sets — keep only "recent" (LastDistinctHorizonMinutes)
            if (!string.IsNullOrWhiteSpace(r.Source))
                s.Sources[r.Source] = now;
            if (!string.IsNullOrWhiteSpace(r.Destination) && IsPrivateIp(r.Destination))
                s.Dests[r.Destination] = now;

            PruneOld(s.Sources, now, _cfg.LastDistinctHorizonMinutes);
            PruneOld(s.Dests, now, _cfg.LastDistinctHorizonMinutes);

            // EWMA-ish: one "unit" per qualifying observation
            double alpha = _cfg.EwmaAlphaPerEvent; // small
            s.Score = (1 - alpha) * s.Score + alpha * 1.0;

            s.LastSeen = now;
            s.ObsCount = Math.Min(s.ObsCount + 1, int.MaxValue);

            // Evict oldest keys globally if necessary (bounded memory)
            if (_ports.Count > _cfg.MaxKeys) EvictOld(now);
        }

        /// <summary>
        /// Penalize a port when a strong signal fires (e.g., threat-feed hit, reputation, etc.).
        /// Call from detectors for HIGH/CRITICAL events tied to this (port, proto).
        /// </summary>
        public static void MarkBad(int port, string? proto, DateTime now, string reason = "bad")
        {
            if (string.IsNullOrWhiteSpace(proto)) return;
            var key = (port, NormalizeProto(proto));
            var s = _ports.GetOrAdd(key, _ => new PortStats(now));
            s.LastBadSeen = now;
            s.BadCount = Math.Min(s.BadCount + 1, int.MaxValue);
            // Strongly nudge score down
            s.Score *= 0.25;
        }

        /// <summary>
        /// Core decision used by R013: is this (port, proto) considered "allowed/noisy-but-legit"?
        /// </summary>
        public static bool IsAllowed(int port, string? proto, DateTime now)
        {
            if (string.IsNullOrWhiteSpace(proto)) return false;
            if (port <= 1024) return false;
            if (IsSensitivePort(port)) return false;

            if (!_ports.TryGetValue((port, NormalizeProto(proto)), out var s))
                return false;

            // Cooldown after any bad signal
            if (s.LastBadSeen.HasValue && (now - s.LastBadSeen.Value).TotalDays < _cfg.CooldownAfterBadDays)
                return false;

            // Age out long-unseen ports
            if ((now - s.LastSeen).TotalDays > _cfg.ForgetAfterDays) return false;

            // Current “evidence”
            int srcs = CountRecent(s.Sources, now, _cfg.LastDistinctHorizonMinutes);
            int dsts = CountRecent(s.Dests, now, _cfg.LastDistinctHorizonMinutes);

            return s.Score >= _cfg.MinEwmaScore
                && srcs >= _cfg.MinDistinctSources
                && dsts >= _cfg.MinDistinctDests;
        }

        // ======== Implementation ========

        private static readonly HashSet<int> _sensitive = new() {
            // Classic admin & infra ports we never "learn away" for R013
            22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 445, 465, 587, 593, 636, 993, 995, 1433, 1521, 3306, 3389, 5900, 5985, 5986
        };

        private static bool IsSensitivePort(int p) => _sensitive.Contains(p);

        private static string NormalizeProto(string? p) =>
            string.IsNullOrWhiteSpace(p) ? "TCP" : p.Trim().ToUpperInvariant();

        private static bool IsPrivateIp(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            if (!System.Net.IPAddress.TryParse(ip.Trim(), out var addr)) return false;
            if (System.Net.IPAddress.IsLoopback(addr)) return true;

            var family = addr.AddressFamily;
            if (family == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var b = addr.GetAddressBytes();
                // 10.0.0.0/8
                if (b[0] == 10) return true;
                // 172.16.0.0/12
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
                // 192.168.0.0/16
                if (b[0] == 192 && b[1] == 168) return true;
                return false;
            }
            else if (family == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                var b = addr.GetAddressBytes();
                // fc00::/7 (Unique Local Addresses)
                if ((b[0] & 0xFE) == 0xFC) return true;
                return false;
            }

            return false;
        }

        private static int CountRecent(ConcurrentDictionary<string, DateTime> map, DateTime now, int minutes)
        {
            var cutoff = now.AddMinutes(-minutes);
            int c = 0;
            foreach (var kv in map)
                if (kv.Value >= cutoff) c++;
            return c;
        }

        private static void PruneOld(ConcurrentDictionary<string, DateTime> map, DateTime now, int minutes)
        {
            var cutoff = now.AddMinutes(-minutes);
            foreach (var kv in map)
                if (kv.Value < cutoff) map.TryRemove(kv.Key, out _);
        }

        private static void EvictOld(DateTime now)
        {
            var cutoff = now.AddDays(-_cfg.ForgetAfterDays);
            foreach (var kv in _ports)
            {
                if (kv.Value.LastSeen < cutoff)
                    _ports.TryRemove(kv.Key, out _);
            }
        }

        private static void Load()
        {
            try
            {
                if (!File.Exists(_cfg.StoragePath)) return;
                var json = File.ReadAllText(_cfg.StoragePath);
                var disk = JsonSerializer.Deserialize<List<DiskRow>>(json) ?? new();
                _ports.Clear();
                foreach (var d in disk)
                {
                    var s = new PortStats(d.LastSeen)
                    {
                        Score = d.Score,
                        ObsCount = d.ObsCount,
                        LastBadSeen = d.LastBadSeen
                    };
                    foreach (var k in d.Sources) s.Sources[k] = d.LastSeen;
                    foreach (var k in d.Dests) s.Dests[k] = d.LastSeen;
                    _ports[(d.Port, d.Proto)] = s;
                }
            }
            catch { /* best effort */ }
        }

        private static void Save()
        {
            try
            {
                var now = DateTime.UtcNow;
                var cut = now.AddDays(-_cfg.ForgetAfterDays);
                var disk = _ports
                    .Where(kv => kv.Value.LastSeen >= cut)
                    .Select(kv =>
                    {
                        var (port, proto) = kv.Key;
                        var s = kv.Value;
                        return new DiskRow
                        {
                            Port = port,
                            Proto = proto,
                            Score = s.Score,
                            ObsCount = s.ObsCount,
                            LastSeen = s.LastSeen,
                            LastBadSeen = s.LastBadSeen,
                            Sources = s.Sources.Keys.Take(_cfg.MaxStoredPeers).ToList(),
                            Dests = s.Dests.Keys.Take(_cfg.MaxStoredPeers).ToList()
                        };
                    })
                    .ToList();

                var json = JsonSerializer.Serialize(disk, new JsonSerializerOptions { WriteIndented = false });
                File.WriteAllText(_cfg.StoragePath, json);
            }
            catch { /* best effort */ }
        }

        // ======== State ========
        private static LearnerConfig _cfg = new();
        private static readonly ConcurrentDictionary<(int Port, string Proto), PortStats> _ports = new();
        private static Timer? _persistTimer;

        // ======== Models ========
        public sealed class LearnerConfig
        {
            public string StoragePath { get; set; } = Path.Combine(AppContext.BaseDirectory, "data", "port-baseline.json");
            public int MaxKeys { get; set; } = 5000;
            public int MaxStoredPeers { get; set; } = 64;

            // Evidence requirements (tune to your network size)
            public double MinEwmaScore { get; set; } = 0.20; // needs repeated observations
            public int MinDistinctSources { get; set; } = 3;  // many internal talkers
            public int MinDistinctDests { get; set; } = 3;    // and destinations

            public int LastDistinctHorizonMinutes { get; set; } = 60 * 24; // ~1 day
            public double EwmaAlphaPerEvent { get; set; } = 0.02;

            public int CooldownAfterBadDays { get; set; } = 14; // post-breach caution
            public int ForgetAfterDays { get; set; } = 45;      // drift adaptation
        }

        private sealed class PortStats
        {
            public PortStats(DateTime now)
            {
                LastSeen = now;
                Sources = new ConcurrentDictionary<string, DateTime>(StringComparer.Ordinal);
                Dests = new ConcurrentDictionary<string, DateTime>(StringComparer.Ordinal);
            }
            public double Score { get; set; }
            public int ObsCount { get; set; }
            public DateTime LastSeen { get; set; }
            public DateTime? LastBadSeen { get; set; }
            public int BadCount { get; set; }
            public ConcurrentDictionary<string, DateTime> Sources { get; }
            public ConcurrentDictionary<string, DateTime> Dests { get; }
        }

        private sealed class DiskRow
        {
            public int Port { get; set; }
            public string Proto { get; set; } = "TCP";
            public double Score { get; set; }
            public int ObsCount { get; set; }
            public DateTime LastSeen { get; set; }
            public DateTime? LastBadSeen { get; set; }
            public List<string> Sources { get; set; } = new();
            public List<string> Dests { get; set; } = new();
        }
    }
}
