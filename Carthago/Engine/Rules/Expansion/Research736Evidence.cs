// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Shared validation/state only; no behavioral convergence.
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class Research736Evidence
    {
        internal static bool Process(TrafficRecord r, params string[] names)
            => Research676Evidence.Process(r, names);

        internal static bool PrivateToPublic(TrafficRecord r)
            => Research676Evidence.PrivateToPublic(r);

        internal static bool HypervisorProcess(TrafficRecord r)
            => Process(r, "hostd", "hostd.exe", "vpxa", "vpxa.exe", "vmx", "vmx.exe");

        internal static bool LinuxTransferProcess(TrafficRecord r)
            => Process(r, "curl", "wget", "python", "python3", "rsync", "scp", "sftp", "rclone");

        internal static bool LinuxWebProcess(TrafficRecord r)
            => Process(r, "curl", "wget", "python", "python3");

        internal static bool MacUploadProcess(TrafficRecord r)
            => Process(r, "osascript", "microsoft word", "microsoft excel", "preview");

        internal static bool BusyBoxWebProcess(TrafficRecord r)
            => Process(r, "busybox", "wget", "curl");

        internal static bool FloodTool(TrafficRecord r)
            => Process(r, "hping3", "hping", "nping", "nping.exe");

        internal static bool Tls443(TrafficRecord r)
            => Research676Evidence.Tcp(r)
               && PrivateToPublic(r)
               && r.DestinationPort == 443
               && r.TlsVersion != null
               && !string.IsNullOrWhiteSpace(r.Sni)
               && r.L4Len is >= 32 and <= 8192
               && r.HttpMethod == null && r.HttpUri == null
               && r.DnsQname == null && !r.DnsIsResponse;

        internal static bool RawTcpPayload(TrafficRecord r)
            => Research706Evidence.TcpPayload(r)
               && PrivateToPublic(r);

        internal static bool DeadDropHost(string? host)
            => Research656Evidence.HostIs(host, "pastebin.com")
               || Research656Evidence.HostIs(host, "hastebin.com")
               || Research656Evidence.HostIs(host, "paste.ee")
               || Research656Evidence.HostIs(host, "controlc.com")
               || Research656Evidence.HostIs(host, "dpaste.org")
               || Research656Evidence.HostIs(host, "privatebin.net")
               || Research656Evidence.HostIs(host, "gist.github.com");

        internal static bool CommonServiceHost(string? host)
            => DeadDropHost(host)
               || Research716Evidence.CloudStorageHost(host)
               || Research656Evidence.HostIs(host, "github.com")
               || Research656Evidence.HostIs(host, "gitlab.com")
               || Research656Evidence.HostIs(host, "bitbucket.org")
               || Research716Evidence.PublicIpDiscoveryHost(host);

        internal static bool ProxyLikePort(int? port)
            => port is 1080 or 3128 or 8080 or 8443 or 8888;

        internal static bool UncommonTcpPort(int? port)
            => port is >= 1024 and <= 65535
               && port is not (1883 or 3306 or 3389 or 4443 or 5432 or 6379 or 8080 or 8443 or 11211);

        internal static bool HttpLargeUploadShape(TrafficRecord r, out string method, out string uri)
        {
            method = string.Empty;
            uri = string.Empty;
            return WebSignatureRequestEvidence.TryGet(r, out method, out uri, allowPut: true)
                && method is "POST" or "PUT"
                && PrivateToPublic(r)
                && r.L4Len is >= 900 and <= 8192;
        }

        internal static bool HttpRequestShape(TrafficRecord r, out string method)
        {
            method = string.Empty;
            if (!WebSignatureRequestEvidence.TryGet(r, out method, out _)
                || method is not ("GET" or "POST")
                || !PrivateToPublic(r)
                || r.L4Len is null or < 80 or > 4096)
                return false;
            return true;
        }
    }

    internal sealed class Research736CountWindow
    {
        private sealed class Slot
        {
            internal DateTime First;
            internal DateTime Latest = DateTime.MinValue;
            internal int Count;
            internal long Bytes;
            internal readonly HashSet<Guid> Ids = new();
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);

        internal bool Observe(
            string key, Guid id, int size, DateTime at,
            int threshold, int windowSeconds, long minimumBytes = 0)
        {
            if (string.IsNullOrWhiteSpace(key) || id == Guid.Empty
                || at.Kind != DateTimeKind.Utc || size is < 1 or > 8192
                || threshold is < 3 or > 32 || windowSeconds is < 2 or > 180)
                return false;

            lock (_gate)
            {
                if (!_slots.TryGetValue(key, out var slot))
                {
                    if (_slots.Count >= 512)
                    {
                        foreach (var stale in _slots
                            .Where(x => at >= x.Value.Latest
                                && at - x.Value.Latest > TimeSpan.FromMinutes(5))
                            .Select(x => x.Key).ToArray())
                            _slots.Remove(stale);
                        if (_slots.Count >= 512) return false;
                    }

                    slot = new Slot { First = at };
                    _slots.Add(key, slot);
                }

                if (slot.Ids.Contains(id) || at <= slot.Latest) return false;
                if (at - slot.First > TimeSpan.FromSeconds(windowSeconds))
                {
                    slot.First = at;
                    slot.Count = 0;
                    slot.Bytes = 0;
                    slot.Ids.Clear();
                }

                if (slot.Ids.Count >= 128) return false;
                slot.Ids.Add(id);
                slot.Count++;
                slot.Bytes += size;
                slot.Latest = at;

                if (slot.Count < threshold || slot.Bytes < minimumBytes) return false;

                slot.First = at;
                slot.Count = 0;
                slot.Bytes = 0;
                slot.Ids.Clear();
                return true;
            }
        }
    }

    internal sealed class Research736CadenceWindow
    {
        private sealed class Slot
        {
            internal DateTime First;
            internal DateTime Latest = DateTime.MinValue;
            internal int Count;
            internal int LastSize;
            internal readonly HashSet<Guid> Ids = new();
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);

        internal bool Observe(
            string key, Guid id, int size, DateTime at,
            int threshold, int minIntervalSeconds, int maxIntervalSeconds,
            int maximumSizeDelta, int windowSeconds)
        {
            if (string.IsNullOrWhiteSpace(key) || id == Guid.Empty
                || at.Kind != DateTimeKind.Utc || size is < 32 or > 8192
                || threshold is < 3 or > 8
                || minIntervalSeconds is < 2 or > 120
                || maxIntervalSeconds <= minIntervalSeconds || maxIntervalSeconds > 180
                || maximumSizeDelta is < 0 or > 4096
                || windowSeconds is < 10 or > 300)
                return false;

            lock (_gate)
            {
                if (!_slots.TryGetValue(key, out var slot))
                {
                    if (_slots.Count >= 512)
                    {
                        foreach (var stale in _slots
                            .Where(x => at >= x.Value.Latest
                                && at - x.Value.Latest > TimeSpan.FromMinutes(10))
                            .Select(x => x.Key).ToArray())
                            _slots.Remove(stale);
                        if (_slots.Count >= 512) return false;
                    }

                    slot = new Slot { First = at, LastSize = size };
                    _slots.Add(key, slot);
                }

                if (slot.Ids.Contains(id) || at <= slot.Latest) return false;

                if (slot.Count > 0)
                {
                    var interval = (at - slot.Latest).TotalSeconds;
                    if (at - slot.First > TimeSpan.FromSeconds(windowSeconds)
                        || interval < minIntervalSeconds
                        || interval > maxIntervalSeconds
                        || Math.Abs(slot.LastSize - size) > maximumSizeDelta)
                    {
                        slot.First = at;
                        slot.Count = 0;
                        slot.Ids.Clear();
                    }
                }

                if (slot.Ids.Count >= 16) return false;
                slot.Ids.Add(id);
                slot.Count++;
                slot.LastSize = size;
                slot.Latest = at;

                if (slot.Count < threshold) return false;

                slot.First = at;
                slot.Count = 0;
                slot.Ids.Clear();
                return true;
            }
        }
    }
}
