// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Shared evidence hygiene/state only; no predicate convergence.
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class Research726Evidence
    {
        internal static bool Process(TrafficRecord r, params string[] names)
            => Research676Evidence.Process(r, names);

        internal static bool EsxiProcess(TrafficRecord r)
            => Process(r, "hostd", "hostd.exe", "vpxa", "vpxa.exe", "vmx", "vmx.exe");

        internal static bool PrivateToPublic(TrafficRecord r)
            => Research676Evidence.PrivateToPublic(r);

        internal static bool PrivatePair(TrafficRecord r)
            => Research676Evidence.PrivatePair(r, out _, out _);

        internal static bool Tcp(TrafficRecord r)
            => Research676Evidence.Tcp(r);

        internal static bool Tls443(TrafficRecord r)
            => Tcp(r)
               && PrivateToPublic(r)
               && r.DestinationPort == 443
               && r.TlsVersion != null
               && !string.IsNullOrWhiteSpace(r.Sni)
               && r.L4Len is >= 32 and <= 8192
               && r.HttpMethod == null && r.HttpUri == null
               && r.DnsQname == null && !r.DnsIsResponse;

        internal static bool Dot853(TrafficRecord r)
            => Tcp(r)
               && PrivateToPublic(r)
               && r.DestinationPort == 853
               && r.TlsVersion != null
               && !string.IsNullOrWhiteSpace(r.Sni)
               && r.L4Len is >= 32 and <= 8192
               && r.HttpMethod == null && r.HttpUri == null
               && r.DnsQname == null && !r.DnsIsResponse;

        internal static bool OtTcp(TrafficRecord r)
            => Tcp(r)
               && PrivatePair(r)
               && r.DestinationPort is 102 or 502 or 20000 or 44818 or 4840
               && r.HttpMethod == null && r.HttpUri == null
               && r.DnsQname == null && r.TlsVersion == null
               && r.L4Len is null or <= 4096;

        internal static bool TextStorageHost(string? host)
            => Research656Evidence.HostIs(host, "pastebin.com")
               || Research656Evidence.HostIs(host, "hastebin.com")
               || Research656Evidence.HostIs(host, "paste.ee")
               || Research656Evidence.HostIs(host, "controlc.com")
               || Research656Evidence.HostIs(host, "dpaste.org")
               || Research656Evidence.HostIs(host, "privatebin.net");

        internal static bool CodeRepositoryHost(string? host)
            => Research656Evidence.HostIs(host, "github.com")
               || Research656Evidence.HostIs(host, "gitlab.com")
               || Research656Evidence.HostIs(host, "bitbucket.org");

        internal static bool MacNonBrowser(TrafficRecord r)
            => Process(r, "osascript", "python", "python3", "bash", "sh", "zsh",
                "perl", "ruby", "curl", "wget", "microsoft word", "microsoft excel", "preview");

        internal static bool MacTextStorageProcess(TrafficRecord r)
            => Process(r, "osascript", "curl", "wget", "microsoft word", "microsoft excel");

        internal static bool LinuxDnsTool(TrafficRecord r)
            => Process(r, "python", "python3", "node", "nodejs", "curl", "wget", "bash", "sh", "zsh");

        internal static bool FloodShape(TrafficRecord r)
        {
            if (r == null || r.Id == Guid.Empty || r.IpVersion != 4
                || !PrivateToPublic(r)
                || r.SourcePort is null or <= 0 or > 65535
                || r.DestinationPort is null or <= 0 or > 65535
                || r.HttpMethod != null || r.HttpUri != null || r.DnsQname != null
                || r.TlsVersion != null || r.Sni != null)
                return false;

            if (r.IsTcp && !r.IsUdp && !r.IsQuic
                && string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase))
                return r.TcpFlags == 0x02 && r.L4Len is null or 0 && r.Length >= 40;

            if (!r.IsTcp && r.IsUdp && !r.IsQuic
                && string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase))
                return r.TcpFlags == null && r.L4Len is >= 1 and <= 512 && r.Length >= 28;

            return false;
        }

        internal static bool EsxiPortProtocolMismatch(TrafficRecord r)
        {
            if (!EsxiProcess(r) || !Tcp(r) || !PrivateToPublic(r))
                return false;

            var httpOnVmwareService = string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                && r.HttpMethod is "GET" or "POST"
                && !string.IsNullOrWhiteSpace(r.HttpUri)
                && r.TlsVersion == null && r.Sni == null
                && r.DestinationPort is 902 or 903;

            var tlsOnCleartextWebPort = r.TlsVersion != null
                && !string.IsNullOrWhiteSpace(r.Sni)
                && r.HttpMethod == null && r.HttpUri == null
                && r.DnsQname == null
                && r.DestinationPort is 80 or 8000 or 8080;

            return httpOnVmwareService || tlsOnCleartextWebPort;
        }
    }

    internal sealed class Research726BurstWindow
    {
        private sealed class Slot
        {
            internal DateTime First;
            internal DateTime Latest = DateTime.MinValue;
            internal int Count;
            internal readonly HashSet<Guid> Ids = new();
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);

        internal bool Observe(string key, Guid id, DateTime at, int threshold, int windowSeconds)
        {
            if (string.IsNullOrWhiteSpace(key) || id == Guid.Empty || at.Kind != DateTimeKind.Utc
                || threshold is < 4 or > 64 || windowSeconds is < 2 or > 60)
                return false;

            lock (_gate)
            {
                if (!_slots.TryGetValue(key, out var slot))
                {
                    if (_slots.Count >= 512)
                    {
                        foreach (var stale in _slots
                            .Where(x => at >= x.Value.Latest && at - x.Value.Latest > TimeSpan.FromMinutes(2))
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
                    slot.Ids.Clear();
                }

                if (slot.Ids.Count >= 128) return false;
                slot.Ids.Add(id);
                slot.Count++;
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
