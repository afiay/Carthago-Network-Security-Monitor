// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Bounded candidate evidence: never promote packet Info to protocol facts.
    // Declared HTTP sizes, process names and first-seen JA4T are NOT proof of
    // transferred bytes, credential alerts or approved fingerprint baselines.
    internal static class NetworkBatch256260Evidence
    {
        private static bool Private(string? value)
        {
            if (!IPAddress.TryParse(value, out var ip)) return false;
            var b = ip.GetAddressBytes();
            return b.Length == 4 && (b[0] == 10 || b[0] == 172 && b[1] >= 16 && b[1] <= 31
                || b[0] == 192 && b[1] == 168)
                || b.Length == 16 && (b[0] & 0xfe) == 0xfc;
        }

        private static bool Endpoints(TrafficRecord r)
            => r.Id != Guid.Empty && IPAddress.TryParse(r.Source, out var source)
                && IPAddress.TryParse(r.Destination, out var destination)
                && source.AddressFamily == destination.AddressFamily && !source.Equals(destination);

        private static bool Approved(string? process)
            => process != null && new[] { "veeamagent.exe", "onedrive.exe",
                "rclone-approved", "rsync-approved", "backup-agent.exe" }
                .Any(p => process.Trim().Equals(p, StringComparison.OrdinalIgnoreCase));

        internal static bool InternalStagingRequest(TrafficRecord r)
        {
            if (!Endpoints(r) || !Private(r.Source) || !Private(r.Destination)
                || !r.IsTcp || r.IsUdp || Approved(r.ProcessName)
                || r.HttpMethod is not ("POST" or "PUT" or "PATCH")
                || !NetworkBatch131135Evidence.CleartextHttpRequest(r)
                || !NetworkBatch156165Evidence.Authority(r)
                || !NetworkBatch156165Evidence.Path(r, out var path)
                || path.Length is < 10 or > 256 || path.Contains('%')
                || !NetworkBatch166170Evidence.Header(r, "Content-Length", out var value)
                || !long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var declared)
                || declared is < 1024 or > 1073741824L)
                return false;
            var file = path.Split('/').Last().ToLowerInvariant();
            if (file.Length is < 8 or > 128
                || file.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-')))
                return false;
            return new[] { ".tar.gz", ".tgz", ".zip", ".7z", ".sql", ".sql.gz",
                ".dump", ".bak", ".kdbx", ".pfx" }
                .Any(ext => file.EndsWith(ext, StringComparison.Ordinal))
                && (file.Contains("backup", StringComparison.Ordinal)
                    || file.Contains("dump", StringComparison.Ordinal)
                    || file.Contains("archive", StringComparison.Ordinal)
                    || file.Contains("source", StringComparison.Ordinal)
                    || file.Contains("secret", StringComparison.Ordinal));
        }

        // This is a same-record co-observation, NOT an upstream credential alert.
        // A real incident chain requires a trusted, timestamped alert feed.
        internal static bool CredentialProcessAndUploadRequest(TrafficRecord r)
        {
            if (!NetworkBatch251255Evidence.HttpUpload(r)
                || !NetworkBatch251255Evidence.Declared(r, out var declared)
                || declared < 1024 || Approved(r.ProcessName)) return false;
            var process = r.ProcessName?.Trim();
            return process != null && new[] { "mimikatz.exe", "rubeus.exe",
                "secretsdump.exe", "lazagne.exe" }
                .Any(p => process.Equals(p, StringComparison.OrdinalIgnoreCase));
        }

        internal static bool IcmpUnreachable(TrafficRecord r)
        {
            if (!Endpoints(r) || r.IsTcp || r.IsUdp || r.TcpFlags != null
                || r.IcmpTypeCode == null || r.HttpMethod != null || r.TlsVersion != null)
                return false;
            var type = r.IcmpTypeCode.Value >> 8;
            var code = r.IcmpTypeCode.Value & 255;
            return r.IpVersion == 4 && string.Equals(r.Protocol, "ICMP", StringComparison.OrdinalIgnoreCase)
                    && type == 3 && code <= 15
                || r.IpVersion == 6 && string.Equals(r.Protocol, "ICMPv6", StringComparison.OrdinalIgnoreCase)
                    && type == 1 && code <= 7;
        }

        internal static bool TcpReset(TrafficRecord r)
            => Endpoints(r) && r.IsTcp && !r.IsUdp && !r.IsQuic
                && string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                && r.SourcePort is > 0 and <= 65535 && r.DestinationPort is > 0 and <= 65535
                && r.IcmpTypeCode == null && r.TcpFlags.HasValue
                && (r.TcpFlags.Value & 0x04) != 0 && (r.TcpFlags.Value & 0x02) == 0;

        internal static bool SynFingerprint(TrafficRecord r, out string fingerprint)
        {
            fingerprint = "";
            if (!Endpoints(r) || !r.IsTcp || r.IsUdp || r.IsQuic
                || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || r.SourcePort is not (> 0 and <= 65535)
                || r.DestinationPort is not (> 0 and <= 65535)
                || r.IcmpTypeCode != null || r.TcpFlags == null
                || (r.TcpFlags.Value & 0x02) == 0 || (r.TcpFlags.Value & 0x14) != 0
                || string.IsNullOrWhiteSpace(r.Ja4T)) return false;
            var value = r.Ja4T!.Trim();
            if (value.Length is < 8 or > 128
                || value.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or ':' or '.')))
                return false;
            fingerprint = value;
            return true;
        }

        internal sealed class BoundedWindow
        {
            private sealed class Slot
            {
                internal readonly Queue<(Guid Id, DateTime At)> Items = new();
                internal readonly HashSet<Guid> Seen = new();
                internal DateTime Latest = DateTime.MinValue;
            }
            private readonly object _gate = new();
            private readonly Dictionary<string, Slot> _slots = new(StringComparer.OrdinalIgnoreCase);
            internal int Observe(TrafficRecord r, DateTime at, string key, TimeSpan window)
            {
                if (r.Id == Guid.Empty) return 0;
                lock (_gate)
                {
                    if (!_slots.TryGetValue(key, out var slot))
                    {
                        if (_slots.Count >= 512)
                        {
                            foreach (var old in _slots.Where(x => at - x.Value.Latest > TimeSpan.FromMinutes(30))
                                .Select(x => x.Key).ToArray()) _slots.Remove(old);
                            if (_slots.Count >= 512) return 0;
                        }
                        _slots.Add(key, slot = new Slot());
                    }
                    if (at < slot.Latest || slot.Seen.Contains(r.Id)) return 0;
                    while (slot.Items.Count > 0 && at - slot.Items.Peek().At > window)
                    {
                        var old = slot.Items.Dequeue();
                        slot.Seen.Remove(old.Id);
                    }
                    if (slot.Items.Count >= 256) return 0;
                    slot.Items.Enqueue((r.Id, at));
                    slot.Seen.Add(r.Id);
                    slot.Latest = at;
                    return slot.Items.Count;
                }
            }
        }

        // Change relative to this rule instance's first SYN fingerprint;
        // not a claim of population rarity or an approved persistent baseline.
        internal sealed class FingerprintChange
        {
            private sealed class Slot
            {
                internal string Value = "";
                internal DateTime Latest = DateTime.MinValue;
                internal readonly HashSet<Guid> Seen = new();
            }
            private readonly object _gate = new();
            private readonly Dictionary<string, Slot> _slots = new(StringComparer.OrdinalIgnoreCase);
            internal bool Observe(TrafficRecord r, DateTime at, string key, string fingerprint)
            {
                if (r.Id == Guid.Empty) return false;
                lock (_gate)
                {
                    if (!_slots.TryGetValue(key, out var slot))
                    {
                        if (_slots.Count >= 512)
                        {
                            foreach (var old in _slots.Where(x => at - x.Value.Latest > TimeSpan.FromMinutes(20))
                                .Select(x => x.Key).ToArray()) _slots.Remove(old);
                            if (_slots.Count >= 512) return false;
                        }
                        _slots.Add(key, new Slot { Value = fingerprint, Latest = at });
                        _slots[key].Seen.Add(r.Id);
                        return false;
                    }
                    if (at < slot.Latest || !slot.Seen.Add(r.Id)) return false;
                    if (slot.Seen.Count > 256) return false;
                    slot.Latest = at;
                    if (string.Equals(slot.Value, fingerprint, StringComparison.Ordinal)) return false;
                    slot.Value = fingerprint;
                    return true;
                }
            }
        }
    }
}
