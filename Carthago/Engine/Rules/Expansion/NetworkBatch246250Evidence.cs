// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Bounded, typed request/packet evidence. Info, port guesses and declared
    // HTTP body lengths are never treated as completed transfers.
    internal static class NetworkBatch246250Evidence
    {
        private static bool Private(string? value)
        {
            if (!IPAddress.TryParse(value, out var ip)) return false;
            var b = ip.GetAddressBytes();
            return b.Length == 4 && (b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168)
                || b.Length == 16 && (b[0] & 0xfe) == 0xfc;
        }

        private static bool Tcp(TrafficRecord r)
            => r.Id != Guid.Empty && r.IsTcp && !r.IsUdp && !r.IsQuic
                && string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                && r.SourcePort is > 0 and <= 65535 && r.DestinationPort is > 0 and <= 65535
                && r.HttpMethod == null && r.DnsQname == null && r.TlsVersion == null
                && r.Sni == null && IPAddress.TryParse(r.Source, out _)
                && IPAddress.TryParse(r.Destination, out _);

        internal static bool Egress(TrafficRecord r)
            => Tcp(r) && Private(r.Source) && NetworkBatch226230Evidence.Public(r.Destination)
                && !string.Equals(r.Source, r.Destination, StringComparison.OrdinalIgnoreCase);

        internal static bool SourceArchive(TrafficRecord r)
        {
            if (!NetworkBatch241245Evidence.Upload(r, out var file, out _)) return false;
            if (!(file.EndsWith(".zip", StringComparison.Ordinal)
                || file.EndsWith(".tar.gz", StringComparison.Ordinal)
                || file.EndsWith(".tgz", StringComparison.Ordinal)
                || file.EndsWith(".7z", StringComparison.Ordinal))) return false;
            var stem = file.EndsWith(".tar.gz", StringComparison.Ordinal) ? file[..^7]
                : file[..file.LastIndexOf('.')];
            var tokens = stem.Split(new[] { '-', '_', '.' }, StringSplitOptions.RemoveEmptyEntries);
            return tokens.Any(t => t is "src" or "source" or "sourcecode" or "repo" or "repository"
                or "frontend" or "backend" or "project");
        }

        internal static bool SshClient(TrafficRecord r)
        {
            if (!Egress(r) || r.DestinationPort != 22 || r.SourcePort == 22
                || r.ApplicationProtocol != null
                    && !string.Equals(r.ApplicationProtocol, "SSH", StringComparison.OrdinalIgnoreCase)
                || r.Length is < 40 or > 65535) return false;
            var process = r.ProcessName?.Trim();
            return process != null && new[] { "scp.exe", "sftp.exe", "pscp.exe", "winscp.exe" }
                .Any(p => process.Equals(p, StringComparison.OrdinalIgnoreCase));
        }

        internal static bool FtpUpload(TrafficRecord r)
            => Egress(r) && r.DestinationPort == 21 && r.SourcePort != 21
                && (string.Equals(r.ApplicationProtocol, "ftp.stor", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.ApplicationProtocol, "ftp.appe", StringComparison.OrdinalIgnoreCase));

        internal static bool SmbWrite(TrafficRecord r)
            => Egress(r) && r.DestinationPort == 445 && r.SourcePort != 445
                && string.Equals(r.ApplicationProtocol, "smb2.write.request", StringComparison.OrdinalIgnoreCase);

        internal static bool IpLiteralPost(TrafficRecord r, out long declared)
        {
            declared = 0;
            if (!NetworkBatch131135Evidence.CleartextHttpRequest(r)
                || !Private(r.Source) || !NetworkBatch226230Evidence.Public(r.Destination)
                || r.HttpMethod is not ("POST" or "PUT" or "PATCH")
                || r.Sni != null || r.HttpHost == null
                || !IPAddress.TryParse(r.HttpHost, out var host)
                || !IPAddress.TryParse(r.Destination, out var dest) || !host.Equals(dest)
                || !NetworkBatch156165Evidence.UriOf(r, out _)
                || !NetworkBatch156165Evidence.Authority(r)
                || !NetworkBatch166170Evidence.Header(r, "Content-Length", out var value)
                || !long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out declared))
                return false;
            return declared >= 20L * 1024 * 1024 && declared <= 10_737_418_240L;
        }

        // Packet IDs are per-observation identifiers, not TCP sequence numbers.
        // This counts observed packet bytes, never delivered application bytes.
        internal sealed class ObservedByteWindow
        {
            private sealed class Bucket
            {
                internal readonly Queue<(Guid Id, DateTime At, int Bytes)> Entries = new();
                internal readonly HashSet<Guid> Seen = new();
                internal DateTime Latest = DateTime.MinValue;
                internal long Bytes;
            }
            private readonly object _gate = new();
            private readonly Dictionary<string, Bucket> _buckets = new(StringComparer.OrdinalIgnoreCase);
            internal long Observe(TrafficRecord r, DateTime at)
            {
                if (!SshClient(r)) return 0;
                var key = r.Source + "|" + r.Destination + "|" + r.DestinationPort;
                lock (_gate)
                {
                    if (!_buckets.TryGetValue(key, out var bucket))
                    {
                        if (_buckets.Count >= 512)
                        {
                            foreach (var old in _buckets.Where(e => at - e.Value.Latest > TimeSpan.FromMinutes(20))
                                .Select(e => e.Key).ToArray()) _buckets.Remove(old);
                            if (_buckets.Count >= 512) return 0;
                        }
                        bucket = new Bucket();
                        _buckets.Add(key, bucket);
                    }
                    if (at < bucket.Latest || bucket.Seen.Contains(r.Id)) return 0;
                    while (bucket.Entries.Count > 0
                        && at - bucket.Entries.Peek().At > TimeSpan.FromMinutes(20))
                    {
                        var old = bucket.Entries.Dequeue();
                        bucket.Seen.Remove(old.Id);
                        bucket.Bytes -= old.Bytes;
                    }
                    if (bucket.Entries.Count >= 4096) return 0;
                    bucket.Entries.Enqueue((r.Id, at, r.Length));
                    bucket.Seen.Add(r.Id);
                    bucket.Bytes += r.Length;
                    bucket.Latest = at;
                    return bucket.Bytes;
                }
            }
        }
    }
}
