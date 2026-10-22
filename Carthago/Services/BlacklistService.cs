// File: Services/BlacklistService.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace Carthago.Services
{
    /// <summary>
    /// Blacklist service supporting single IPs and CIDR ranges (IPv4/IPv6).
    /// Thread-safe; expirations are UTC-based.
    /// </summary>
    public class BlacklistService
    {
        // Single-IP blocks (case-insensitive for string keys)
        private readonly ConcurrentDictionary<string, DateTime?> _ipBlocks =
            new(StringComparer.OrdinalIgnoreCase);

        // CIDR blocks with expiry
        private readonly ConcurrentDictionary<CidrBlock, DateTime?> _cidrBlocks =
            new(CidrBlock.Equality);

        /// <summary>
        /// Add a single IP. If duration is null, block indefinitely.
        /// </summary>
        public void Add(string ip, TimeSpan? duration = null)
        {
            if (string.IsNullOrWhiteSpace(ip)) return;
            DateTime? expiryUtc = duration.HasValue ? DateTime.UtcNow.Add(duration.Value) : null;
            _ipBlocks[ip] = expiryUtc;
        }

        /// <summary>
        /// Remove a single IP block if present.
        /// </summary>
        public void Remove(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return;
            _ipBlocks.TryRemove(ip, out _);
        }

        /// <summary>
        /// Add a CIDR block. Returns false if the CIDR is invalid.
        /// </summary>
        public bool AddCidr(string cidr, TimeSpan? duration = null)
        {
            if (!CidrBlock.TryParse(cidr, out var block))
                return false;

            DateTime? expiryUtc = duration.HasValue ? DateTime.UtcNow.Add(duration.Value) : null;
            _cidrBlocks[block] = expiryUtc;
            return true;
        }

        /// <summary>
        /// Remove a CIDR block (string form must match a parseable CIDR; normalized internally).
        /// </summary>
        public bool RemoveCidr(string cidr)
        {
            if (!CidrBlock.TryParse(cidr, out var block))
                return false;
            return _cidrBlocks.TryRemove(block, out _);
        }

        /// <summary>
        /// True if the IP is currently blocked by either an exact IP or a CIDR range.
        /// Expired entries are cleaned automatically.
        /// </summary>
        public bool IsBlocked(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip))
                return false;

            var now = DateTime.UtcNow;

            // Exact IP
            if (_ipBlocks.TryGetValue(ip, out var expiry))
            {
                if (expiry == null || expiry > now) return true;
                // expired -> remove
                _ipBlocks.TryRemove(ip, out _);
            }

            if (!IPAddress.TryParse(ip, out var addr))
                return false;

            // CIDR ranges
            foreach (var kv in _cidrBlocks.ToArray())
            {
                var block = kv.Key;
                var exp = kv.Value;

                if (exp != null && exp <= now)
                {
                    _cidrBlocks.TryRemove(block, out _);
                    continue;
                }

                if (block.Contains(addr))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Snapshot of currently blocked IPs (expired removed).
        /// </summary>
        public IEnumerable<string> GetBlockedIps()
        {
            var now = DateTime.UtcNow;
            foreach (var kv in _ipBlocks.ToArray())
            {
                var exp = kv.Value;
                if (exp != null && exp <= now)
                {
                    _ipBlocks.TryRemove(kv.Key, out _);
                    continue;
                }
                yield return kv.Key;
            }
        }

        /// <summary>
        /// Snapshot of currently active CIDR ranges (expired removed).
        /// </summary>
        public IEnumerable<string> GetBlockedCidrs()
        {
            var now = DateTime.UtcNow;
            foreach (var kv in _cidrBlocks.ToArray())
            {
                var exp = kv.Value;
                if (exp != null && exp <= now)
                {
                    _cidrBlocks.TryRemove(kv.Key, out _);
                    continue;
                }
                yield return kv.Key.ToString();
            }
        }

        // ======== CIDR representation ========

        private readonly struct CidrBlock
        {
            public AddressFamily Family { get; }
            public byte[] NetworkBytes { get; } // masked network address
            public int PrefixLength { get; }

            private CidrBlock(AddressFamily fam, byte[] network, int prefixLen)
            {
                Family = fam;
                NetworkBytes = network;
                PrefixLength = prefixLen;
            }

            public static bool TryParse(string cidr, out CidrBlock block)
            {
                block = default;
                if (string.IsNullOrWhiteSpace(cidr)) return false;

                var parts = cidr.Split('/', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length != 2) return false;

                if (!IPAddress.TryParse(parts[0], out var ip)) return false;
                if (!int.TryParse(parts[1], out var prefixLen)) return false;

                int maxBits = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
                if (prefixLen < 0 || prefixLen > maxBits) return false;

                var ipBytes = ip.GetAddressBytes();
                var maskBytes = BuildMask(prefixLen, maxBits);
                var network = new byte[ipBytes.Length];
                for (int i = 0; i < ipBytes.Length; i++)
                    network[i] = (byte)(ipBytes[i] & maskBytes[i]);

                block = new CidrBlock(ip.AddressFamily, network, prefixLen);
                return true;
            }

            public bool Contains(IPAddress addr)
            {
                if (addr.AddressFamily != Family) return false;

                var ipBytes = addr.GetAddressBytes();
                var maskBytes = BuildMask(PrefixLength, Family == AddressFamily.InterNetwork ? 32 : 128);

                for (int i = 0; i < ipBytes.Length; i++)
                {
                    if ((ipBytes[i] & maskBytes[i]) != NetworkBytes[i])
                        return false;
                }
                return true;
            }

            public override string ToString()
            {
                var ip = new IPAddress(NetworkBytes);
                return $"{ip}/{PrefixLength}";
            }

            // Prepares byte mask for prefix length (works for IPv4/IPv6)
            private static byte[] BuildMask(int prefix, int maxBits)
            {
                int byteLen = maxBits / 8;
                var mask = new byte[byteLen];

                int fullBytes = prefix / 8;
                int remBits = prefix % 8;

                for (int i = 0; i < fullBytes; i++)
                    mask[i] = 0xFF;

                if (remBits > 0)
                {
                    // High-order bits set
                    mask[fullBytes] = (byte)(0xFF << (8 - remBits));
                }

                // rest remain 0
                return mask;
            }

            // We use a custom equality comparer to avoid array reference comparison
            public static readonly IEqualityComparer<CidrBlock> Equality = new CidrBlockComparer();

            private sealed class CidrBlockComparer : IEqualityComparer<CidrBlock>
            {
                public bool Equals(CidrBlock x, CidrBlock y)
                {
                    if (x.Family != y.Family) return false;
                    if (x.PrefixLength != y.PrefixLength) return false;
                    if (x.NetworkBytes.Length != y.NetworkBytes.Length) return false;

                    for (int i = 0; i < x.NetworkBytes.Length; i++)
                        if (x.NetworkBytes[i] != y.NetworkBytes[i]) return false;

                    return true;
                }

                public int GetHashCode(CidrBlock obj)
                {
                    unchecked
                    {
                        int h = (int)obj.Family * 397 ^ obj.PrefixLength;
                        // Fold first and last 4 bytes for speed (works for both v4/v6)
                        int n = obj.NetworkBytes.Length;
                        for (int i = 0; i < n; i += Math.Max(1, n / 8))
                            h = (h * 31) ^ obj.NetworkBytes[i];
                        return h;
                    }
                }
            }
        }
    }
}
