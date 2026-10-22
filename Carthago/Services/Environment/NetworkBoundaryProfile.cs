// SPDX-License-Identifier: MIT
// File: Services/Environment/NetworkBoundaryProfile.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Carthago.Services.EnvironmentTuning
{
    public enum NetworkBoundaryZone
    {
        Unknown,
        Internal,
        Dmz,
        Management,
        Vpn,
        CloudPrivate,
        LinkLocal,
        Loopback,
        External
    }

    public sealed record NetworkBoundaryDecision(
        string Value,
        NetworkBoundaryZone Zone,
        string MatchedBy,
        bool IsIpAddress,
        bool IsRoutableExternal)
    {
        public bool IsInternalLike => Zone is NetworkBoundaryZone.Internal
            or NetworkBoundaryZone.Dmz
            or NetworkBoundaryZone.Management
            or NetworkBoundaryZone.Vpn
            or NetworkBoundaryZone.CloudPrivate
            or NetworkBoundaryZone.LinkLocal
            or NetworkBoundaryZone.Loopback;
    }

    public sealed record NetworkBoundaryProfile
    {
        public IReadOnlyList<string> InternalCidrs { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> DmzCidrs { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> ManagementCidrs { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> VpnCidrs { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> CloudPrivateCidrs { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> ApprovedExternalDestinations { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> ApprovedInternalDestinations { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> ManagementOnlyServices { get; init; } = Array.Empty<string>();

        public static NetworkBoundaryProfile DefaultLocal() => new()
        {
            InternalCidrs = new[]
            {
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "fc00::/7",
                "fe80::/10"
            },
            ManagementCidrs = Array.Empty<string>(),
            DmzCidrs = Array.Empty<string>(),
            VpnCidrs = Array.Empty<string>(),
            CloudPrivateCidrs = Array.Empty<string>(),
            ApprovedExternalDestinations = Array.Empty<string>(),
            ApprovedInternalDestinations = Array.Empty<string>(),
            ManagementOnlyServices = new[] { "ssh", "rdp", "winrm", "snmp", "ldap", "kerberos", "kubernetes-api", "docker-api" }
        };

        public NetworkBoundaryDecision ClassifyAddress(string? value)
        {
            var normalized = Normalize(value);
            if (string.IsNullOrWhiteSpace(normalized))
                return new NetworkBoundaryDecision(string.Empty, NetworkBoundaryZone.Unknown, "empty", false, false);

            if (!IPAddress.TryParse(normalized, out var ip))
            {
                var approvedExternal = MatchesName(ApprovedExternalDestinations, normalized);
                var approvedInternal = MatchesName(ApprovedInternalDestinations, normalized);
                var zone = approvedInternal ? NetworkBoundaryZone.Internal : approvedExternal ? NetworkBoundaryZone.External : NetworkBoundaryZone.Unknown;
                return new NetworkBoundaryDecision(normalized, zone, approvedInternal ? "approved-internal-name" : approvedExternal ? "approved-external-name" : "hostname", false, zone == NetworkBoundaryZone.External);
            }

            if (IPAddress.IsLoopback(ip))
                return new NetworkBoundaryDecision(normalized, NetworkBoundaryZone.Loopback, "loopback", true, false);

            if (IsLinkLocal(ip))
                return new NetworkBoundaryDecision(normalized, NetworkBoundaryZone.LinkLocal, "link-local", true, false);

            if (MatchesAnyCidr(ip, ManagementCidrs, out var managementMatch))
                return new NetworkBoundaryDecision(normalized, NetworkBoundaryZone.Management, managementMatch, true, false);

            if (MatchesAnyCidr(ip, VpnCidrs, out var vpnMatch))
                return new NetworkBoundaryDecision(normalized, NetworkBoundaryZone.Vpn, vpnMatch, true, false);

            if (MatchesAnyCidr(ip, DmzCidrs, out var dmzMatch))
                return new NetworkBoundaryDecision(normalized, NetworkBoundaryZone.Dmz, dmzMatch, true, false);

            if (MatchesAnyCidr(ip, CloudPrivateCidrs, out var cloudMatch))
                return new NetworkBoundaryDecision(normalized, NetworkBoundaryZone.CloudPrivate, cloudMatch, true, false);

            if (MatchesAnyCidr(ip, InternalCidrs, out var internalMatch))
                return new NetworkBoundaryDecision(normalized, NetworkBoundaryZone.Internal, internalMatch, true, false);

            if (IsPrivateAddress(ip))
                return new NetworkBoundaryDecision(normalized, NetworkBoundaryZone.Internal, "rfc1918/unique-local", true, false);

            return new NetworkBoundaryDecision(normalized, NetworkBoundaryZone.External, "public-routable", true, true);
        }

        public bool IsApprovedDestination(string? value)
        {
            var normalized = Normalize(value);
            if (string.IsNullOrWhiteSpace(normalized))
                return false;

            return MatchesName(ApprovedExternalDestinations, normalized)
                || MatchesName(ApprovedInternalDestinations, normalized);
        }

        public static bool IsBoundaryCrossing(NetworkBoundaryDecision source, NetworkBoundaryDecision destination)
        {
            if (source.Zone == NetworkBoundaryZone.Unknown || destination.Zone == NetworkBoundaryZone.Unknown)
                return false;

            return source.IsInternalLike != destination.IsInternalLike
                || source.Zone != destination.Zone && source.Zone is NetworkBoundaryZone.Management or NetworkBoundaryZone.Dmz or NetworkBoundaryZone.Vpn;
        }

        private static string Normalize(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            var normalized = value.Trim().TrimEnd('.').ToLowerInvariant();
            if (normalized.StartsWith("https://", StringComparison.Ordinal)) normalized = normalized[8..];
            if (normalized.StartsWith("http://", StringComparison.Ordinal)) normalized = normalized[7..];
            var slash = normalized.IndexOf('/');
            if (slash >= 0 && !LooksLikeCidr(normalized)) normalized = normalized[..slash];
            var colon = normalized.LastIndexOf(':');
            if (colon > 0 && normalized.Count(static ch => ch == ':') == 1 && int.TryParse(normalized[(colon + 1)..], out _))
                normalized = normalized[..colon];
            return normalized;
        }

        private static bool LooksLikeCidr(string value)
            => value.Contains('/') && value.TakeWhile(static c => c != '/').Any(static c => char.IsDigit(c));

        private static bool MatchesName(IEnumerable<string>? patterns, string normalized)
        {
            if (patterns == null)
                return false;

            foreach (var raw in patterns)
            {
                var pattern = Normalize(raw);
                if (string.IsNullOrWhiteSpace(pattern))
                    continue;

                if (string.Equals(pattern, normalized, StringComparison.OrdinalIgnoreCase))
                    return true;

                if (pattern.StartsWith("*.", StringComparison.Ordinal) && normalized.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase))
                    return true;

                if (!IPAddress.TryParse(pattern, out _) && normalized.EndsWith('.' + pattern, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static bool MatchesAnyCidr(IPAddress ip, IEnumerable<string>? cidrs, out string matched)
        {
            matched = string.Empty;
            if (cidrs == null)
                return false;

            foreach (var cidr in cidrs)
            {
                if (CidrContains(cidr, ip))
                {
                    matched = cidr;
                    return true;
                }
            }

            return false;
        }

        private static bool CidrContains(string? cidr, IPAddress ip)
        {
            if (string.IsNullOrWhiteSpace(cidr))
                return false;

            var text = cidr.Trim();
            if (!text.Contains('/'))
                return IPAddress.TryParse(text, out var single) && AddressEquals(single, ip);

            var parts = text.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network) || !int.TryParse(parts[1], out var prefixLength))
                return false;

            var ipBytes = ip.GetAddressBytes();
            var networkBytes = network.GetAddressBytes();
            if (ipBytes.Length != networkBytes.Length)
                return false;

            var bitLength = ipBytes.Length * 8;
            if (prefixLength < 0 || prefixLength > bitLength)
                return false;

            var fullBytes = prefixLength / 8;
            var remainingBits = prefixLength % 8;
            for (var i = 0; i < fullBytes; i++)
            {
                if (ipBytes[i] != networkBytes[i])
                    return false;
            }

            if (remainingBits == 0)
                return true;

            var mask = (byte)(0xFF << (8 - remainingBits));
            return (ipBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
        }

        private static bool AddressEquals(IPAddress left, IPAddress right)
            => left.GetAddressBytes().SequenceEqual(right.GetAddressBytes());

        private static bool IsLinkLocal(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
                return bytes[0] == 169 && bytes[1] == 254;
            return bytes.Length == 16 && bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80;
        }

        private static bool IsPrivateAddress(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
            {
                return bytes[0] == 10
                    || bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31
                    || bytes[0] == 192 && bytes[1] == 168;
            }

            return bytes.Length == 16 && (bytes[0] & 0xfe) == 0xfc;
        }
    }
}
