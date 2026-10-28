// SPDX-License-Identifier: MIT
using System;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Strict, observable application-operation contracts; packet Info and
    // port-guessed ApplicationService never establish a decoded operation.
    internal static class NetworkBatch231235Evidence
    {
        private static bool Flow(TrafficRecord r, bool tcp)
            => r.Id != Guid.Empty && r.IsTcp == tcp && r.IsUdp != tcp
                && !r.IsQuic && r.TlsVersion == null
                && string.Equals(r.Protocol, tcp ? "TCP" : "UDP", StringComparison.OrdinalIgnoreCase)
                && IPAddress.TryParse(r.Source, out var src)
                && IPAddress.TryParse(r.Destination, out var dst)
                && src.AddressFamily == dst.AddressFamily && !src.Equals(dst);

        internal static bool Coap(TrafficRecord r)
            => Flow(r, false) && r.DestinationPort == 5683
                && r.HttpMethod == null && r.DnsQname == null
                && string.Equals(r.ApplicationProtocol, "coap.discovery", StringComparison.OrdinalIgnoreCase);

        internal static bool Mdns(TrafficRecord r, out string query)
        {
            query = (r.DnsQname ?? "").TrimEnd('.').ToLowerInvariant();
            if (!Flow(r, false) || r.DestinationPort != 5353
                || !string.Equals(r.ApplicationProtocol, "mDNS", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(r.DnsQtype, "PTR", StringComparison.OrdinalIgnoreCase)
                || r.DnsIsResponse || r.HttpMethod != null || r.DnsAnswers != null
                || query.Length is < 12 or > 253 || query.Contains("..", StringComparison.Ordinal)
                || !query.EndsWith(".local", StringComparison.Ordinal)) return false;
            if (r.Destination != "224.0.0.251" && !r.Destination!.Equals("ff02::fb", StringComparison.OrdinalIgnoreCase))
                return false;
            var labels = query.Split('.');
            if (labels.Length < 3) return false;
            foreach (var label in labels)
            {
                if (label.Length is < 1 or > 63) return false;
                foreach (var ch in label)
                    if (!char.IsAsciiLetterOrDigit(ch) && ch != '-' && ch != '_') return false;
            }
            return query == "_services._dns-sd._udp.local"
                || query.StartsWith("_", StringComparison.Ordinal)
                   && (query.Contains("._tcp.local", StringComparison.Ordinal)
                       || query.Contains("._udp.local", StringComparison.Ordinal));
        }

        internal static bool PrinterAdmin(TrafficRecord r)
        {
            if (!Flow(r, true) || r.DestinationPort != 631
                || !string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                || r.HttpMethod is not ("GET" or "POST")
                || string.IsNullOrWhiteSpace(r.HttpUri)) return false;
            var path = r.HttpUri!.Split('?', 2)[0];
            return (path.Equals("/admin", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/admin/", StringComparison.OrdinalIgnoreCase))
                && Boundary(r);
        }

        internal static bool RtspPlay(TrafficRecord r)
            => Flow(r, true) && (r.DestinationPort == 554 || r.DestinationPort == 8554)
                && r.HttpMethod == null && r.DnsQname == null
                && string.Equals(r.ApplicationProtocol, "rtsp.play", StringComparison.OrdinalIgnoreCase)
                && Boundary(r);

        internal static bool OnvifProbe(TrafficRecord r)
            => Flow(r, false) && r.DestinationPort == 3702
                && r.Destination == "239.255.255.250"
                && string.Equals(r.ApplicationProtocol, "wsdiscovery.probe", StringComparison.OrdinalIgnoreCase)
                && Private(r.Source) && Workstation(r.ProcessName)
                && r.HttpMethod == null && r.DnsQname == null;

        private static bool Workstation(string? name)
            => name != null && (name.Equals("python.exe", StringComparison.OrdinalIgnoreCase)
                || name.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)
                || name.Equals("nmap.exe", StringComparison.OrdinalIgnoreCase)
                || name.Equals("onvif-device-manager.exe", StringComparison.OrdinalIgnoreCase));

        private static bool Private(string? value)
        {
            if (!IPAddress.TryParse(value, out var ip)) return false;
            var b = ip.GetAddressBytes();
            if (b.Length == 4) return b[0] == 10
                || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168;
            return b.Length == 16 && (b[0] & 0xfe) == 0xfc;
        }

        private static bool Boundary(TrafficRecord r)
            => Private(r.Source) && NetworkBatch226230Evidence.Public(r.Destination)
                || NetworkBatch226230Evidence.Public(r.Source) && Private(r.Destination)
                || Private(r.Source) && Private(r.Destination) && Different24(r.Source!, r.Destination!);

        private static bool Different24(string src, string dst)
        {
            if (!IPAddress.TryParse(src, out var a) || !IPAddress.TryParse(dst, out var b)) return false;
            var x = a.GetAddressBytes(); var y = b.GetAddressBytes();
            return x.Length == 4 && y.Length == 4
                && (x[0] != y[0] || x[1] != y[1] || x[2] != y[2]);
        }
    }
}
