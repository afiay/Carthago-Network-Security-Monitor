// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Parser/endpoint contracts only. ApplicationService is a port-based guess
    // in PacketHandler and packet Info is untrusted narrative, not OT decoding.
    internal static class NetworkBatch221225Evidence
    {
        private static bool Flow(TrafficRecord r)
        {
            if (r.Id == Guid.Empty || r.IsTcp == r.IsUdp || r.IsQuic
                || r.DnsQname != null || r.HttpMethod != null
                || !IPAddress.TryParse(r.Source, out var src)
                || !IPAddress.TryParse(r.Destination, out var dst)
                || src.Equals(dst) || src.AddressFamily != dst.AddressFamily)
                return false;
            return r.IsTcp
                ? r.Protocol == null || r.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase)
                : r.Protocol == null || r.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase);
        }

        private static bool PublicDestination(string? value)
        {
            if (!IPAddress.TryParse(value, out var ip) || IPAddress.IsLoopback(ip)
                || ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal) return false;
            var b = ip.GetAddressBytes();
            if (b.Length == 16) return (b[0] & 0xfe) != 0xfc;
            return !(b[0] is 0 or 10 or 127 || b[0] >= 224
                || b[0] == 169 && b[1] == 254
                || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168
                || b[0] == 100 && b[1] is >= 64 and <= 127);
        }

        private static bool HostIs(string? host, string domain)
            => host != null && (host.Equals(domain, StringComparison.OrdinalIgnoreCase)
                || host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase));

        private static bool ProcessIs(string? name, string process)
            => name != null && (name.Equals(process, StringComparison.OrdinalIgnoreCase)
                || name.Equals(process + ".exe", StringComparison.OrdinalIgnoreCase));

        internal static bool RemoteDesktop(TrafficRecord r, out string vendor)
        {
            vendor = "";
            if (!Flow(r) || !PublicDestination(r.Destination)
                || r.Sni != null && r.HttpHost != null
                    && !r.Sni.Equals(r.HttpHost, StringComparison.OrdinalIgnoreCase)) return false;
            var host = r.Sni ?? r.HttpHost;
            var candidates = new (string Vendor, string Process, string Domain)[]
            {
                ("anydesk", "anydesk", "anydesk.com"),
                ("teamviewer", "teamviewer", "teamviewer.com"),
                ("rustdesk", "rustdesk", "rustdesk.com"),
                ("splashtop", "splashtop", "splashtop.com"),
                ("screenconnect", "screenconnect.clientservice", "screenconnect.com"),
                ("screenconnect", "screenconnect.clientservice", "connectwise.com")
            };
            foreach (var candidate in candidates)
            {
                if (ProcessIs(r.ProcessName, candidate.Process) && HostIs(host, candidate.Domain))
                {
                    vendor = candidate.Vendor;
                    return true;
                }
            }
            return false;
        }

        internal static bool Overlay(TrafficRecord r, out string vendor, out string signal)
        {
            vendor = ""; signal = "";
            if (!Flow(r) || !PublicDestination(r.Destination)
                || r.Sni != null && r.HttpHost != null
                    && !r.Sni.Equals(r.HttpHost, StringComparison.OrdinalIgnoreCase)) return false;
            var host = r.Sni ?? r.HttpHost;
            if (ProcessIs(r.ProcessName, "tailscale") && HostIs(host, "tailscale.com"))
                vendor = "tailscale";
            else if (ProcessIs(r.ProcessName, "zerotier-one") && HostIs(host, "zerotier.com"))
                vendor = "zerotier";
            else if (ProcessIs(r.ProcessName, "ngrok") && (HostIs(host, "ngrok.io") || HostIs(host, "ngrok.com")))
                vendor = "ngrok";
            else if (ProcessIs(r.ProcessName, "cloudflared") && (HostIs(host, "argotunnel.com")
                || HostIs(host, "trycloudflare.com")))
                vendor = "cloudflare-tunnel";
            else if (ProcessIs(r.ProcessName, "wireguard") && r.IsUdp
                && r.DestinationPort == 51820)
                vendor = "wireguard";
            if (vendor.Length == 0) return false;
            signal = vendor == "wireguard" ? "process+port" : "process+host";
            return true;
        }

        internal static bool Ot(TrafficRecord r, out string protocol)
        {
            protocol = "";
            if (!Flow(r) || string.IsNullOrWhiteSpace(r.ApplicationProtocol))
                return false;
            var typed = r.ApplicationProtocol.Trim().ToLowerInvariant();
            // Require parser-evidenced L7 identity AND transport/port consistency;
            // neither port nor ApplicationService (port guess) suffices alone.
            var protocols = new Dictionary<string, (string Name, int Port, bool Tcp)>
            {
                ["modbus"] = ("modbus", 502, true),
                ["dnp3"] = ("dnp3", 20000, true),
                ["s7"] = ("s7comm", 102, true),
                ["s7comm"] = ("s7comm", 102, true),
                ["cip"] = ("ethernetip-cip", 44818, true),
                ["opcua"] = ("opcua", 4840, true),
                ["bacnet"] = ("bacnet", 47808, false),
                ["profinet"] = ("profinet", 34964, false),
                ["iec104"] = ("iec104", 2404, true)
            };
            if (!protocols.TryGetValue(typed, out var contract)
                || (contract.Tcp ? !r.IsTcp : !r.IsUdp)
                || r.SourcePort != contract.Port && r.DestinationPort != contract.Port)
                return false;
            protocol = contract.Name;
            return true;
        }

        internal static string Key(TrafficRecord r, string family)
            => NetworkBatch206215Evidence.Fingerprint((r.Source ?? "") + "|" +
                (r.Destination ?? "") + "|" + family);
    }
}
