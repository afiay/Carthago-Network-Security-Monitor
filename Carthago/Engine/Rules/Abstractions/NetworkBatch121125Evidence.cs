// SPDX-License-Identifier: MIT
using System;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    // Parser/transport contracts for R121-R125. Never derive trusted protocol
    // identity from Info, user-agent, process text or a port alone.
    internal static class NetworkBatch121125Evidence
    {
        private static bool Same(string? value, string expected)
            => string.Equals(value, expected, StringComparison.OrdinalIgnoreCase);

        private static bool Classified(TrafficRecord r, string protocol)
            => Same(r.ApplicationProtocol, protocol) || Same(r.ApplicationService, protocol);

        private static bool Endpoints(TrafficRecord r)
            => r.Id != Guid.Empty && !r.IsQuic && !r.IcmpTypeCode.HasValue
                && r.DnsQname == null && r.DnsAnswers == null && !r.DnsIsResponse
                && IPAddress.TryParse(r.Source, out var source)
                && IPAddress.TryParse(r.Destination, out var destination)
                && !source.Equals(destination)
                && source.AddressFamily == destination.AddressFamily
                && (r.IpVersion == null
                    || r.IpVersion == 4 && source.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                    || r.IpVersion == 6 && source.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);

        private static bool NoHttp(TrafficRecord r)
            => r.HttpMethod == null && r.HttpUri == null && r.HttpRequestHeaders == null;

        internal static bool BacnetDiscovery(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Endpoints(r) || !r.IsUdp || r.IsTcp || r.TcpFlags.HasValue
                || r.SourcePort != 47808 && r.DestinationPort != 47808
                || !(Same(r.Protocol, "UDP") || Same(r.Protocol, "BACnet"))
                || !Classified(r, "BACnet")
                || r.ApplicationProtocol != null && !Same(r.ApplicationProtocol, "UDP") && !Same(r.ApplicationProtocol, "BACnet")
                || r.ApplicationService != null && !Same(r.ApplicationService, "BACnet")
                || !NoHttp(r))
                return false;

            var info = r.Info ?? string.Empty;
            if (info.Length > 1024) return false;
            // Who-Is is the discovery request. I-Am or multicast alone is not.
            return info.Contains("who-is", StringComparison.OrdinalIgnoreCase)
                || info.Contains("whois", StringComparison.OrdinalIgnoreCase)
                || info.Contains("who is", StringComparison.OrdinalIgnoreCase);
        }

        internal static bool CoapOrGateway(RuleEvaluationContext context, out bool directCoap, out bool gateway)
        {
            var r = context.Record;
            directCoap = false;
            gateway = false;
            if (!Endpoints(r) || r.IsTcp == r.IsUdp) return false;
            var info = r.Info ?? string.Empty;
            if (info.Length > 1024) return false;

            directCoap = r.IsUdp && !r.TcpFlags.HasValue
                && (r.DestinationPort is 5683 or 5684)
                && (Same(r.Protocol, "UDP") || Same(r.Protocol, "CoAP"))
                && Classified(r, "CoAP")
                && (r.ApplicationProtocol == null || Same(r.ApplicationProtocol, "UDP") || Same(r.ApplicationProtocol, "CoAP"))
                && (r.ApplicationService == null || Same(r.ApplicationService, "CoAP"))
                && NoHttp(r);
            // Zigbee gateway egress is normally TLS/HTTPS, not native Zigbee
            // on the WAN. Require independently attributed gateway process.
            gateway = r.IsTcp && !r.IsUdp
                && (Same(r.Protocol, "TCP") || Same(r.Protocol, "HTTPS") || Same(r.Protocol, "TLS"))
                && (Same(r.ApplicationProtocol, "TCP") || Same(r.ApplicationProtocol, "HTTPS") || Same(r.ApplicationProtocol, "TLS"))
                && (Same(r.ApplicationService, "HTTPS") || Same(r.ApplicationService, "TLS"))
                && !string.IsNullOrWhiteSpace(r.ProcessName)
                && (r.ProcessName.Contains("gateway", StringComparison.OrdinalIgnoreCase)
                    || r.ProcessName.Contains("zigbee", StringComparison.OrdinalIgnoreCase))
                && (info.Contains("zigbee2mqtt", StringComparison.OrdinalIgnoreCase)
                    || info.Contains("zigbee", StringComparison.OrdinalIgnoreCase))
                && NoHttp(r);
            return directCoap || gateway;
        }

        internal static bool VpnPortal(TrafficRecord r, string path)
        {
            if (!Endpoints(r) || r.IsUdp || !r.IsTcp || r.HttpUri == null
                || r.HttpMethod == null || string.IsNullOrWhiteSpace(r.HttpHost)
                || !(Same(r.HttpMethod, "GET") || Same(r.HttpMethod, "POST"))
                || !(Same(r.Protocol, "HTTP") || Same(r.Protocol, "HTTPS") || Same(r.Protocol, "TCP") || Same(r.Protocol, "TLS"))
                || !(Classified(r, "HTTP") || Classified(r, "HTTPS"))
                || r.ApplicationProtocol != null && !Same(r.ApplicationProtocol, "HTTP") && !Same(r.ApplicationProtocol, "HTTPS") && !Same(r.ApplicationProtocol, "TCP")
                || r.ApplicationService != null && !Same(r.ApplicationService, "HTTP") && !Same(r.ApplicationService, "HTTPS")
                || !string.IsNullOrWhiteSpace(r.Sni) && !Same(r.HttpHost, r.Sni))
                return false;

            var host = r.HttpHost ?? string.Empty;
            var vpnHost = host.Contains("vpn", StringComparison.OrdinalIgnoreCase)
                || host.Contains("fortinet", StringComparison.OrdinalIgnoreCase)
                || host.Contains("globalprotect", StringComparison.OrdinalIgnoreCase)
                || host.Contains("anyconnect", StringComparison.OrdinalIgnoreCase);
            return path.StartsWith("/remote/login", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/sslvpn", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/webvpn", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/global-protect", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/globalprotect", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/+cscoe+/", StringComparison.OrdinalIgnoreCase)
                || vpnHost && (path.StartsWith("/vpn/", StringComparison.OrdinalIgnoreCase)
                    || path.StartsWith("/auth/saml", StringComparison.OrdinalIgnoreCase));
        }

        private static bool RemoteTcp(TrafficRecord r)
            => Endpoints(r) && r.IsTcp && !r.IsUdp
                && NoHttp(r)
                && (Same(r.Protocol, "TCP") || Same(r.Protocol, "RDP") || Same(r.Protocol, "WinRM")
                    || Same(r.Protocol, "WSMAN"));

        internal static bool Rdp(TrafficRecord r)
            => RemoteTcp(r)
                && (r.DestinationPort == 3389 || Classified(r, "RDP"))
                && (r.ApplicationProtocol == null || Same(r.ApplicationProtocol, "TCP") || Same(r.ApplicationProtocol, "RDP"))
                && (r.ApplicationService == null || Same(r.ApplicationService, "RDP"));

        internal static bool Winrm(TrafficRecord r)
            => RemoteTcp(r)
                && (r.DestinationPort is 5985 or 5986 || Classified(r, "WinRM") || Classified(r, "WSMAN"))
                && (r.ApplicationProtocol == null || Same(r.ApplicationProtocol, "TCP") || Same(r.ApplicationProtocol, "WinRM") || Same(r.ApplicationProtocol, "WSMAN"))
                && (r.ApplicationService == null || Same(r.ApplicationService, "WinRM") || Same(r.ApplicationService, "WSMAN"));
    }
}
