// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Shared validation/classification only; no behavioral convergence.
using System;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class Research766Evidence
    {
        internal static bool Process(TrafficRecord r, params string[] names)
            => Research676Evidence.Process(r, names);

        internal static bool MacDnsProcess(TrafficRecord r)
            => Process(r, "osascript");

        internal static bool WindowsDnsProcess(TrafficRecord r)
            => Process(r, "powershell.exe", "pwsh.exe", "rundll32.exe", "python.exe", "python3.exe");

        internal static bool MacFloodProcess(TrafficRecord r)
            => Process(r, "osascript");

        internal static bool LinuxInterpreterWebProcess(TrafficRecord r)
            => Process(r, "perl", "perl5", "ruby");

        internal static bool WindowsLolbinWebProcess(TrafficRecord r)
            => Process(r, "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe");

        internal static bool HighEntropyPublicDns(TrafficRecord r, out string query, out string root)
            => Research756Evidence.HighEntropyPublicDns(r, out query, out root);

        internal static bool CleartextHttpRequest(TrafficRecord r, out int size)
        {
            size = 0;
            if (!WebSignatureRequestEvidence.TryGet(r, out var method, out _)
                || method is not ("GET" or "POST")
                || !Research676Evidence.PrivateToPublic(r)
                || r.L4Len is null or < 80 or > 4096)
                return false;
            size = r.L4Len.Value;
            return true;
        }

        internal static bool WindowsLolbinWebPacket(TrafficRecord r, out int size)
        {
            size = 0;
            if (!WindowsLolbinWebProcess(r)) return false;

            if (CleartextHttpRequest(r, out size))
                return true;

            if (Research736Evidence.Tls443(r) && r.L4Len is >= 80 and <= 4096)
            {
                size = r.L4Len.Value;
                return true;
            }

            return false;
        }

        internal static bool SnmpUdp(TrafficRecord r)
        {
            if (r == null || r.Id == Guid.Empty || r.IpVersion != 4
                || r.IsTcp || !r.IsUdp || r.IsQuic
                || !string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                || r.SourcePort is null or <= 0 or > 65535
                || r.DestinationPort != 161
                || r.TcpFlags != null
                || r.L4Len is null or < 8 or > 1500
                || r.Length < 36
                || r.HttpMethod != null || r.HttpUri != null
                || r.TlsVersion != null || r.Sni != null
                || r.DnsQname != null || r.DnsIsResponse)
                return false;

            if (r.ApplicationProtocol != null
                && !string.Equals(r.ApplicationProtocol, "SNMP", StringComparison.OrdinalIgnoreCase))
                return false;

            return IPAddress.TryParse(r.Source, out var source)
                && IPAddress.TryParse(r.Destination, out var destination)
                && source != null && destination != null
                && source.AddressFamily == AddressFamily.InterNetwork
                && destination.AddressFamily == AddressFamily.InterNetwork
                && !source.Equals(destination);
        }

        internal static bool PublicSnmpToPrivate(TrafficRecord r)
            => SnmpUdp(r) && Research676Evidence.PublicToPrivate(r);

        internal static bool PrivateSnmpPair(TrafficRecord r)
            => SnmpUdp(r) && Research676Evidence.PrivatePair(r, out _, out _);

        internal static bool OtPayloadPacketToPrivate(TrafficRecord r)
        {
            if (r == null || r.Id == Guid.Empty || r.IpVersion != 4
                || r.IsQuic
                || r.DestinationPort is not (102 or 502 or 20000 or 44818 or 47808 or 50000)
                || r.SourcePort is null or <= 0 or > 65535
                || r.L4Len is null or < 1 or > 4096
                || r.Length < 28
                || r.HttpMethod != null || r.HttpUri != null
                || r.TlsVersion != null || r.Sni != null
                || r.DnsQname != null || r.DnsIsResponse)
                return false;

            var tcp = r.IsTcp && !r.IsUdp
                && string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase);
            var udp = !r.IsTcp && r.IsUdp
                && string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                && r.TcpFlags == null;
            if (!tcp && !udp) return false;

            return IPAddress.TryParse(r.Source, out var source)
                && IPAddress.TryParse(r.Destination, out var destination)
                && source != null && destination != null
                && source.AddressFamily == AddressFamily.InterNetwork
                && destination.AddressFamily == AddressFamily.InterNetwork
                && !source.Equals(destination)
                && Research646Evidence.Private(destination);
        }

        internal static bool MacScreensharingPublicSynAck(TrafficRecord r)
            => Research676Evidence.SynAck(r)
               && Research676Evidence.PrivateToPublic(r)
               && r.SourcePort == 5900
               && Process(r, "screensharingd");

        internal static bool MacSshdPublicSynAck(TrafficRecord r)
            => Research676Evidence.SynAck(r)
               && Research676Evidence.PrivateToPublic(r)
               && r.SourcePort == 22
               && Process(r, "sshd");

        internal static bool MacPostSshToolEgress(TrafficRecord r)
            => Process(r, "zsh", "osascript", "curl", "python3")
               && (Research736Evidence.Tls443(r)
                   || (Research706Evidence.TcpPayload(r)
                       && Research676Evidence.PrivateToPublic(r)
                       && r.DestinationPort is > 1024 and <= 65535));
    }
}
