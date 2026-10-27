// SPDX-License-Identifier: MIT
using System;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
namespace Carthago.Engine.Rules
{
    // Validated packet fields only; free-form Info is not corroborated telemetry.
    internal static class NetworkBatch106110Evidence
    {
        internal static bool StructuredFlow(RuleEvaluationContext c)
        {
            var r=c.Record;
            if(r.Id==Guid.Empty || !NetworkBatch076080Evidence.ValidTime(c)
                || !r.IsTcp || r.IsUdp || r.IsQuic || r.IcmpTypeCode.HasValue
                || r.DnsQname!=null || r.DnsIsResponse || r.DnsAnswers!=null
                || !string.Equals(r.Protocol,"TCP",StringComparison.OrdinalIgnoreCase)
                || !IPAddress.TryParse(r.Source,out var src)
                || !IPAddress.TryParse(r.Destination,out var dst)
                || src.Equals(dst) || src.AddressFamily!=dst.AddressFamily
                || r.IpVersion==4 && src.AddressFamily!=AddressFamily.InterNetwork
                || r.IpVersion==6 && src.AddressFamily!=AddressFamily.InterNetworkV6
                || r.IpVersion is not (null or 4 or 6)
                || r.TcpFlags is ushort f && ((f&0x07)!=0 || (f&0x18)==0)
                || Math.Max(r.Length,r.L4Len??0)<=0)
                return false;
            return r.HttpHost==null || r.Sni==null
                || r.HttpHost.Equals(r.Sni,StringComparison.OrdinalIgnoreCase);
        }
        internal static bool InternalAdminProbe(RuleEvaluationContext c)
        {
            var r=c.Record;
            if(!StructuredFlow(c) || !IPAddress.TryParse(r.Source,out var src)
                || !IPAddress.TryParse(r.Destination,out var dst)
                || !Private(src) || !Private(dst)
                || r.DestinationPort is not int port
                || port is not (22 or 135 or 139 or 445 or 3389 or 5985 or 5986 or 5900 or 1433 or 3306 or 5432)
                || r.HttpMethod!=null || r.HttpUri!=null) return false;
            return true;
        }
        internal static bool StructuredHttpRead(RuleEvaluationContext c)
        {
            var r=c.Record;
            return StructuredFlow(c)
                && string.Equals(r.ApplicationProtocol,"HTTP",StringComparison.OrdinalIgnoreCase)
                && string.Equals(r.HttpMethod,"GET",StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(r.HttpHost??r.Sni)
                && !string.IsNullOrWhiteSpace(r.HttpUri) && r.HttpUri!.Length<=4096
                && r.HttpUri.IndexOfAny(new[]{'\r','\n','\0'})<0;
        }
        internal static bool GitPayloadPath(TrafficRecord r)
        {
            var path=(r.HttpUri??string.Empty).Split('?', '#')[0];
            return path.EndsWith(".ps1",StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".dll",StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".sh",StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".zip",StringComparison.OrdinalIgnoreCase)
                || path.Contains("/-/raw/",StringComparison.OrdinalIgnoreCase)
                || path.Contains("/releases/download/",StringComparison.OrdinalIgnoreCase);
        }
        internal static bool ChatActionPath(TrafficRecord r)
        {
            var path=(r.HttpUri??string.Empty).Split('?', '#')[0];
            return path.Contains("sendDocument",StringComparison.OrdinalIgnoreCase)
                || path.Contains("sendPhoto",StringComparison.OrdinalIgnoreCase)
                || path.Contains("sendVideo",StringComparison.OrdinalIgnoreCase)
                || path.Contains("sendMessage",StringComparison.OrdinalIgnoreCase)
                || path.Contains("/api/webhooks/",StringComparison.OrdinalIgnoreCase)
                || path.Contains("/api/files.upload",StringComparison.OrdinalIgnoreCase)
                || path.Contains("/api/chat.postMessage",StringComparison.OrdinalIgnoreCase)
                || path.Contains("/services/",StringComparison.OrdinalIgnoreCase);
        }
        private static bool Private(IPAddress ip)
        {
            if(ip.AddressFamily==AddressFamily.InterNetwork)
            {
                var b=ip.GetAddressBytes();
                return b[0]==10 || b[0]==172 && b[1]>=16 && b[1]<=31
                    || b[0]==192 && b[1]==168;
            }
            return ip.AddressFamily==AddressFamily.InterNetworkV6
                && (ip.IsIPv6LinkLocal || (ip.GetAddressBytes()[0]&0xfe)==0xfc);
        }
    }
}
