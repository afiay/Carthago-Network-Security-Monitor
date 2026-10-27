// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Carthago.Models;
namespace Carthago.Engine.Rules
{
    // Narrow evidence validators for R091–R095. Never inspect untrusted packet Info.
    internal static class NetworkBatch091095Evidence
    {
        private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

        internal static bool Http(RuleEvaluationContext c)
            => NetworkBatch081085Evidence.HttpRequest(c) && !c.Record.DnsIsResponse
               && c.Record.DnsQname == null && !c.Record.IsQuic;

        private static bool Pattern(string s, string expression)
        {
            try { return Regex.IsMatch(s, expression, Options, TimeSpan.FromMilliseconds(50)); }
            catch (RegexMatchTimeoutException) { return false; }
        }

        internal static bool ScannerAgent(RuleEvaluationContext c)
        {
            if (!Http(c)) return false;
            var ua = c.Record.HttpUserAgent;
            if (string.IsNullOrWhiteSpace(ua) || ua.Length > 512 || ua.IndexOfAny(new[]{'\r','\n','\0'})>=0)
                return false;
            // Identifies a scanner's self-declared agent; does not establish
            // unauthorized scanning or corroborate the claimed executable.
            return Pattern(ua, @"(?:^|[\s(;])(?:nmap|masscan|zgrab|zmap|nikto|sqlmap|gobuster|ffuf)(?:[/\s;)]|$)");
        }

        internal static bool MalwareEndpoint(RuleEvaluationContext c)
        {
            if (!NetworkBatch086090Evidence.TryTarget(c, out var target)) return false;
            if (!Uri.TryCreate("http://example.invalid"+(target.StartsWith("/") ? target : "/"), UriKind.Absolute, out var uri))
                return false;
            var path=uri.AbsolutePath;
            // Only specific endpoint shape; generic '/bot', '/panel', '/cnc'
            // are too common to justify a malware attribution.
            return Pattern(path, @"(?:^|/)(?:gate\.php|c2/gate\.php)(?:$|/)");
        }

        internal static bool PowerShellCradle(RuleEvaluationContext c)
        {
            if (!NetworkBatch086090Evidence.TryTarget(c, out var target)) return false;
            if (target.Length>4096) return false;
            var executable=Pattern(target, @"(?:^|[=&;\s])(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)(?:\s|$)");
            var retrieval=Pattern(target, @"(?:downloadstring\s*\(|invoke-webrequest\b|iwr\b|new-object\s+net\.webclient)");
            var execution=Pattern(target, @"(?:\biex\b|invoke-expression\b|\|\s*iex\b)");
            return executable && retrieval && execution;
        }

        internal static bool DnsQuestion(RuleEvaluationContext c)
        {
            var r=c.Record;
            if (r.Id==Guid.Empty || !NetworkBatch076080Evidence.ValidTime(c)
                || r.DnsIsResponse || string.IsNullOrWhiteSpace(r.DnsQname)
                || r.DnsQname!.Length>253 || r.HttpMethod!=null || r.HttpUri!=null
                || r.HttpRequestHeaders!=null || r.IsQuic || r.IcmpTypeCode.HasValue
                || !IPAddress.TryParse(r.Source,out var src)
                || !IPAddress.TryParse(r.Destination,out var dst)
                || src.AddressFamily!=dst.AddressFamily || src.Equals(dst)
                || r.IpVersion == 4 && src.AddressFamily!=AddressFamily.InterNetwork
                || r.IpVersion == 6 && src.AddressFamily!=AddressFamily.InterNetworkV6
                || r.IpVersion is not (null or 4 or 6)
                || !(string.Equals(r.Protocol,"DNS",StringComparison.OrdinalIgnoreCase)
                   || string.Equals(r.ApplicationProtocol,"DNS",StringComparison.OrdinalIgnoreCase))
                || !r.IsUdp && !r.IsTcp || r.IsUdp && r.IsTcp
                || r.IsUdp && r.TcpFlags.HasValue
                || !new[]{"A","AAAA","TXT","CNAME","MX","NS","SRV","PTR"}
                    .Contains(r.DnsQtype,StringComparer.OrdinalIgnoreCase))
                return false;
            if (r.IsTcp && (!string.Equals(r.Protocol,"TCP",StringComparison.OrdinalIgnoreCase)
                           && !string.Equals(r.Protocol,"DNS",StringComparison.OrdinalIgnoreCase)
                           || r.TcpFlags is ushort flags && ((flags&0x07)!=0 || (flags&0x18)==0)))
                return false;
            var name=r.DnsQname.Trim().TrimEnd('.');
            if (name.Length==0 || name.IndexOf('.') < 0) return false;
            foreach(var label in name.Split('.'))
            {
                if (label.Length is < 1 or > 63 || label[0]=='-' || label[^1]=='-'
                    || label.Any(x=>!char.IsAsciiLetterOrDigit(x)&&x!='-'&&x!='_')) return false;
            }
            return true;
        }

        internal static RuleEvaluationResult Alert(RuleDescriptor d,RuleEvaluationContext c,string summary)
            => NetworkBatch081085Evidence.Match(d,c,summary);
    }
}
