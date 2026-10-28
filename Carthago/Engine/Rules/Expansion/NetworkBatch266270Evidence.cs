// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Candidate typed-flow predicates; never infer process execution, update blocking
    // or sensor tampering from packet Info or from a port number alone.
    internal static class NetworkBatch266270Evidence
    {
        private static bool Private(IPAddress ip)
        {
            var b = ip.GetAddressBytes();
            return b.Length == 4 && (b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168)
                || b.Length == 16 && (b[0] & 0xfe) == 0xfc;
        }
        private static bool Public(IPAddress ip)
            => !Private(ip) && !IPAddress.IsLoopback(ip) && !ip.IsIPv6LinkLocal
                && !ip.IsIPv6Multicast && !ip.IsIPv6SiteLocal
                && !ip.Equals(IPAddress.Any) && !ip.Equals(IPAddress.IPv6Any)
                && ip.GetAddressBytes()[0] != 0
                && (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                    || ip.GetAddressBytes()[0] is < 224
                        && !(ip.GetAddressBytes()[0] == 169 && ip.GetAddressBytes()[1] == 254)
                        && !(ip.GetAddressBytes()[0] == 100 && ip.GetAddressBytes()[1] is >= 64 and <= 127));
        private static bool Endpoints(TrafficRecord r, out IPAddress source, out IPAddress destination)
        {
            source = IPAddress.None; destination = IPAddress.None;
            return r.Id != Guid.Empty && IPAddress.TryParse(r.Source, out source)
                && IPAddress.TryParse(r.Destination, out destination)
                && source.AddressFamily == destination.AddressFamily && !source.Equals(destination)
                && (r.IpVersion == 4 && source.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                    || r.IpVersion == 6 && source.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
        }
        internal static bool ExternalTcp(TrafficRecord r)
            => Endpoints(r, out var src, out var dst) && Private(src) && Public(dst)
                && r.IsTcp && !r.IsUdp && !r.IsQuic
                && string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                && r.SourcePort is > 0 and <= 65535 && r.DestinationPort is > 0 and <= 65535
                && r.IcmpTypeCode == null && r.DnsIsResponse == false
                && r.ProcessId > 0;
        internal static string Process(TrafficRecord r)
        {
            var value = r.ProcessName;
            if (string.IsNullOrWhiteSpace(value) || value!.Length > 260) return "";
            var basename = value.Trim().Replace('\\', '/').Split('/').Last().ToLowerInvariant();
            return basename.Length is >= 3 and <= 64
                && basename.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-')
                ? basename : "";
        }
        internal static bool ProcessEgress(TrafficRecord r, out string process)
        {
            process = Process(r);
            return ExternalTcp(r) && process.Length > 0
                && r.DnsQname == null && r.IcmpTypeCode == null
                && (r.HttpMethod == null || NetworkBatch131135Evidence.CleartextHttpRequest(r))
                && (r.TlsVersion == null || r.Sni != null);
        }
        private static readonly HashSet<string> CommonProcesses = new(StringComparer.Ordinal) {
            "chrome.exe", "msedge.exe", "firefox.exe", "svchost.exe", "explorer.exe",
            "onedrive.exe", "teams.exe", "system", "services.exe", "lsass.exe"
        };
        internal static bool NewProcessEgress(TrafficRecord r, out string process)
        {
            if (!ProcessEgress(r, out process)) return false;
            return !CommonProcesses.Contains(process);
        }
        private static readonly HashSet<string> MasqueradeNames = new(StringComparer.Ordinal) {
            "svchosts.exe", "scvhost.exe", "svhost.exe", "lsasss.exe", "spoolsv32.exe",
            "explorer32.exe", "rundll32x.exe", "msiexec32.exe", "conhost64.exe", "taskhostw32.exe"
        };
        internal static bool SuspiciousName(TrafficRecord r, out string process)
            => ProcessEgress(r, out process) && MasqueradeNames.Contains(process);

        private static readonly HashSet<string> Interpreters = new(StringComparer.Ordinal) {
            "powershell.exe", "pwsh.exe", "python.exe", "pythonw.exe", "node.exe",
            "bash.exe", "wscript.exe", "cscript.exe", "mshta.exe", "ruby.exe",
            "perl.exe", "php.exe", "cmd.exe"
        };
        internal static bool InterpreterDnsOrHttp(TrafficRecord r, out string kind)
        {
            kind = "";
            var process = Process(r);
            if (!Interpreters.Contains(process) || r.ProcessId <= 0
                || !Endpoints(r, out var src, out var dst) || !Private(src) || !Public(dst)
                || r.IcmpTypeCode != null) return false;
            if (ExternalTcp(r) && NetworkBatch131135Evidence.CleartextHttpRequest(r)
                && r.DnsQname == null && !r.DnsIsResponse)
            {
                kind = "cleartext_http_request"; return true;
            }
            if (r.IsUdp && !r.IsTcp && !r.IsQuic
                && string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                && r.SourcePort is > 0 and <= 65535 && r.DestinationPort == 53
                && string.Equals(r.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase)
                && !r.DnsIsResponse && r.DnsQname is { Length: > 3 and <= 253 }
                && r.DnsQname.Contains('.') && r.DnsQname.All(c =>
                    char.IsAsciiLetterOrDigit(c) || c is '.' or '-')
                && r.DnsQtype is "A" or "AAAA" or "TXT" or "CNAME"
                && r.HttpMethod == null && r.TlsVersion == null && r.Sni == null)
            {
                kind = "typed_dns_query"; return true;
            }
            return false;
        }
        private static readonly HashSet<string> UpdateDomains = new(StringComparer.Ordinal) {
            "definitionupdates.microsoft.com", "database.clamav.net",
            "update.eset.com", "updates.sophos.com"
        };
        internal static bool SecurityUpdateDnsFailure(TrafficRecord r, out string rcode)
        {
            rcode = "";
            if (!Endpoints(r, out var src, out var dst) || !Public(src) || !Private(dst)
                || r.IsTcp || !r.IsUdp || r.IsQuic
                || !string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                || r.SourcePort != 53 || r.DestinationPort is not (> 0 and <= 65535)
                || !string.Equals(r.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase)
                || !r.DnsIsResponse || r.DnsQtype is not ("A" or "AAAA")
                || r.HttpMethod != null || r.TlsVersion != null || r.Sni != null
                || r.IcmpTypeCode != null || r.DnsQname == null
                || !UpdateDomains.Contains(r.DnsQname.TrimEnd('.').ToLowerInvariant())
                || !(string.Equals(r.DnsRcode, "SERVFAIL", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.DnsRcode, "REFUSED", StringComparison.OrdinalIgnoreCase)))
                return false;
            rcode = r.DnsRcode.ToLowerInvariant();
            return true;
        }
        internal sealed class FirstObserved
        {
            private readonly object _gate = new();
            private readonly Dictionary<string, DateTime> _seen = new(StringComparer.Ordinal);
            internal bool Observe(TrafficRecord r, DateTime at, string key)
            {
                if (r.Id == Guid.Empty || at.Kind != DateTimeKind.Utc) return false;
                lock (_gate)
                {
                    if (_seen.ContainsKey(key)) return false;
                    if (_seen.Count >= 1024)
                    {
                        foreach (var old in _seen.Where(x => at - x.Value > TimeSpan.FromHours(1))
                            .Select(x => x.Key).ToArray()) _seen.Remove(old);
                        if (_seen.Count >= 1024) return false;
                    }
                    _seen.Add(key, at);
                    return true;
                }
            }
        }
        internal sealed class DistinctWindow
        {
            private sealed class Slot
            {
                internal readonly Queue<(Guid Id, DateTime At)> Items = new();
                internal readonly HashSet<Guid> Seen = new();
                internal DateTime Latest = DateTime.MinValue;
            }
            private readonly object _gate = new();
            private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);
            internal int Observe(TrafficRecord r, DateTime at, string key, TimeSpan window)
            {
                if (r.Id == Guid.Empty || at.Kind != DateTimeKind.Utc) return 0;
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
                        var old = slot.Items.Dequeue(); slot.Seen.Remove(old.Id);
                    }
                    if (slot.Items.Count >= 256) return 0;
                    slot.Items.Enqueue((r.Id, at)); slot.Seen.Add(r.Id); slot.Latest = at;
                    return slot.Items.Count;
                }
            }
        }
    }
}
