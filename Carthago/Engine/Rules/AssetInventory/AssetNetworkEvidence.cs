// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services.Baseline;

namespace Carthago.Engine.Rules.AssetInventory;

internal static class AssetNetworkEvidence
{
    private static readonly HashSet<int> Ports = new()
    { 21,22,25,53,80,135,139,143,389,443,445,636,993,1433,3306,3389,5432,5985,5986,6379,8080,8443,9200,27017 };

    internal static bool Private(string? text, out string normalized)
    {
        normalized = "";
        if (!IPAddress.TryParse(text, out var a) || a.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = a.GetAddressBytes();
        if (!(b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
              (b[0] == 192 && b[1] == 168))) return false;
        normalized = a.ToString();
        return true;
    }
    internal static bool Public(string? text, out string normalized)
    {
        normalized = "";
        if (!IPAddress.TryParse(text, out var a) || a.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = a.GetAddressBytes();
        if (b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224
            || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
            || (b[0] == 169 && b[1] == 254)
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 192 && (b[1] == 168 || b[1] == 0))
            || (b[0] == 198 && (b[1] == 18 || b[1] == 19 || (b[1] == 51 && b[2] == 100)))
            || (b[0] == 203 && b[1] == 0 && b[2] == 113)) return false;
        normalized = a.ToString();
        return true;
    }
    internal static bool Outbound(RuleEvaluationContext c, out string src, out string dst)
    {
        src = dst = "";
        var r = c.Record;
        if (!Private(r.Source, out src) || !Public(r.Destination, out dst)
            || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
            || !r.DestinationPort.HasValue || r.DestinationPort.Value < 1 || r.DestinationPort.Value > 65535
            || r.DnsIsResponse || r.DnsQname is not null
            || string.Equals(r.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase))
            return false;
        if (r.TcpFlags is ushort f) return (f & 0x12) == 0x02 && (f & 0x05) == 0;
        return !string.IsNullOrWhiteSpace(r.ApplicationProtocol);
    }
    internal static bool SensitiveSource(TrafficRecord r)
    {
        var p = r.SourcePort;
        var proc = r.ProcessName?.Trim();
        var service = r.ApplicationService?.Trim();
        return p == 1433 && (Equals(proc,"sqlservr") || Equals(service,"sql server")
            || (r.Info?.Contains("sql server", StringComparison.OrdinalIgnoreCase) ?? false))
            || p == 5432 && (Equals(proc,"postgres") || Equals(service,"postgresql"))
            || p == 3306 && (Equals(proc,"mysqld") || Equals(service,"mysql"))
            || p == 6379 && (Equals(proc,"redis-server") || Equals(service,"redis"));
    }
    private static bool Equals(string? a, string b) => string.Equals(a,b,StringComparison.OrdinalIgnoreCase);
    internal static bool ServerReply(RuleEvaluationContext c, out string host, out int port)
    {
        host = ""; port = 0;
        var r = c.Record;
        if (!Private(r.Source, out host) || !Private(r.Destination, out var peer) || host == peer
            || !Equals(r.Protocol,"TCP") || !r.SourcePort.HasValue || !Ports.Contains(r.SourcePort.Value)
            || !r.TcpFlags.HasValue || (r.TcpFlags.Value & 0x17) != 0x12) return false;
        port = r.SourcePort.Value;
        return true;
    }
    internal static bool Inbound(RuleEvaluationContext c, out string host, out string peer, out int port)
    {
        host = peer = ""; port = 0;
        var r = c.Record;
        if (!Private(r.Source, out peer) || !Private(r.Destination, out host) || host == peer
            || !Equals(r.Protocol,"TCP") || !r.DestinationPort.HasValue || !Ports.Contains(r.DestinationPort.Value))
            return false;
        if (r.TcpFlags is ushort flags)
        {
            if ((flags & 0x12) != 0x02 || (flags & 0x05) != 0) return false;
        }
        else if (string.IsNullOrWhiteSpace(r.ApplicationProtocol)
            || !(r.Info?.Contains("Inbound connection to unrecognized internal service",
                 StringComparison.OrdinalIgnoreCase) ?? false)) return false;
        if (new[] { "nginx","apache","httpd","iis","sqlservr","postgres","mysqld" }
            .Contains(r.ProcessName?.Trim(), StringComparer.OrdinalIgnoreCase)) return false;
        port = r.DestinationPort.Value;
        return true;
    }
    internal static bool Asn(string? raw, out string value)
    {
        value = "";
        var s = raw?.Trim() ?? "";
        if (s.StartsWith("AS",StringComparison.OrdinalIgnoreCase)) s = s.Substring(2);
        if (s.Length is < 1 or > 10 || s.Any(x => x < '0' || x > '9')
            || !uint.TryParse(s, out var n) || n == 0) return false;
        value = "AS" + n.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return true;
    }
    internal static DetectionEvent Alert(RuleDescriptor d, RuleEvaluationContext c, string summary)
    {
        var r = c.Record;
        var e = new DetectionEvent
        {
            RuleId=d.RuleId, RuleName=d.Name, TimestampUtc=c.TimestampUtc,
            Severity=d.DefaultSeverity, SourceIp=r.Source, DestinationIp=r.Destination,
            SourcePort=r.SourcePort, DestinationPort=r.DestinationPort, Protocol=r.Protocol,
            Summary=summary, Description=summary, Count=1,
            Evidence="Corroborated structured network evidence; authorization and asset role are not inferred."
        };
        var intelligence = RuleIntelligenceFactory.CreateDefault(d);
        e.RuleMaturityAtDetection=intelligence.Maturity.ToString();
        e.RuleRevisionAtDetection=intelligence.Revision;
        ConfidenceBuilder.ApplyDefault(e,d,intelligence);
        return e;
    }
}
internal sealed class AssetNetworkState
{
    private sealed class State
    {
        internal DateTime Last;
        internal readonly Dictionary<string,DateTime> Known = new(StringComparer.Ordinal);
        internal readonly Dictionary<string,DateTime> Candidates = new(StringComparer.Ordinal);
        internal bool Reported;
    }
    private readonly Dictionary<string,State> _hosts = new(StringComparer.Ordinal);
    private readonly object _lock = new();
    // A new value requires two distinct observations after the required known-value warmup.
    internal bool Novel(string host,string value,DateTime now,int warmup,bool ready,bool firstPersisted)
    {
        lock (_lock)
        {
            var s=Get(host,now);
            if (now <= s.Last) return false;
            s.Last=now;
            if (s.Known.ContainsKey(value)) return false;
            if (s.Candidates.TryGetValue(value,out var first))
            {
                if (now-first>TimeSpan.FromMinutes(2))
                {
                    s.Candidates[value]=now;
                    return false;
                }
                s.Candidates.Remove(value);
                if (s.Known.Count >= 64)
                    s.Known.Remove(s.Known.OrderBy(x => x.Value).First().Key);
                s.Known[value]=now;
                return ready;
            }
            if (s.Known.Count >= warmup && ready && firstPersisted)
            {
                if(s.Candidates.Count<64) s.Candidates[value]=now;
            }
            else if(s.Known.Count<64) s.Known[value]=now;
            return false;
        }
    }
    internal bool Service(string host,int port,DateTime now) =>
        Novel(host,port.ToString(System.Globalization.CultureInfo.InvariantCulture),now,1,true,true);
    internal bool FanIn(string host,string peer,DateTime now)
    {
        lock (_lock)
        {
            var s=Get(host,now);
            if(now<=s.Last) return false;
            s.Last=now;
            foreach(var old in s.Known.Where(x=>now-x.Value>TimeSpan.FromMinutes(5))
                .Select(x=>x.Key).ToArray()) s.Known.Remove(old);
            if(s.Known.Count<5) s.Reported=false;
            if(s.Known.Count>=256 && !s.Known.ContainsKey(peer))
                s.Known.Remove(s.Known.OrderBy(x=>x.Value).First().Key);
            s.Known[peer]=now;
            if(s.Known.Count>=5 && !s.Reported){s.Reported=true;return true;}
            return false;
        }
    }
    private State Get(string key,DateTime now)
    {
        foreach(var old in _hosts.Where(x=>now-x.Value.Last>TimeSpan.FromMinutes(30))
            .Select(x=>x.Key).ToArray()) _hosts.Remove(old);
        if(_hosts.Count>=2048 && !_hosts.ContainsKey(key))
            _hosts.Remove(_hosts.OrderBy(x=>x.Value.Last).First().Key);
        if(!_hosts.TryGetValue(key,out var s)) _hosts[key]=s=new State();
        return s;
    }
}
internal static class AssetNetworkBaseline
{
    internal static async Task<bool> Observe(AssetNetworkState state,RuleEvaluationContext c,
        string kind,string host,string value,int warmup,CancellationToken token)
    {
        var store=BaselineStore.Current;
        var decision=await store.ObserveAsync(new BaselineObservation(kind,host,value,c.TimestampUtc,
            "Validated network observation; no raw application payload or organization metadata."),
            token).ConfigureAwait(false);
        return state.Novel(host,value,c.TimestampUtc,warmup,
            !decision.IsLearningMode && store.Readiness.IsReady,decision.IsFirstSeen);
    }
}
