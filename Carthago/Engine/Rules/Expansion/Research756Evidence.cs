// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Shared evidence validation/state only; no behavioral convergence.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class Research756Evidence
    {
        internal static bool Process(TrafficRecord r, params string[] names)
            => Research676Evidence.Process(r, names);

        internal static bool EsxiProcess(TrafficRecord r)
            => Research746Evidence.HypervisorProcess(r);

        internal static bool LinuxVncProcess(TrafficRecord r)
            => Process(r, "x11vnc", "vncserver", "xvnc", "xtigervnc");

        internal static bool MacScriptProcess(TrafficRecord r)
            => Process(r, "osascript", "python", "python3");

        internal static bool RmmProcess(TrafficRecord r)
            => Process(r, "teamviewer.exe", "teamviewer_desktop.exe", "anydesk.exe",
                "screenconnect.clientservice.exe", "screenconnect.windowsclient.exe",
                "connectwisecontrol.client.exe");

        internal static bool MsbuildProcess(TrafficRecord r)
            => Process(r, "msbuild.exe", "msbuild");

        internal static bool EsxiDnsTool(TrafficRecord r)
            => Process(r, "busybox", "nslookup");

        internal static bool LinuxDnsTunnelTool(TrafficRecord r)
            => Process(r, "iodine", "iodined", "dnscat2", "dnscat2-client", "dig");

        internal static bool LinuxShellTool(TrafficRecord r)
            => Process(r, "bash", "sh", "zsh", "curl", "wget", "python", "python3");

        internal static bool CodeRepositoryHost(string? host)
            => Research746Evidence.CodeRepositoryHost(host);

        internal static bool Tls443(TrafficRecord r)
            => Research736Evidence.Tls443(r);

        internal static bool EsxiRepositoryTls(TrafficRecord r)
            => Tls443(r) && EsxiProcess(r) && CodeRepositoryHost(r.Sni);

        internal static bool LlmnrNbnsConflict(RuleEvaluationContext context, out string responder, out string peer)
        {
            responder = peer = string.Empty;
            if (!NetworkBatch081085Evidence.NameServiceConflict(context, out responder, out peer, out _))
                return false;
            return IPAddress.TryParse(responder, out var r)
                && IPAddress.TryParse(peer, out var p)
                && r != null && p != null
                && Research646Evidence.Private(r)
                && Research646Evidence.Private(p);
        }

        internal static bool SmbSynToResponder(TrafficRecord r)
            => Research676Evidence.Syn(r)
               && Research676Evidence.PrivatePair(r, out _, out _)
               && r.DestinationPort == 445;

        internal static bool PublicUncommonTrigger(TrafficRecord r)
            => Research676Evidence.Syn(r)
               && Research676Evidence.PublicToPrivate(r)
               && r.DestinationPort is >= 1024 and <= 65535
               && r.DestinationPort is not (3306 or 3389 or 5432 or 5900 or 5985 or 5986 or 6379
                    or 8080 or 8443 or 11211);

        internal static bool ReversePublicSyn(TrafficRecord r)
            => Research676Evidence.Syn(r) && Research676Evidence.PrivateToPublic(r);

        internal static bool VncProcessSynAck(TrafficRecord r)
            => Research676Evidence.SynAck(r)
               && Research676Evidence.PrivateToPublic(r)
               && r.SourcePort == 5900
               && LinuxVncProcess(r);

        internal static bool MacBrowserUaHttp(TrafficRecord r, out string method)
        {
            method = string.Empty;
            return WebSignatureRequestEvidence.TryGet(r, out method, out _)
                && method is "GET" or "POST"
                && Research676Evidence.PrivateToPublic(r)
                && MacScriptProcess(r)
                && Research716Evidence.BrowserLikeUserAgent(r.HttpUserAgent)
                && r.HttpUserAgent!.Contains("Macintosh", StringComparison.OrdinalIgnoreCase);
        }

        internal static bool RmmTlsPayload(TrafficRecord r)
            => Tls443(r) && RmmProcess(r) && r.L4Len is >= 100 and <= 1200;

        internal static bool MsbuildTlsPayload(TrafficRecord r)
            => Tls443(r) && MsbuildProcess(r) && r.L4Len is >= 900 and <= 8192;

        internal static bool HighEntropyPublicDns(TrafficRecord r, out string query, out string root)
        {
            query = root = string.Empty;
            if (!DnsSignatureRequestEvidence.TryGetQuery(r, out query)
                || !Research676Evidence.PrivateToPublic(r)
                || !Research716Evidence.HighEntropyDnsQuery(query))
                return false;
            var labels = query.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (labels.Length < 2) return false;
            root = labels[^2] + "." + labels[^1];
            return true;
        }

        internal static bool LinuxRemoteServiceTrigger(TrafficRecord r)
            => Research676Evidence.Syn(r)
               && Research676Evidence.PublicToPrivate(r)
               && r.DestinationPort is 22 or 80 or 111 or 139 or 443 or 445 or 2049 or 3306 or 5432;

        internal static bool LinuxShellEgress(TrafficRecord r)
            => LinuxShellTool(r)
               && (Tls443(r)
                   || (Research706Evidence.TcpPayload(r)
                       && Research676Evidence.PrivateToPublic(r)
                       && r.DestinationPort is > 1024 and <= 65535));

        internal static string RedactedQueryKey(string root, int length)
            => root + "|len:" + length.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    internal sealed class Research756PeerSequenceWindow
    {
        private sealed class Start
        {
            internal Guid Id;
            internal string Peer = string.Empty;
            internal DateTime At;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, Start> _pending = new(StringComparer.Ordinal);

        internal bool Observe(string key, string peer, Guid id, DateTime at, bool trigger, int maxSeconds)
        {
            if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(peer)
                || id == Guid.Empty || at.Kind != DateTimeKind.Utc
                || maxSeconds is < 5 or > 180)
                return false;

            lock (_gate)
            {
                if (trigger)
                {
                    if (_pending.Count >= 512)
                    {
                        foreach (var stale in _pending
                            .Where(x => at >= x.Value.At && at - x.Value.At > TimeSpan.FromMinutes(5))
                            .Select(x => x.Key).ToArray())
                            _pending.Remove(stale);
                        if (_pending.Count >= 512) return false;
                    }

                    if (_pending.TryGetValue(key, out var existing) && at <= existing.At)
                        return false;

                    _pending[key] = new Start { Id = id, Peer = peer, At = at };
                    return false;
                }

                if (!_pending.TryGetValue(key, out var start)
                    || start.Id == id
                    || !string.Equals(start.Peer, peer, StringComparison.Ordinal)
                    || at <= start.At
                    || at - start.At > TimeSpan.FromSeconds(maxSeconds))
                    return false;

                _pending.Remove(key);
                return true;
            }
        }
    }

    internal sealed class Research756HostSequenceWindow
    {
        private sealed class Start
        {
            internal Guid Id;
            internal DateTime At;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, Start> _pending = new(StringComparer.Ordinal);

        internal bool Observe(string host, Guid id, DateTime at, bool trigger, int maxSeconds)
        {
            if (string.IsNullOrWhiteSpace(host) || id == Guid.Empty || at.Kind != DateTimeKind.Utc
                || maxSeconds is < 5 or > 180)
                return false;

            lock (_gate)
            {
                if (trigger)
                {
                    if (_pending.Count >= 512)
                    {
                        foreach (var stale in _pending
                            .Where(x => at >= x.Value.At && at - x.Value.At > TimeSpan.FromMinutes(5))
                            .Select(x => x.Key).ToArray())
                            _pending.Remove(stale);
                        if (_pending.Count >= 512) return false;
                    }

                    if (_pending.TryGetValue(host, out var existing) && at <= existing.At)
                        return false;

                    _pending[host] = new Start { Id = id, At = at };
                    return false;
                }

                if (!_pending.TryGetValue(host, out var start)
                    || start.Id == id
                    || at <= start.At
                    || at - start.At > TimeSpan.FromSeconds(maxSeconds))
                    return false;

                _pending.Remove(host);
                return true;
            }
        }
    }
}
