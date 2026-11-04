// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Shared field validation/state only; no rule convergence.
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class Research746Evidence
    {
        internal static bool Process(TrafficRecord r, params string[] names)
            => Research676Evidence.Process(r, names);

        internal static bool PrivateToPublic(TrafficRecord r)
            => Research676Evidence.PrivateToPublic(r);

        internal static bool PrivatePair(TrafficRecord r)
            => Research676Evidence.PrivatePair(r, out _, out _);

        internal static bool HypervisorProcess(TrafficRecord r)
            => Process(r, "hostd", "hostd.exe", "vpxa", "vpxa.exe", "vmx", "vmx.exe");

        internal static bool WindowsArchiveProcess(TrafficRecord r)
            => Process(r, "7z.exe", "7za.exe", "7zz.exe", "winrar.exe", "rar.exe");

        internal static bool LinuxCryptoProcess(TrafficRecord r)
            => Process(r, "openssl", "gpg", "gpg2", "age", "age-keygen");

        internal static bool EsxiFtpProcess(TrafficRecord r)
            => Process(r, "busybox", "curl", "wget", "ftpput", "lftp");

        internal static bool MacCloudProcess(TrafficRecord r)
            => Process(r, "osascript", "microsoft word", "microsoft excel", "preview");

        internal static bool MacRepositoryProcess(TrafficRecord r)
            => Process(r, "osascript", "curl", "git", "microsoft word", "microsoft excel");

        internal static bool MacLateralTransferProcess(TrafficRecord r)
            => Process(r, "scp", "sftp", "rsync");

        internal static bool MacCadenceProcess(TrafficRecord r)
            => Process(r, "osascript");

        internal static bool MacFollowOnProcess(TrafficRecord r)
            => Process(r, "osascript", "zsh", "curl", "python3");

        internal static bool CodeRepositoryHost(string? host)
            => Research656Evidence.HostIs(host, "github.com")
               || Research656Evidence.HostIs(host, "gitlab.com")
               || Research656Evidence.HostIs(host, "bitbucket.org");

        internal static bool Tls443(TrafficRecord r)
            => Research736Evidence.Tls443(r);

        internal static bool NonstandardTls(TrafficRecord r)
            => Research676Evidence.Tcp(r)
               && PrivateToPublic(r)
               && r.DestinationPort is 4443 or 7443 or 9443 or 10443 or 12443
               && r.TlsVersion != null
               && !string.IsNullOrWhiteSpace(r.Sni)
               && r.L4Len is >= 32 and <= 8192
               && r.HttpMethod == null && r.HttpUri == null
               && r.DnsQname == null && !r.DnsIsResponse;

        internal static bool UncommonRawPayload(TrafficRecord r)
            => Research706Evidence.TcpPayload(r)
               && PrivateToPublic(r)
               && r.DestinationPort is >= 1024 and <= 65535
               && r.DestinationPort is not (1883 or 2375 or 3306 or 3389 or 4443 or 5432 or 6379
                   or 7443 or 8080 or 8443 or 873 or 902 or 903 or 9443 or 10443 or 11211 or 12443);

        internal static bool MacLateralPayload(TrafficRecord r)
            => Research706Evidence.TcpPayload(r)
               && PrivatePair(r)
               && r.DestinationPort is 22 or 873;

        internal static bool RemoteMsiHttpGet(TrafficRecord r)
        {
            if (!WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "GET"
                || !PrivateToPublic(r)
                || !Process(r, "msiexec.exe", "msiexec"))
                return false;

            var queryIndex = uri.IndexOf('?');
            var path = queryIndex >= 0 ? uri[..queryIndex] : uri;
            return path.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".msp", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".mst", StringComparison.OrdinalIgnoreCase);
        }

        internal static bool VncIngressSyn(TrafficRecord r)
            => Research676Evidence.Syn(r)
               && Research676Evidence.PublicToPrivate(r)
               && r.DestinationPort == 5900;

        internal static bool MacScriptEgress(TrafficRecord r)
            => MacFollowOnProcess(r)
               && (Tls443(r) || UncommonRawPayload(r));
    }

    internal sealed class Research746VncBridgeWindow
    {
        private sealed class Trigger
        {
            internal Guid Id;
            internal DateTime At;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, Trigger> _pending = new(StringComparer.Ordinal);

        internal bool Observe(string localHost, Guid id, DateTime at, bool trigger)
        {
            if (string.IsNullOrWhiteSpace(localHost) || id == Guid.Empty || at.Kind != DateTimeKind.Utc)
                return false;

            lock (_gate)
            {
                if (trigger)
                {
                    if (_pending.Count >= 512)
                    {
                        foreach (var stale in _pending
                            .Where(x => at >= x.Value.At && at - x.Value.At > TimeSpan.FromMinutes(3))
                            .Select(x => x.Key).ToArray())
                            _pending.Remove(stale);
                        if (_pending.Count >= 512) return false;
                    }

                    if (_pending.TryGetValue(localHost, out var previous) && at <= previous.At)
                        return false;

                    _pending[localHost] = new Trigger { Id = id, At = at };
                    return false;
                }

                if (!_pending.TryGetValue(localHost, out var start)
                    || start.Id == id
                    || at <= start.At
                    || at - start.At > TimeSpan.FromSeconds(90))
                    return false;

                _pending.Remove(localHost);
                return true;
            }
        }
    }
}
