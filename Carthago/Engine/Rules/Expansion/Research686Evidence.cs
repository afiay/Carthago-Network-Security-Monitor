// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Shared input hygiene only; predicates remain rule-specific.
using System;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class Research686Evidence
    {
        private static readonly string[] FileSharingRoots =
        {
            "githubusercontent.com", "0x0.st", "anonfiles.com", "bashupload.com",
            "cdn.discordapp.com", "dl.dropboxusercontent.com", "gofile.io", "mediafire.com",
            "mega.nz", "pastebin.com", "pixeldrain.com", "storage.googleapis.com",
            "temp.sh", "transfer.sh", "ufile.io", "workers.dev", "x0.at"
        };

        internal static bool Process(TrafficRecord r, params string[] expected)
        {
            if (r == null || r.ProcessId <= 0) return false;
            var process = NetworkBatch266270Evidence.Process(r);
            return process.Length > 0 && expected.Contains(process, StringComparer.Ordinal);
        }

        internal static bool PrivateToPublic(TrafficRecord r)
            => Research646Evidence.Pair(r, false, out _, out _);

        internal static bool HttpGetToDestinationIp(TrafficRecord r, params string[] process)
        {
            if (!Process(r, process)
                || !PrivateToPublic(r)
                || !WebSignatureRequestEvidence.TryGet(r, out var method, out _)
                || method != "GET"
                || r.HttpHost == null
                || !IPAddress.TryParse(r.HttpHost, out var host)
                || !IPAddress.TryParse(r.Destination, out var destination)
                || !host.Equals(destination))
                return false;
            return r.DestinationPort is 80 or 8080 or 8000 or 8888;
        }

        internal static bool HostIsFileSharing(string? value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length > 253) return false;
            var host = value.Trim().TrimEnd('.').ToLowerInvariant();
            if (host.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-'))) return false;
            foreach (var root in FileSharingRoots)
                if (host == root || host.EndsWith("." + root, StringComparison.Ordinal))
                    return true;
            return false;
        }

        internal static bool ProcessFileSharingContact(TrafficRecord r, params string[] processes)
        {
            if (!Process(r, processes) || !PrivateToPublic(r) || !r.IsTcp || r.IsUdp || r.IsQuic)
                return false;
            if (r.TlsVersion != null && r.Sni != null && r.HttpMethod == null
                && HostIsFileSharing(r.Sni) && r.DestinationPort == 443)
                return true;
            return WebSignatureRequestEvidence.TryGet(r, out var method, out _)
                && method == "GET" && HostIsFileSharing(r.HttpHost);
        }

        internal static bool SuspiciousFilePath(string uri)
        {
            var q = uri.IndexOf('?');
            var path = (q < 0 ? uri : uri.Substring(0, q)).ToLowerInvariant();
            return path.EndsWith(".exe", StringComparison.Ordinal)
                || path.EndsWith(".dll", StringComparison.Ordinal)
                || path.EndsWith(".ps1", StringComparison.Ordinal)
                || path.EndsWith(".psm1", StringComparison.Ordinal)
                || path.EndsWith(".vbs", StringComparison.Ordinal)
                || path.EndsWith(".vbe", StringComparison.Ordinal)
                || path.EndsWith(".hta", StringComparison.Ordinal)
                || path.EndsWith(".bat", StringComparison.Ordinal)
                || path.EndsWith(".msi", StringComparison.Ordinal)
                || path.EndsWith(".sct", StringComparison.Ordinal);
        }

        internal static bool ExternalSmbSyn(TrafficRecord r, params string[] process)
            => Process(r, process) && PrivateToPublic(r)
                && Research676Evidence.Syn(r) && r.DestinationPort == 445;

        internal static bool ExternalWebDav(TrafficRecord r, params string[] process)
            => Process(r, process) && PrivateToPublic(r)
                && NetworkBatch171175Evidence.DavHttp(r);

        internal static bool ExternalCleartextHttpGet(TrafficRecord r, params string[] process)
            => Process(r, process) && PrivateToPublic(r)
                && WebSignatureRequestEvidence.TryGet(r, out var method, out _)
                && method == "GET";

        internal static bool ToolExternalTcp(TrafficRecord r, params string[] process)
            => Process(r, process)
                && NetworkBatch266270Evidence.ProcessEgress(r, out var observed)
                && process.Contains(observed, StringComparer.Ordinal);
    }
}
