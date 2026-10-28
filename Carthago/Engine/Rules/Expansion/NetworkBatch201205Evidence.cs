// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Only typed HTTP request fields qualify; packet Info is never used to
    // assert API calls, registry success, file reads or credential exposure.
    internal static class NetworkBatch201205Evidence
    {
        private static bool Http(TrafficRecord r, out Uri uri)
        {
            uri = null!;
            return NetworkBatch166170Evidence.Http(r)
                && NetworkBatch156165Evidence.UriOf(r, out uri)
                && !string.IsNullOrWhiteSpace(r.HttpMethod)
                && !string.IsNullOrWhiteSpace(r.HttpHost);
        }

        internal static bool KubernetesTokenRequest(TrafficRecord r, out string classifier)
        {
            classifier = "";
            if (!Http(r, out var uri) || !r.HttpMethod!.Equals("POST", StringComparison.OrdinalIgnoreCase)
                || !(r.HttpHost!.Equals("kubernetes.default.svc", StringComparison.OrdinalIgnoreCase)
                    || r.HttpHost.Equals("kubernetes.default.svc.cluster.local", StringComparison.OrdinalIgnoreCase)))
                return false;
            var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (segments.Length != 7 || !segments[0].Equals("api", StringComparison.OrdinalIgnoreCase)
                || segments[1] != "v1" || segments[2] != "namespaces"
                || segments[4] != "serviceaccounts" || segments[6] != "token"
                || segments[3].Length is < 1 or > 63 || segments[5].Length is < 1 or > 63)
                return false;
            classifier = "serviceaccount_tokenrequest_api";
            return true;
        }

        private static bool External(string? ip)
        {
            if (!IPAddress.TryParse(ip, out var a) || IPAddress.IsLoopback(a)
                || a.IsIPv6LinkLocal || a.IsIPv6Multicast || a.IsIPv6SiteLocal)
                return false;
            var b = a.GetAddressBytes();
            if (b.Length == 16) return (b[0] & 0xfe) != 0xfc;
            return !(b[0] is 0 or 10 or 127 || b[0] >= 224
                || b[0] == 169 && b[1] == 254
                || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168
                || b[0] == 100 && b[1] is >= 64 and <= 127);
        }

        internal static bool Registry(TrafficRecord r, out string operation, out string artifact)
        {
            operation = ""; artifact = "";
            if (!Http(r, out var uri) || !External(r.Destination)) return false;
            var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (segments.Length < 4 || !segments[0].Equals("v2", StringComparison.OrdinalIgnoreCase))
                return false;
            var marker = Array.FindLastIndex(segments, x =>
                x.Equals("manifests", StringComparison.OrdinalIgnoreCase)
                || x.Equals("blobs", StringComparison.OrdinalIgnoreCase));
            if (marker < 2 || marker >= segments.Length - 1) return false;
            var method = r.HttpMethod!.ToUpperInvariant();
            if (segments[marker] == "manifests" || segments[marker].Equals("manifests", StringComparison.OrdinalIgnoreCase))
            {
                if (marker != segments.Length - 2 || segments[^1].Length is < 1 or > 128)
                    return false;
                operation = method is "GET" or "HEAD" ? "pull" : method == "PUT" ? "push" : "";
            }
            else
            {
                if (segments[marker + 1].Equals("uploads", StringComparison.OrdinalIgnoreCase))
                {
                    if (method is not ("POST" or "PATCH" or "PUT")) return false;
                    operation = "push";
                }
                else
                {
                    if (marker != segments.Length - 2 || !segments[^1].StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)
                        || segments[^1].Length != 71
                        || segments[^1][7..].Any(c => !Uri.IsHexDigit(c))) return false;
                    operation = method is "GET" or "HEAD" ? "pull" : "";
                }
            }
            if (operation.Length == 0) return false;
            artifact = string.Join("/", segments.Skip(1));
            if (segments[marker].Equals("blobs", StringComparison.OrdinalIgnoreCase)
                && !segments[marker + 1].Equals("uploads", StringComparison.OrdinalIgnoreCase))
                artifact = segments[marker + 1].ToLowerInvariant();
            return true;
        }

        internal static bool TerraformState(TrafficRecord r, out string path)
        {
            path = "";
            if (!Http(r, out var uri) || !External(r.Destination)
                || r.HttpMethod is not ("GET" or "HEAD" or "PUT"))
                return false;
            path = uri.AbsolutePath;
            if (path.Length is < 9 or > 512
                || path.StartsWith("/docs/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/documentation/", StringComparison.OrdinalIgnoreCase))
                return false;
            var name = path.Split('/').LastOrDefault() ?? "";
            return name.Equals("terraform.tfstate", StringComparison.OrdinalIgnoreCase)
                || name.Equals("terraform.tfstate.backup", StringComparison.OrdinalIgnoreCase)
                || name.EndsWith(".tfstate", StringComparison.OrdinalIgnoreCase) && name.Length > 8
                || name.EndsWith(".tfstate.backup", StringComparison.OrdinalIgnoreCase) && name.Length > 15;
        }

        internal static bool CiSecret(TrafficRecord r, out string parameter)
        {
            parameter = "";
            if (!Http(r, out var uri)) return false;
            var names = new[] { "gitlab-ci-token", "gitlab_token", "github_token", "ci_job_token",
                "job_token", "circle_token", "circle-token", "buildkite_token", "buildkite-agent-access-token" };
            foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = pair.Split('=', 2);
                if (parts.Length != 2 || !names.Contains(parts[0], StringComparer.OrdinalIgnoreCase))
                    continue;
                string value;
                try { value = Uri.UnescapeDataString(parts[1]); }
                catch (UriFormatException) { continue; }
                if (value.Length is < 16 or > 512
                    || value.Contains("example", StringComparison.OrdinalIgnoreCase)
                    || value.Contains("placeholder", StringComparison.OrdinalIgnoreCase)
                    || value.Contains("redacted", StringComparison.OrdinalIgnoreCase)
                    || value.All(c => c == 'x' || c == 'X' || c == '0')
                    || value.Any(char.IsWhiteSpace))
                    continue;
                parameter = parts[0].ToLowerInvariant();
                return true;
            }
            return false;
        }
    }
}
