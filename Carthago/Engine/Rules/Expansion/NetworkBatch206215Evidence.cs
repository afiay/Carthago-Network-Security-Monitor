// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Request-shape evidence only. Packet Info never establishes a Git operation,
    // package installation, script execution or a verified registry reputation.
    internal static class NetworkBatch206215Evidence
    {
        internal static bool Http(TrafficRecord r, out Uri uri)
        {
            uri = null!;
            return NetworkBatch166170Evidence.Http(r)
                && NetworkBatch156165Evidence.UriOf(r, out uri)
                && PublicDestination(r.Destination)
                && !string.IsNullOrWhiteSpace(r.HttpHost);
        }

        private static bool PublicDestination(string? value)
        {
            if (!IPAddress.TryParse(value, out var ip) || IPAddress.IsLoopback(ip)
                || ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal) return false;
            var b = ip.GetAddressBytes();
            if (b.Length == 16) return (b[0] & 0xfe) != 0xfc;
            return !(b[0] is 0 or 10 or 127 || b[0] >= 224
                || b[0] == 169 && b[1] == 254
                || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168
                || b[0] == 100 && b[1] is >= 64 and <= 127);
        }

        private static bool HostIs(string? host, string suffix)
            => host != null && (host.Equals(suffix, StringComparison.OrdinalIgnoreCase)
                || host.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase));

        internal static bool OfficialGit(string? host)
            => new[] { "github.com", "gitlab.com", "bitbucket.org", "dev.azure.com",
                "visualstudio.com", "git.sr.ht" }.Any(x => HostIs(host, x));

        internal static bool OfficialPackage(string? host)
            => new[] { "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org",
                "files.pythonhosted.org", "pythonhosted.org", "api.nuget.org",
                "nuget.org", "repo.maven.apache.org", "repo1.maven.org",
                "rubygems.org" }.Any(x => HostIs(host, x));

        private static bool Client(TrafficRecord r, params string[] names)
        {
            var process = r.ProcessName ?? "";
            var ua = r.HttpUserAgent ?? "";
            return names.Any(name =>
                process.Equals(name, StringComparison.OrdinalIgnoreCase)
                || process.Equals(name + ".exe", StringComparison.OrdinalIgnoreCase)
                || ua.StartsWith(name + "/", StringComparison.OrdinalIgnoreCase));
        }

        private static bool Query(Uri uri, string name, string value)
            => uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Split('=', 2))
                .Any(x => x.Length == 2 && x[0].Equals(name, StringComparison.OrdinalIgnoreCase)
                    && x[1].Equals(value, StringComparison.OrdinalIgnoreCase));

        internal static bool Git(TrafficRecord r, bool push)
        {
            if (!Http(r, out var uri) || OfficialGit(r.HttpHost) || !Client(r, "git", "git-lfs"))
                return false;
            var path = uri.AbsolutePath;
            // Git smart HTTP permits repository paths without a .git suffix.
            if (path.Split('/', StringSplitOptions.RemoveEmptyEntries).Length < 3) return false;
            if (path.EndsWith("/info/refs", StringComparison.OrdinalIgnoreCase))
                return r.HttpMethod == "GET" && Query(uri, "service",
                    push ? "git-receive-pack" : "git-upload-pack");
            return r.HttpMethod == "POST" && path.EndsWith(
                push ? "/git-receive-pack" : "/git-upload-pack",
                StringComparison.OrdinalIgnoreCase);
        }

        internal static bool Package(TrafficRecord r, out string ecosystem)
        {
            ecosystem = "";
            if (!Http(r, out var uri) || OfficialPackage(r.HttpHost)
                || r.HttpMethod is not ("GET" or "HEAD")) return false;
            var p = uri.AbsolutePath;
            if (Client(r, "npm", "pnpm", "yarn")
                && (p.StartsWith("/-/package/", StringComparison.OrdinalIgnoreCase)
                    || p.StartsWith("/@") || p.StartsWith("/-/v1/search")
                    || p.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase)))
                ecosystem = "npm";
            else if (Client(r, "pip", "poetry")
                && (p.StartsWith("/simple/", StringComparison.OrdinalIgnoreCase)
                    || p.StartsWith("/packages/", StringComparison.OrdinalIgnoreCase)
                    || p.EndsWith(".whl", StringComparison.OrdinalIgnoreCase)))
                ecosystem = "pypi";
            else if (Client(r, "nuget", "dotnet")
                && (p.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase)
                    || p.EndsWith("/v3/index.json", StringComparison.OrdinalIgnoreCase)))
                ecosystem = "nuget";
            return ecosystem.Length != 0;
        }

        internal static bool NpmCallback(TrafficRecord r)
            => Http(r, out var uri) && !OfficialPackage(r.HttpHost)
                && r.HttpMethod is ("GET" or "POST")
                && Client(r, "npm", "pnpm", "yarn", "node")
                && (Query(uri, "event", "postinstall") || Query(uri, "event", "preinstall")
                    || Query(uri, "phase", "postinstall") || Query(uri, "phase", "preinstall"))
                && uri.AbsolutePath.StartsWith("/beacon", StringComparison.OrdinalIgnoreCase);

        internal static bool Pypi(TrafficRecord r)
            => Http(r, out var uri) && !OfficialPackage(r.HttpHost)
                && r.HttpMethod is ("GET" or "HEAD") && Client(r, "pip", "poetry")
                && (uri.AbsolutePath.StartsWith("/simple/", StringComparison.OrdinalIgnoreCase)
                    || uri.AbsolutePath.StartsWith("/packages/", StringComparison.OrdinalIgnoreCase)
                    || uri.AbsolutePath.EndsWith(".whl", StringComparison.OrdinalIgnoreCase)
                    || uri.AbsolutePath.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase));

        private static bool QueryPresent(Uri uri, string name)
            => uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Split('=', 2))
                .Any(x => x.Length == 2 && x[0].Equals(name, StringComparison.OrdinalIgnoreCase)
                    && x[1].Length > 0 && x[1].Length <= 1024);

        internal static string Fingerprint(string value)
            => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

        internal static bool PowerShellScript(TrafficRecord r)
            => Http(r, out var uri) && r.HttpMethod == "GET"
                && Client(r, "powershell", "pwsh")
                && !HostIs(r.HttpHost, "powershellgallery.com")
                && uri.AbsolutePath.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase);

        // A raw script GET is observable; the following packet does not
        // establish shell execution or prove the contents of a process pipe.
        internal static bool CurlRawScript(TrafficRecord r)
            => Http(r, out var uri) && r.HttpMethod == "GET"
                && Client(r, "curl", "wget")
                && (HostIs(r.HttpHost, "raw.githubusercontent.com")
                    || HostIs(r.HttpHost, "gist.githubusercontent.com")
                    || HostIs(r.HttpHost, "paste.rs")
                    || uri.AbsolutePath.EndsWith(".sh", StringComparison.OrdinalIgnoreCase));

        internal static bool Presigned(TrafficRecord r, out string provider, out string artifact)
        {
            provider = ""; artifact = "";
            if (!Http(r, out var uri) || r.HttpMethod is not ("GET" or "HEAD")) return false;
            if (HostIs(r.HttpHost, "s3.amazonaws.com")
                && QueryPresent(uri, "X-Amz-Signature")
                && Query(uri, "X-Amz-Algorithm", "AWS4-HMAC-SHA256"))
                provider = "aws-presigned";
            else if (HostIs(r.HttpHost, "storage.googleapis.com")
                && QueryPresent(uri, "X-Goog-Signature")
                && Query(uri, "X-Goog-Algorithm", "GOOG4-RSA-SHA256"))
                provider = "gcs-signed";
            else if (HostIs(r.HttpHost, "blob.core.windows.net")
                && QueryPresent(uri, "sig") && QueryPresent(uri, "se") && QueryPresent(uri, "sp"))
                provider = "azure-sas";
            if (provider.Length == 0 || uri.AbsolutePath == "/") return false;
            // Never retain signed URLs or query credentials in rule-owned state.
            artifact = Fingerprint(r.HttpHost + uri.AbsolutePath);
            return true;
        }

        internal static bool S3List(TrafficRecord r)
        {
            if (!Http(r, out var uri) || r.HttpMethod != "GET"
                || !HostIs(r.HttpHost, "s3.amazonaws.com")) return false;
            var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            // Virtual-host style root, or path-style /bucket. Never an object path.
            if (segments.Length > 1) return false;
            return Query(uri, "list-type", "2") || QueryPresent(uri, "prefix")
                || QueryPresent(uri, "delimiter");
        }

        internal static bool AzureList(TrafficRecord r)
        {
            if (!Http(r, out var uri) || r.HttpMethod != "GET"
                || !HostIs(r.HttpHost, "blob.core.windows.net")) return false;
            var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            return segments.Length == 1 && segments[0].Length is >= 3 and <= 63
                && Query(uri, "restype", "container") && Query(uri, "comp", "list");
        }
    }
}
