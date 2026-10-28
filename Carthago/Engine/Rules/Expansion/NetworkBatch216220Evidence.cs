// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Text.RegularExpressions;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Request-shape evidence only. Neither packet Info nor declared Content-Length
    // proves a body was transmitted, received or used for exfiltration.
    internal static class NetworkBatch216220Evidence
    {
        private static readonly Regex DiscordWebhook = new(
            @"^/api/webhooks/[0-9]{5,}/[A-Za-z0-9_-]{10,}$",
            RegexOptions.CultureInvariant | RegexOptions.Compiled);
        private static readonly Regex DiscordChannel = new(
            @"^/api/v[0-9]+/channels/[0-9]+/messages$",
            RegexOptions.CultureInvariant | RegexOptions.Compiled);
        private static readonly Regex TelegramDocument = new(
            @"^/bot[0-9]+:[A-Za-z0-9_-]{15,}/sendDocument$",
            RegexOptions.CultureInvariant | RegexOptions.Compiled);

        private static bool Http(TrafficRecord r, out Uri uri)
            => NetworkBatch206215Evidence.Http(r, out uri);

        private static bool Host(string? host, string expected)
            => string.Equals(host, expected, StringComparison.OrdinalIgnoreCase);

        private static bool QueryPresent(Uri uri, string name)
        {
            foreach (var item in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = item.Split('=', 2);
                if (parts.Length == 2 && parts[0].Equals(name, StringComparison.OrdinalIgnoreCase)
                    && parts[1].Length is > 0 and <= 512) return true;
            }
            return false;
        }

        internal static bool GcsList(TrafficRecord r)
        {
            if (!Http(r, out var uri) || !Host(r.HttpHost, "storage.googleapis.com")
                || !string.Equals(r.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase)
                || QueryPresent(uri, "alt") && uri.Query.Contains("alt=media", StringComparison.OrdinalIgnoreCase))
                return false;
            var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            // JSON API: /storage/v1/b/{bucket}/o, not /o/{object}.
            if (segments.Length == 5 && segments[0].Equals("storage", StringComparison.OrdinalIgnoreCase)
                && segments[1].Equals("v1", StringComparison.OrdinalIgnoreCase)
                && segments[2].Equals("b", StringComparison.OrdinalIgnoreCase)
                && segments[3].Length is >= 3 and <= 222
                && segments[4].Equals("o", StringComparison.OrdinalIgnoreCase))
                return true;
            // XML API: /{bucket}?prefix=... or ?delimiter=...; never an object GET.
            return segments.Length == 1 && segments[0].Length is >= 3 and <= 222
                && (QueryPresent(uri, "prefix") || QueryPresent(uri, "delimiter"));
        }

        internal static bool Multipart(TrafficRecord r)
            => NetworkBatch166170Evidence.Header(r, "Content-Type", out var type)
                && type.StartsWith("multipart/form-data;", StringComparison.OrdinalIgnoreCase)
                && type.Contains("boundary=", StringComparison.OrdinalIgnoreCase);

        internal static bool DeclaredBytes(TrafficRecord r, out long bytes)
        {
            bytes = 0;
            return NetworkBatch166170Evidence.Header(r, "Content-Length", out var value)
                && long.TryParse(value, System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out bytes)
                && bytes > 0 && bytes <= 50_000_000;
        }

        internal static bool UploadContext(TrafficRecord r, long minimum)
            => Multipart(r) || DeclaredBytes(r, out var bytes) && bytes >= minimum;

        internal static bool Slack(TrafficRecord r, out string kind)
        {
            kind = "";
            if (!Http(r, out var uri) || !string.Equals(r.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
                return false;
            var path = uri.AbsolutePath;
            var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (Host(r.HttpHost, "hooks.slack.com") && segments.Length == 4
                && segments[0].Equals("services", StringComparison.OrdinalIgnoreCase)
                && segments.Skip(1).All(x => x.Length is >= 3 and <= 128))
                kind = "slack-webhook-post";
            else if (Host(r.HttpHost, "slack.com")
                && path.Equals("/api/files.upload", StringComparison.OrdinalIgnoreCase))
                kind = "slack-file-upload-request";
            return kind.Length > 0 && UploadContext(r, 50_000);
        }

        internal static bool Discord(TrafficRecord r, out string kind)
        {
            kind = "";
            if (!Http(r, out var uri) || !Host(r.HttpHost, "discord.com")
                || !string.Equals(r.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase)
                || !UploadContext(r, 50_000)) return false;
            if (DiscordWebhook.IsMatch(uri.AbsolutePath)) kind = "discord-webhook-post";
            else if (DiscordChannel.IsMatch(uri.AbsolutePath) && Multipart(r))
                kind = "discord-channel-attachment-request";
            return kind.Length > 0;
        }

        internal static bool Telegram(TrafficRecord r)
            => Http(r, out var uri) && Host(r.HttpHost, "api.telegram.org")
                && string.Equals(r.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase)
                && TelegramDocument.IsMatch(uri.AbsolutePath) && UploadContext(r, 50_000);

        internal static bool Paste(TrafficRecord r, out string provider)
        {
            provider = "";
            if (!Http(r, out _) || r.HttpMethod is not ("POST" or "PUT" or "PATCH"))
                return false;
            var host = r.HttpHost ?? "";
            if (new[] { "pastebin.com", "hastebin.com", "paste.rs", "ghostbin.com",
                "rentry.co", "paste.ee", "dpaste.com", "transfer.sh" }
                .Any(x => Host(host, x))) provider = host.ToLowerInvariant();
            return provider.Length > 0 && (Multipart(r) || DeclaredBytes(r, out _));
        }

        internal static string SafeKey(TrafficRecord r)
            => NetworkBatch206215Evidence.Fingerprint((r.Source ?? "") + "|" +
                (r.HttpHost ?? "") + "|" + (r.Destination ?? ""));
    }
}
