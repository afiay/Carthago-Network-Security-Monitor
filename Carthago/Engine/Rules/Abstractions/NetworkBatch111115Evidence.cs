// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    // R111-R115 use parser-attributed fields, never Info-only protocol claims.
    // MQTT action text is accepted only after the flow has been attributed to MQTT.
    internal static class NetworkBatch111115Evidence
    {
        private static readonly byte[] TopicKey = RandomNumberGenerator.GetBytes(32);

        internal static bool HttpUpload(RuleEvaluationContext context)
            => NetworkBatch101105Evidence.CloudUpload(context);

        internal static bool HttpUploadMetadata(TrafficRecord record)
        {
            var path = Path(record.HttpUri);
            var headers = record.HttpRequestHeaders ?? string.Empty;
            if (headers.Length > 4096 || headers.IndexOf('\0') >= 0) return false;
            return path is "/upload" or "/uploads" or "/api/upload" or "/file" or "/files"
                || path.StartsWith("/upload/", StringComparison.Ordinal)
                || path.StartsWith("/uploads/", StringComparison.Ordinal)
                || headers.Contains("Content-Disposition:", StringComparison.OrdinalIgnoreCase)
                || headers.Contains("Content-Range:", StringComparison.OrdinalIgnoreCase)
                || headers.Contains("X-Goog-Upload", StringComparison.OrdinalIgnoreCase)
                || headers.Contains("X-Ms-Blob-Type:", StringComparison.OrdinalIgnoreCase);
        }

        internal static bool PasteUploadContext(TrafficRecord record)
        {
            var path = Path(record.HttpUri);
            return HttpUploadMetadata(record)
                || path is "/documents" or "/api/documents" or "/new"
                || path.StartsWith("/api/file/", StringComparison.Ordinal);
        }

        internal static bool ExportPath(string? uri)
        {
            var path = Path(uri);
            if (path.Length == 0) return false;
            // An export keyword in a query string, filename, header or Info
            // is not evidence of an export endpoint.
            var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            return parts.Any(part => part is "export" or "exports" or "takeout"
                or "archive" or "archives" or "backup" or "backups"
                or "bulk-export" or "content-export");
        }

        private static string Path(string? uri)
        {
            if (string.IsNullOrWhiteSpace(uri) || uri.Length > 4096
                || uri.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
                return string.Empty;
            var path = uri.Split('?', '#')[0];
            // One bounded decode allows encoded path segments but never
            // interprets credentials or query strings as path evidence.
            try { path = Uri.UnescapeDataString(path); }
            catch (UriFormatException) { return string.Empty; }
            return path.Length <= 4096 ? path.ToLowerInvariant() : string.Empty;
        }

        internal static bool Mqtt(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (r.Id == Guid.Empty || !NetworkBatch076080Evidence.ValidTime(context)
                || !r.IsTcp || r.IsUdp || r.IsQuic || r.IcmpTypeCode.HasValue
                || r.DnsQname != null || r.DnsAnswers != null || r.DnsIsResponse
                || r.HttpMethod != null || r.HttpUri != null
                || r.HttpRequestHeaders != null
                || !(string.Equals(r.Protocol, "MQTT", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase))
                || !(string.Equals(r.ApplicationProtocol, "MQTT", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(r.ApplicationService, "MQTT", StringComparison.OrdinalIgnoreCase))
                || r.ApplicationProtocol != null
                    && !string.Equals(r.ApplicationProtocol, "MQTT", StringComparison.OrdinalIgnoreCase)
                || r.ApplicationService != null
                    && !string.Equals(r.ApplicationService, "MQTT", StringComparison.OrdinalIgnoreCase)
                || r.DestinationPort is not int port || port is < 1 or > 65535
                || r.IpVersion is not (null or 4 or 6)
                || r.TcpFlags is ushort flags && ((flags & 0x07) != 0 || (flags & 0x18) == 0)
                || !IPAddress.TryParse(r.Source, out var src)
                || !IPAddress.TryParse(r.Destination, out var dst)
                || src.Equals(dst) || src.AddressFamily != dst.AddressFamily
                || r.IpVersion == 4 && src.AddressFamily != AddressFamily.InterNetwork
                || r.IpVersion == 6 && src.AddressFamily != AddressFamily.InterNetworkV6
                || r.HttpHost != null && r.Sni != null
                    && !r.HttpHost.Equals(r.Sni, StringComparison.OrdinalIgnoreCase))
                return false;
            return true;
        }

        internal static bool TryAction(TrafficRecord record, string action, out string topic)
        {
            topic = string.Empty;
            var info = record.Info?.Trim();
            if (string.IsNullOrWhiteSpace(info) || info.Length > 512) return false;
            if (info.StartsWith("mqtt ", StringComparison.OrdinalIgnoreCase))
                info = info[5..].TrimStart();
            if (!info.StartsWith(action + " ", StringComparison.OrdinalIgnoreCase))
                return false;
            var tail = info[(action.Length + 1)..].TrimStart();
            if (!tail.StartsWith("topic=", StringComparison.OrdinalIgnoreCase)
                && !tail.StartsWith("topic:", StringComparison.OrdinalIgnoreCase))
                return false;
            var token = tail[6..].Split(new[] { ' ', '\t', ',', ';' }, 2)[0]
                .Trim('"', '\'');
            if (!ValidTopic(token)) return false;
            topic = token;
            return true;
        }

        private static bool ValidTopic(string topic)
        {
            if (topic.Length is < 1 or > 256 || topic.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
                return false;
            var parts = topic.Split('/');
            for (var i = 0; i < parts.Length; i++)
            {
                var part = parts[i];
                if (part.Contains('#') && (part != "#" || i != parts.Length - 1))
                    return false;
                if (part.Contains('+') && part != "+")
                    return false;
            }
            return true;
        }

        internal static bool Wildcard(string topic)
            => topic.Split('/').Any(part => part is "#" or "+");

        // HMAC keeps raw topic names, device identifiers and possible embedded
        // secrets out of the long-lived distinct-topic state dictionaries.
        internal static string TopicFingerprint(string topic)
            => Convert.ToHexString(HMACSHA256.HashData(TopicKey, Encoding.UTF8.GetBytes(topic)));
    }
}
