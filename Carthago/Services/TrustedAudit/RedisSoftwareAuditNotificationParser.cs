// SPDX-License-Identifier: MIT
// GA R437 Redis Software source adapter — SOURCE CANDIDATE — UNVERIFIED.
using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;

namespace Carthago.Services.TrustedAudit
{
    public enum RedisSoftwareAuditEventKind
    {
        ConnectionOpened,
        Authentication,
        Command,
        ConnectionClosed
    }

    public enum RedisSoftwareCommandClass
    {
        None,
        Other,
        GenericConfig
    }

    public enum RedisSoftwareCommandOutcome
    {
        NotACommand,
        Succeeded,
        Failed
    }

    /// <summary>
    /// Untrusted, privacy-minimized Redis Software audit metadata.
    /// Parsing a notification does NOT authenticate its origin, the Redis daemon,
    /// its client or the specific CONFIG subcommand. No keys, arguments, username,
    /// ACL rules, error text, identity or arbitrary command names are retained.
    /// </summary>
    public sealed record RedisSoftwareAuditObservation(
        RedisSoftwareAuditEventKind Kind,
        DateTimeOffset OccurredAtUtc,
        long ConnectionId,
        string ClientIp,
        int ClientPort,
        string ServerIp,
        int ServerPort,
        string DatabaseUid,
        int WorkerId,
        long AuditSequence,
        RedisSoftwareCommandClass CommandClass,
        RedisSoftwareCommandOutcome CommandOutcome)
    {
        // Redis Software publishes a command name such as "config", not a
        // cryptographically established "CONFIG SET" subcommand and transaction.
        public bool ProvesConfigSetSubcommand => false;
        public bool AuthenticatedProducer => false;
    }

    /// <summary>
    /// Bounded parser for one already-delimited Redis Software JSON audit
    /// notification. The audit TCP stream framing, transport authentication,
    /// full-delivery metrics and external collector are NOT supplied here.
    /// No raw vendor event may be promoted to an R437 signed success claim.
    /// See https://redis.io/docs/latest/operate/rs/security/audit-events/
    /// </summary>
    public static class RedisSoftwareAuditNotificationParser
    {
        private const int MaxNotificationBytes = 16 * 1024;
        private const long FirstSupportedUnixSecond = 1577836800L; // 2020-01-01 UTC
        private const long LastSupportedUnixSecond = 4102444800L;  // 2100-01-01 UTC

        public static bool TryParse(ReadOnlyMemory<byte> jsonBytes,
            out RedisSoftwareAuditObservation? observation)
        {
            observation = null;
            if (jsonBytes.Length is < 2 or > MaxNotificationBytes)
                return false;

            try
            {
                using var json = JsonDocument.Parse(jsonBytes, new JsonDocumentOptions
                {
                    MaxDepth = 8,
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow
                });

                var root = json.RootElement;
                if (root.ValueKind != JsonValueKind.Object || !HasUniqueProperties(root))
                    return false;

                if (!ReadLong(root, "ts", out var unixTime)
                    || unixTime < FirstSupportedUnixSecond
                    || unixTime >= LastSupportedUnixSecond
                    || !ReadInt(root, "audit_worker_id", out var workerId)
                    || workerId < 0 || workerId > 65535
                    || !ReadLong(root, "audit_seq", out var sequence) || sequence < 0)
                    return false;

                JsonElement fields;
                RedisSoftwareAuditEventKind kind;
                if (root.TryGetProperty("action", out var action))
                {
                    if (root.TryGetProperty("new_conn", out _)
                        || root.TryGetProperty("close_conn", out _)
                        || action.ValueKind != JsonValueKind.String)
                        return false;

                    var type = action.GetString();
                    kind = type switch
                    {
                        "command" => RedisSoftwareAuditEventKind.Command,
                        "auth" => RedisSoftwareAuditEventKind.Authentication,
                        _ => (RedisSoftwareAuditEventKind)(-1)
                    };
                    if ((int)kind < 0)
                        return false;
                    fields = root;
                }
                else if (root.TryGetProperty("new_conn", out var opened)
                    && !root.TryGetProperty("close_conn", out _)
                    && opened.ValueKind == JsonValueKind.Object
                    && HasUniqueProperties(opened))
                {
                    kind = RedisSoftwareAuditEventKind.ConnectionOpened;
                    fields = opened;
                }
                else if (root.TryGetProperty("close_conn", out var closed)
                    && !root.TryGetProperty("new_conn", out _)
                    && closed.ValueKind == JsonValueKind.Object
                    && HasUniqueProperties(closed))
                {
                    kind = RedisSoftwareAuditEventKind.ConnectionClosed;
                    fields = closed;
                }
                else
                {
                    return false;
                }

                if (!ReadLong(fields, "id", out var connectionId) || connectionId <= 0
                    || !ReadIp(fields, "srcip", out var client)
                    || !ReadIp(fields, "trgip", out var server)
                    || !ReadPort(fields, "srcp", out var clientPort)
                    || !ReadPort(fields, "trgp", out var serverPort)
                    || !ReadString(fields, "bdb_uid", 64, out var databaseUid))
                    return false;

                var commandClass = RedisSoftwareCommandClass.None;
                var commandOutcome = RedisSoftwareCommandOutcome.NotACommand;
                if (kind == RedisSoftwareAuditEventKind.Command)
                {
                    if (!ReadString(fields, "command", 64, out var command)
                        || !ReadInt(fields, "status", out var status)
                        || status is not (9 or 10))
                        return false;

                    // Never treat a generic CONFIG command as CONFIG SET.
                    // No other argument/command text is exported or logged.
                    commandClass = string.Equals(command, "config",
                        StringComparison.OrdinalIgnoreCase)
                        ? RedisSoftwareCommandClass.GenericConfig
                        : RedisSoftwareCommandClass.Other;
                    commandOutcome = status == 9
                        ? RedisSoftwareCommandOutcome.Succeeded
                        : RedisSoftwareCommandOutcome.Failed;
                }

                observation = new(
                    kind, DateTimeOffset.FromUnixTimeSeconds(unixTime),
                    connectionId, client, clientPort, server, serverPort,
                    databaseUid, workerId, sequence, commandClass, commandOutcome);
                return true;
            }
            catch (Exception error) when (error is JsonException
                or ArgumentException or InvalidOperationException or OverflowException)
            {
                return false;
            }
        }

        private static bool HasUniqueProperties(JsonElement obj)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in obj.EnumerateObject())
                if (!names.Add(property.Name))
                    return false;
            return true;
        }

        private static bool ReadString(JsonElement obj, string name, int max,
            out string value)
        {
            value = string.Empty;
            if (!obj.TryGetProperty(name, out var element)
                || element.ValueKind != JsonValueKind.String)
                return false;
            var found = element.GetString();
            if (string.IsNullOrEmpty(found) || found.Length > max)
                return false;
            value = found;
            return true;
        }

        private static bool ReadIp(JsonElement obj, string name, out string address)
        {
            address = string.Empty;
            if (!ReadString(obj, name, 64, out var ipText)
                || !IPAddress.TryParse(ipText, out var parsed))
                return false;
            address = parsed.ToString();
            return true;
        }

        private static bool ReadPort(JsonElement obj, string name, out int port)
        {
            port = 0;
            if (!obj.TryGetProperty(name, out var element))
                return false;
            if (element.ValueKind == JsonValueKind.Number)
                return element.TryGetInt32(out port) && port is > 0 and <= 65535;
            if (element.ValueKind != JsonValueKind.String)
                return false;
            var text = element.GetString();
            if (text is not { Length: >= 1 and <= 5 })
                return false;
            foreach (var ch in text)
                if (ch is < '0' or > '9')
                    return false;
            return int.TryParse(text, out port) && port is > 0 and <= 65535;
        }

        private static bool ReadInt(JsonElement obj, string name, out int value)
        {
            value = 0;
            return obj.TryGetProperty(name, out var element)
                && element.ValueKind == JsonValueKind.Number
                && element.TryGetInt32(out value);
        }

        private static bool ReadLong(JsonElement obj, string name, out long value)
        {
            value = 0;
            return obj.TryGetProperty(name, out var element)
                && element.ValueKind == JsonValueKind.Number
                && element.TryGetInt64(out value);
        }
    }
}
