// SPDX-License-Identifier: MIT
// R343 metadata-only IPC protocol contract. NO listener, service, signer or alerts.
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// Transport-verified OS peer metadata. This type is INTERNAL so untrusted
    /// IPC JSON cannot create an authenticated identity. The future transport
    /// adapter must establish the Windows token/SID, process identity and
    /// channel binding from the OS (never from caller-supplied message fields).
    /// Tests simulate it; this type by itself does NOT authenticate Windows.
    /// </summary>
    internal sealed record WinRmTelemetryTransportPeer(
        string WindowsSid, string Machine, int ProcessId, Guid ChannelBinding);

    /// <summary>
    /// Opaque capability issued by one gate after it has checked a transport-
    /// verified peer against operator-pinned SID and machine configuration.
    /// A session ID is not a credential and cannot independently open a gate.
    /// </summary>
    internal sealed class WinRmTelemetryIpcSession
    {
        internal WinRmTelemetryIpcSession(Guid ownerId, Guid id, Guid channelBinding,
            DateTimeOffset createdAtUtc)
        {
            OwnerId = ownerId;
            Id = id;
            ChannelBinding = channelBinding;
            CreatedAtUtc = createdAtUtc;
        }

        internal Guid OwnerId { get; }
        internal Guid ChannelBinding { get; }
        internal DateTimeOffset CreatedAtUtc { get; }
        internal long LastSequence { get; set; }
        internal bool Closed { get; set; }
        internal object Gate { get; } = new();
        public Guid Id { get; }
    }

    /// <summary>
    /// Validated but UNSIGNED IPC observation. No command line, user, secret,
    /// authorization, execution outcome, verified receipt or promotion flag.
    /// </summary>
    internal sealed record WinRmTelemetryIpcCandidate(
        Guid CorrelationId, Guid SessionId, long Sequence,
        string Machine, string RemoteIp, ulong LogonId,
        long LogonRecordId, long ProcessRecordId,
        uint ProcessId, uint ParentProcessId, DateTimeOffset ProcessTimeUtc);

    /// <summary>
    /// In-memory consumer-side protocol gate. It has no socket, named pipe,
    /// privileged OS operation, audit signer, or integration into R343.
    /// It is NOT an authentication provider; only a future OS-authenticated
    /// transport adapter may supply WinRmTelemetryTransportPeer.
    /// </summary>
    internal sealed class WinRmTelemetryIpcContract
    {
        internal const int MaxFrameBytes = 4096;
        internal const int MaxSessions = 64;
        internal const int MaxAcceptedMessages = 4096;
        private const int ProtocolVersion = 1;
        private const string Kind = "UnsignedWinRmCandidate";
        private static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan FutureSkew = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan MaxSessionAge = TimeSpan.FromMinutes(15);
        private static readonly UTF8Encoding StrictUtf8 = new(false, true);
        private static readonly Regex SidPattern = new(
            @"^S-1-[0-9]+(?:-[0-9]+){1,14}$",
            RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        private static readonly HashSet<string> RequiredFields = new(StringComparer.Ordinal)
        {
            "Version", "Kind", "SessionId", "CorrelationId", "Sequence",
            "Machine", "RemoteIp", "LogonId", "LogonRecordId",
            "ProcessRecordId", "ProcessId", "ParentProcessId", "ProcessTimeUtc"
        };

        private readonly string _allowedSid;
        private readonly string _machine;
        private readonly Func<DateTimeOffset> _now;
        private readonly Guid _ownerId = Guid.NewGuid();
        private readonly HashSet<WinRmTelemetryIpcSession> _sessions = new();
        private readonly HashSet<Guid> _usedChannelBindings = new();
        private readonly HashSet<Guid> _seenCorrelations = new();
        private readonly object _gate = new();

        internal WinRmTelemetryIpcContract(string operatorPinnedSid, string machine,
            Func<DateTimeOffset>? utcClock = null)
        {
            if (!ValidSid(operatorPinnedSid)
                || !ValidMachine(machine))
                throw new ArgumentException("Invalid operator-pinned IPC peer configuration.");
            _allowedSid = operatorPinnedSid;
            _machine = machine;
            _now = utcClock ?? (() => DateTimeOffset.UtcNow);
        }

        internal bool TryOpenVerifiedPeer(WinRmTelemetryTransportPeer? peer,
            out WinRmTelemetryIpcSession? session, out string reason)
        {
            session = null;
            reason = "UNAUTHENTICATED_OR_UNAUTHORIZED_PEER";
            if (peer == null || !ValidSid(peer.WindowsSid)
                || !string.Equals(peer.WindowsSid, _allowedSid, StringComparison.Ordinal)
                || !string.Equals(peer.Machine, _machine, StringComparison.OrdinalIgnoreCase)
                || peer.ProcessId <= 0 || peer.ChannelBinding == Guid.Empty)
                return false;

            lock (_gate)
            {
                if (_sessions.Count >= MaxSessions
                    || _usedChannelBindings.Count >= MaxSessions
                    || !_usedChannelBindings.Add(peer.ChannelBinding))
                {
                    reason = "CHANNEL_REPLAY_OR_CAPACITY";
                    return false;
                }
                session = new WinRmTelemetryIpcSession(_ownerId, Guid.NewGuid(),
                    peer.ChannelBinding, _now());
                _sessions.Add(session);
            }

            reason = "TRANSPORT_PEER_SCOPE_ACCEPTED_NOT_ATTESTED";
            return true;
        }

        internal void Close(WinRmTelemetryIpcSession? session)
        {
            if (session == null) return;
            lock (_gate)
            {
                if (_sessions.Remove(session))
                    session.Closed = true;
            }
        }

        internal bool TryAcceptFrame(WinRmTelemetryIpcSession? session,
            ReadOnlySpan<byte> frame, out WinRmTelemetryIpcCandidate? candidate,
            out string reason)
        {
            candidate = null;
            reason = "INVALID_SESSION";
            if (session == null || session.OwnerId != _ownerId)
                return false;

            // Reject oversized and malformed frames before allocating JSON.
            if (frame.Length is < 6 or > MaxFrameBytes)
            {
                reason = "INVALID_FRAME_LENGTH";
                return false;
            }
            var size = BinaryPrimitives.ReadInt32BigEndian(frame[..4]);
            if (size != frame.Length - 4 || size < 2)
            {
                reason = "INVALID_FRAME_LENGTH";
                return false;
            }

            WinRmTelemetryIpcCandidate? parsed;
            try
            {
                var json = StrictUtf8.GetString(frame[4..]);
                if (json.Length == 0 || json[0] == '\uFEFF')
                {
                    reason = "INVALID_UTF8";
                    return false;
                }
                using var doc = JsonDocument.Parse(json, new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 2
                });
                if (!TryParse(doc.RootElement, out parsed))
                {
                    reason = "INVALID_CANDIDATE_SCHEMA";
                    return false;
                }
            }
            catch (Exception ex) when (ex is DecoderFallbackException or JsonException
                or FormatException or OverflowException)
            {
                reason = "INVALID_FRAME_CONTENT";
                return false;
            }

            if (parsed == null
                || parsed.SessionId != session.Id
                || !string.Equals(parsed.Machine, _machine, StringComparison.OrdinalIgnoreCase))
            {
                reason = "CHANNEL_OR_MACHINE_MISMATCH";
                return false;
            }

            var now = _now();
            var age = now - parsed.ProcessTimeUtc;
            if (age < -FutureSkew || age > MaxAge)
            {
                reason = "STALE_OR_FUTURE_CANDIDATE";
                return false;
            }

            lock (_gate)
            {
                if (session.Closed || !_sessions.Contains(session)
                    || now < session.CreatedAtUtc - FutureSkew
                    || now - session.CreatedAtUtc > MaxSessionAge)
                {
                    reason = "SESSION_CLOSED_OR_EXPIRED";
                    return false;
                }
                // Strict 1,2,... sequence and a shared non-evicting replay set
                // prevent cross-session duplicate correlation IDs.
                if (session.LastSequence == long.MaxValue
                    || parsed.Sequence != session.LastSequence + 1
                    || _seenCorrelations.Contains(parsed.CorrelationId))
                {
                    reason = "OUT_OF_ORDER_OR_REPLAY";
                    return false;
                }
                if (_seenCorrelations.Count >= MaxAcceptedMessages)
                {
                    reason = "REPLAY_CACHE_CAPACITY";
                    return false;
                }
                _seenCorrelations.Add(parsed.CorrelationId);
                session.LastSequence = parsed.Sequence;
            }
            candidate = parsed;
            reason = "UNSIGNED_IPC_CANDIDATE_NOT_AUTHORIZED_FOR_ALERT";
            return true;
        }

        private static bool TryParse(JsonElement root,
            out WinRmTelemetryIpcCandidate? candidate)
        {
            candidate = null;
            if (root.ValueKind != JsonValueKind.Object) return false;
            var fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var entry in root.EnumerateObject())
            {
                if (!RequiredFields.Contains(entry.Name)
                    || !fields.TryAdd(entry.Name, entry.Value))
                    return false;
            }
            if (fields.Count != RequiredFields.Count
                || !ReadInt32(fields, "Version", out var version)
                || version != ProtocolVersion
                || !ReadString(fields, "Kind", out var kind)
                || kind != Kind
                || !ReadGuid(fields, "SessionId", out var sessionId)
                || !ReadGuid(fields, "CorrelationId", out var correlationId)
                || !ReadInt64(fields, "Sequence", out var sequence) || sequence <= 0
                || !ReadString(fields, "Machine", out var machine) || !ValidMachine(machine)
                || !ReadString(fields, "RemoteIp", out var remoteIp) || !ValidRemoteIp(remoteIp)
                || !ReadUInt64(fields, "LogonId", out var logonId) || logonId == 0
                || !ReadInt64(fields, "LogonRecordId", out var logonRecordId)
                || !ReadInt64(fields, "ProcessRecordId", out var processRecordId)
                || logonRecordId <= 0 || processRecordId <= logonRecordId
                || !ReadUInt32(fields, "ProcessId", out var processId) || processId == 0
                || !ReadUInt32(fields, "ParentProcessId", out var parentId) || parentId == 0
                || processId == parentId
                || !ReadString(fields, "ProcessTimeUtc", out var timeValue)
                || !DateTimeOffset.TryParseExact(timeValue, "O",
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out var time)
                || time.Offset != TimeSpan.Zero)
                return false;

            candidate = new WinRmTelemetryIpcCandidate(correlationId, sessionId,
                sequence, machine, remoteIp, logonId, logonRecordId,
                processRecordId, processId, parentId, time);
            return true;
        }

        private static bool ReadString(Dictionary<string, JsonElement> fields,
            string key, out string value)
        {
            value = "";
            if (fields[key].ValueKind != JsonValueKind.String) return false;
            value = fields[key].GetString() ?? "";
            return value.Length is > 0 and <= 256;
        }
        private static bool ReadGuid(Dictionary<string, JsonElement> fields,
            string key, out Guid value)
        {
            value = Guid.Empty;
            return ReadString(fields, key, out var text)
                && Guid.TryParseExact(text, "D", out value) && value != Guid.Empty;
        }
        private static bool ReadInt32(Dictionary<string, JsonElement> fields,
            string key, out int value)
            => fields[key].ValueKind == JsonValueKind.Number
                && fields[key].TryGetInt32(out value);
        private static bool ReadInt64(Dictionary<string, JsonElement> fields,
            string key, out long value)
            => fields[key].ValueKind == JsonValueKind.Number
                && fields[key].TryGetInt64(out value);
        private static bool ReadUInt32(Dictionary<string, JsonElement> fields,
            string key, out uint value)
            => fields[key].ValueKind == JsonValueKind.Number
                && fields[key].TryGetUInt32(out value);
        private static bool ReadUInt64(Dictionary<string, JsonElement> fields,
            string key, out ulong value)
            => fields[key].ValueKind == JsonValueKind.Number
                && fields[key].TryGetUInt64(out value);

        private static bool ValidMachine(string? machine)
            => machine is { Length: >= 1 and <= 128 }
                && machine.All(c => char.IsAsciiLetterOrDigit(c)
                    || c is '-' or '.');
        private static bool ValidSid(string? sid)
            => sid is { Length: >= 9 and <= 184 }
                && SidPattern.IsMatch(sid);
        private static bool ValidRemoteIp(string value)
        {
            if (!IPAddress.TryParse(value, out var ip)
                || IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any)
                || ip.Equals(IPAddress.IPv6Any)
                || (ip.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(ip.MapToIPv4())))
                return false;
            return true;
        }
    }
}
