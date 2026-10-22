// SPDX-License-Identifier: MIT
// File: Services/Flow/HandshakeBuffer.cs

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Carthago.Services.Flow
{
    /// <summary>
    /// Thread-safe, memory-bounded TLS handshake buffering for observed TCP flows.
    /// Reassembles complete TLS records across TCP segments, and handshake messages
    /// across multiple TLS handshake records. TLS 1.3 encrypted certificates are
    /// not visible to passive packet inspection.
    /// </summary>
    public static class HandshakeBuffer
    {
        // Hard limits protect the monitor against traffic floods and malformed TLS.
        private const int MaxFlows = 1024;
        private const int MaxBytesPerDirection = 32 * 1024;
        private const int MaxTlsRecordPayload = (16 * 1024) + 2048;
        private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan SweepInterval = TimeSpan.FromSeconds(15);

        private sealed class FlowBuffer
        {
            public byte[] Client = Array.Empty<byte>();
            public byte[] Server = Array.Empty<byte>();
            public int ClientLength;
            public int ServerLength;
            public bool ClientOverflowed;
            public bool ServerOverflowed;
            public byte[]? ClientHello;
            public byte[]? ServerHello;
            public byte[]? Certificate;
            public DateTime LastSeenUtc;
        }

        private static readonly object Sync = new();
        private static readonly Dictionary<FlowKey, FlowBuffer> Flows = new();
        private static DateTime _lastSweepUtc = DateTime.MinValue;
        private static long _expiredFlows;
        private static long _evictedFlows;
        private static long _rejectedSegments;

        public static int ActiveFlowCount
        {
            get { lock (Sync) return Flows.Count; }
        }

        public static long ExpiredFlowCount
        {
            get { lock (Sync) return _expiredFlows; }
        }

        public static long EvictedFlowCount
        {
            get { lock (Sync) return _evictedFlows; }
        }

        public static long RejectedSegmentCount
        {
            get { lock (Sync) return _rejectedSegments; }
        }

        /// <summary>Discard cached handshake data, for example between capture sessions.</summary>
        public static void Clear()
        {
            lock (Sync)
            {
                Flows.Clear();
                _lastSweepUtc = DateTime.MinValue;
            }
        }

        public static void AddClientBytes(FlowKey fk, ReadOnlySpan<byte> data)
            => Append(fk, data, client: true);

        public static void AddServerBytes(FlowKey fk, ReadOnlySpan<byte> data)
            => Append(fk, data, client: false);

        private static void Append(FlowKey key, ReadOnlySpan<byte> data, bool client)
        {
            if (data.IsEmpty) return;

            lock (Sync)
            {
                var now = DateTime.UtcNow;
                SweepExpiredIfDue(now);

                if (!Flows.TryGetValue(key, out var flow))
                {
                    // A newly observed stream must begin with a TLS handshake record.
                    if (data[0] != 0x16) return;

                    if (Flows.Count >= MaxFlows)
                        EvictOldest();

                    flow = new FlowBuffer { LastSeenUtc = now };
                    Flows.Add(key, flow);
                }

                flow.LastSeenUtc = now;

                // Do not retain subsequent application data after the wanted
                // handshake has already been extracted for that direction.
                if (client ? flow.ClientHello is not null : flow.Certificate is not null)
                    return;

                if (client)
                {
                    AppendDirection(ref flow.Client, ref flow.ClientLength,
                        ref flow.ClientOverflowed, data);
                }
                else
                {
                    AppendDirection(ref flow.Server, ref flow.ServerLength,
                        ref flow.ServerOverflowed, data);
                }
            }
        }

        private static void AppendDirection(
            ref byte[] buffer, ref int length, ref bool overflowed,
            ReadOnlySpan<byte> data)
        {
            if (overflowed) return;

            if (data.Length > MaxBytesPerDirection - length)
            {
                // Keep the entry disabled until it expires rather than repeatedly
                // allocating buffers for an oversized or hostile handshake.
                buffer = Array.Empty<byte>();
                length = 0;
                overflowed = true;
                _rejectedSegments++;
                return;
            }

            int required = length + data.Length;
            if (buffer.Length < required)
            {
                int capacity = Math.Min(MaxBytesPerDirection,
                    Math.Max(required, buffer.Length == 0 ? 1024 : buffer.Length * 2));
                var replacement = new byte[capacity];
                if (length > 0)
                    Buffer.BlockCopy(buffer, 0, replacement, 0, length);
                buffer = replacement;
            }

            data.CopyTo(buffer.AsSpan(length));
            length = required;
        }

        /// <summary>
        /// Returns a stable, immutable snapshot, never a view over a mutable buffer.
        /// The returned record can be passed to existing TLS fingerprint parsers.
        /// </summary>
        public static ReadOnlySpan<byte> TryGetClientHello(FlowKey fk)
        {
            lock (Sync)
            {
                if (!TryGetLiveFlow(fk, out var flow))
                    return ReadOnlySpan<byte>.Empty;

                if (flow.ClientHello is null && !flow.ClientOverflowed)
                {
                    flow.ClientHello = FindHandshake(
                        flow.Client.AsSpan(0, flow.ClientLength), 0x01);
                    if (flow.ClientHello is not null)
                    {
                        flow.Client = Array.Empty<byte>();
                        flow.ClientLength = 0;
                    }
                }

                if (flow.ClientHello is { } hello)
                    return hello;
                return ReadOnlySpan<byte>.Empty;
            }
        }

        /// <summary>
        /// Returns immutable snapshots for visible ServerHello and Certificate
        /// messages. A TLS 1.3 encrypted certificate cannot be extracted here.
        /// </summary>
        public static void TryGetServerHellos(
            FlowKey fk,
            out ReadOnlySpan<byte> serverHello,
            out ReadOnlySpan<byte> certificate)
        {
            serverHello = ReadOnlySpan<byte>.Empty;
            certificate = ReadOnlySpan<byte>.Empty;

            lock (Sync)
            {
                if (!TryGetLiveFlow(fk, out var flow)) return;

                if (!flow.ServerOverflowed)
                {
                    var buffered = flow.Server.AsSpan(0, flow.ServerLength);
                    flow.ServerHello ??= FindHandshake(buffered, 0x02);
                    flow.Certificate ??= FindHandshake(buffered, 0x0B);

                    if (flow.Certificate is not null)
                    {
                        flow.Server = Array.Empty<byte>();
                        flow.ServerLength = 0;
                    }
                }

                if (flow.ServerHello is { } hello)
                    serverHello = hello;
                if (flow.Certificate is { } cert)
                    certificate = cert;
            }
        }

        private static bool TryGetLiveFlow(FlowKey key, out FlowBuffer flow)
        {
            var now = DateTime.UtcNow;
            SweepExpiredIfDue(now);

            if (Flows.TryGetValue(key, out var candidate))
            {
                if (now - candidate.LastSeenUtc < IdleTimeout)
                {
                    flow = candidate;
                    return true;
                }

                Flows.Remove(key);
                _expiredFlows++;
            }

            flow = null!;
            return false;
        }

        /// <summary>
        /// Extracts one complete handshake message from complete TLS records.
        /// This supports a handshake message split across several TLS records,
        /// as well as multiple messages inside one record. Returns a normalized
        /// TLS handshake record for compatibility with existing parsers.
        /// </summary>
        private static byte[]? FindHandshake(ReadOnlySpan<byte> input, byte wantedType)
        {
            if (input.Length < 9) return null;

            var rented = ArrayPool<byte>.Shared.Rent(input.Length);
            try
            {
                int offset = 0;
                int assembledLength = 0;
                byte recordMajor = 0x03;
                byte recordMinor = 0x03;
                bool sawRecord = false;

                while (offset + 5 <= input.Length)
                {
                    if (input[offset] != 0x16) break;

                    int recordLength = BinaryPrimitives.ReadUInt16BigEndian(input.Slice(offset + 3, 2));
                    if (recordLength == 0 || recordLength > MaxTlsRecordPayload)
                        break;
                    if (recordLength > input.Length - offset - 5)
                        break; // Still waiting for the remaining TCP bytes.

                    if (!sawRecord)
                    {
                        recordMajor = input[offset + 1];
                        recordMinor = input[offset + 2];
                        sawRecord = true;
                    }

                    input.Slice(offset + 5, recordLength)
                         .CopyTo(rented.AsSpan(assembledLength));
                    assembledLength += recordLength;
                    offset += 5 + recordLength;
                }

                if (!sawRecord) return null;

                var messages = rented.AsSpan(0, assembledLength);
                int messageOffset = 0;

                while (messageOffset + 4 <= messages.Length)
                {
                    int messageLength = (messages[messageOffset + 1] << 16)
                                      | (messages[messageOffset + 2] << 8)
                                      | messages[messageOffset + 3];
                    if (messageLength > messages.Length - messageOffset - 4)
                        break; // Incomplete message.

                    int wholeMessageLength = 4 + messageLength;
                    if (messages[messageOffset] == wantedType)
                    {
                        var record = new byte[5 + wholeMessageLength];
                        record[0] = 0x16;
                        record[1] = recordMajor;
                        record[2] = recordMinor;
                        BinaryPrimitives.WriteUInt16BigEndian(
                            record.AsSpan(3, 2), (ushort)wholeMessageLength);
                        messages.Slice(messageOffset, wholeMessageLength)
                                .CopyTo(record.AsSpan(5));
                        return record;
                    }

                    messageOffset += wholeMessageLength;
                }

                return null;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented, clearArray: true);
            }
        }

        private static void SweepExpiredIfDue(DateTime now)
        {
            if (now - _lastSweepUtc < SweepInterval) return;
            _lastSweepUtc = now;

            List<FlowKey>? expired = null;
            foreach (var item in Flows)
            {
                if (now - item.Value.LastSeenUtc >= IdleTimeout)
                    (expired ??= new List<FlowKey>()).Add(item.Key);
            }

            if (expired is null) return;
            foreach (var key in expired)
            {
                if (Flows.Remove(key)) _expiredFlows++;
            }
        }

        private static void EvictOldest()
        {
            FlowKey oldestKey = default;
            DateTime oldest = DateTime.MaxValue;
            bool found = false;

            foreach (var item in Flows)
            {
                if (item.Value.LastSeenUtc >= oldest) continue;
                oldest = item.Value.LastSeenUtc;
                oldestKey = item.Key;
                found = true;
            }

            if (found && Flows.Remove(oldestKey))
                _evictedFlows++;
        }
    }
}
