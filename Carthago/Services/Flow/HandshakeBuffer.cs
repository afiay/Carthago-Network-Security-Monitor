// SPDX-License-Identifier: MIT
// File: Services/Flow/HandshakeBuffer.cs

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;

namespace Carthago.Services.Flow
{
    /// <summary>
    /// Bounded state to reassemble TLS handshake (client/server) across segments.
    /// NOTE: No tuples with ReadOnlySpan — we use out parameters.
    /// </summary>
    public static class HandshakeBuffer
    {
        private sealed class Buf
        {
            public byte[] Client = Array.Empty<byte>();
            public byte[] Server = Array.Empty<byte>();
            public int ClientLen;
            public int ServerLen;
        }

        private static readonly ConcurrentDictionary<FlowKey, Buf> _map = new();

        private static void Append(ref byte[] dst, ref int len, ReadOnlySpan<byte> src, int max = 32 * 1024)
        {
            int need = len + src.Length;
            if (need > max) { dst = Array.Empty<byte>(); len = 0; return; }
            if (dst.Length < need)
            {
                var n = new byte[Math.Max(need, dst.Length == 0 ? 2048 : dst.Length * 2)];
                if (len > 0) Buffer.BlockCopy(dst, 0, n, 0, len);
                dst = n;
            }
            src.CopyTo(dst.AsSpan(len));
            len += src.Length;
        }

        public static void AddClientBytes(FlowKey fk, ReadOnlySpan<byte> data)
        {
            var b = _map.GetOrAdd(fk, _ => new Buf());
            Append(ref b.Client, ref b.ClientLen, data);
        }

        public static void AddServerBytes(FlowKey fk, ReadOnlySpan<byte> data)
        {
            var b = _map.GetOrAdd(fk, _ => new Buf());
            Append(ref b.Server, ref b.ServerLen, data);
        }

        public static ReadOnlySpan<byte> TryGetClientHello(FlowKey fk)
        {
            if (!_map.TryGetValue(fk, out var b) || b.ClientLen < 5) return ReadOnlySpan<byte>.Empty;
            var span = b.Client.AsSpan(0, b.ClientLen);
            int offset = 0;
            while (offset + 5 <= span.Length)
            {
                if (span[offset] != 0x16) return ReadOnlySpan<byte>.Empty;
                ushort recLen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(offset + 3, 2));
                if (offset + 5 + recLen > span.Length) return ReadOnlySpan<byte>.Empty;
                var body = span.Slice(offset + 5, recLen);
                if (body.Length >= 4 && body[0] == 0x01) // ClientHello
                    return span.Slice(offset, 5 + recLen);
                offset += 5 + recLen;
            }
            return ReadOnlySpan<byte>.Empty;
        }

        public static void TryGetServerHellos(FlowKey fk, out ReadOnlySpan<byte> serverHello, out ReadOnlySpan<byte> certificate)
        {
            serverHello = ReadOnlySpan<byte>.Empty;
            certificate = ReadOnlySpan<byte>.Empty;

            if (!_map.TryGetValue(fk, out var b) || b.ServerLen < 5) return;
            var span = b.Server.AsSpan(0, b.ServerLen);
            int offset = 0;

            while (offset + 5 <= span.Length)
            {
                if (span[offset] != 0x16) break;
                ushort recLen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(offset + 3, 2));
                if (offset + 5 + recLen > span.Length) break;

                var body = span.Slice(offset + 5, recLen);
                if (body.Length >= 4)
                {
                    byte hsType = body[0];
                    if (hsType == 0x02) serverHello = span.Slice(offset, 5 + recLen);  // ServerHello
                    else if (hsType == 0x0B) certificate = span.Slice(offset, 5 + recLen); // Certificate
                }

                offset += 5 + recLen;
            }
        }
    }
}
