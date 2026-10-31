// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic classic AOSP ADB transport envelopes; not device or shell evidence.
    public sealed class AdbTransportMessageInspectorTests
    {
        private const uint Cnxn = 0x4e584e43;
        private const uint Auth = 0x48545541;
        private const uint Open = 0x4e45504f;
        private const uint Okay = 0x59414b4f;
        private const uint Clse = 0x45534c43;
        private const uint Wrte = 0x45545257;

        private static byte[] Packet(uint command = Cnxn, int length = 8)
        {
            var data = new byte[24 + length];
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), command);
            uint arg0 = command switch { Cnxn => 0x01000000, Auth => 1, _ => 7 };
            uint arg1 = command switch { Cnxn => 4096, Auth or Open => 0, _ => 9 };
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4, 4), arg0);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8, 4), arg1);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(12, 4), (uint)length);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20, 4), command ^ 0xffffffffu);
            return data;
        }

        private static bool Inspect(byte[] data, out AdbTransportMessageObservation found,
            bool complete = true, bool endpoint = true)
            => AdbTransportMessageInspector.TryInspect(data, complete, endpoint, out found);

        [Theory]
        [InlineData(Cnxn, 8)]
        [InlineData(Auth, 8)]
        [InlineData(Open, 8)]
        [InlineData(Okay, 0)]
        [InlineData(Clse, 0)]
        [InlineData(Wrte, 8)]
        public void RecognizesClassicCommandEnvelopes(uint command, int length)
        {
            Assert.True(Inspect(Packet(command, length), out var found));
            Assert.Equal(command, found.Command);
            Assert.Equal(length, found.PayloadLength);
            Assert.Equal(command == Auth, found.AuthenticationMessageUnverified);
        }

        [Fact] public void UnknownCommandsAndHttpTlsAreRejected()
        {
            Assert.False(Inspect(Packet(0x12345678), out _));
            Assert.False(Inspect(System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1"), out _));
            Assert.False(Inspect(new byte[] { 0x16, 3, 3, 0, 0 }, out _));
        }

        [Fact] public void MagicAndLengthCorruptionFailClosed()
        {
            var data = Packet(); data[20] ^= 0x80; Assert.False(Inspect(data, out _));
            data = Packet(); data[12]++; Assert.False(Inspect(data, out _));
        }

        [Fact] public void TruncatedAndOversizedMessagesAreRejected()
        {
            Assert.False(Inspect(new byte[23], out _));
            Assert.False(Inspect(Packet(Cnxn, 4097), out _));
            var data = Packet(); Array.Resize(ref data, data.Length - 1);
            Assert.False(Inspect(data, out _));
        }

        [Fact] public void InvalidCommandArgumentShapesFail()
        {
            var data = Packet(Open); data.AsSpan(4, 4).Clear(); Assert.False(Inspect(data, out _));
            data = Packet(Auth); data.AsSpan(4, 4).Clear(); Assert.False(Inspect(data, out _));
            data = Packet(Cnxn); data.AsSpan(8, 4).Clear(); Assert.False(Inspect(data, out _));
            data = Packet(Okay, 0); data.AsSpan(8, 4).Clear(); Assert.False(Inspect(data, out _));
        }

        [Fact] public void PayloadRequirementsAreStrict()
        {
            Assert.False(Inspect(Packet(Open, 0), out _));
            Assert.False(Inspect(Packet(Wrte, 0), out _));
            Assert.False(Inspect(Packet(Okay, 1), out _));
            Assert.False(Inspect(Packet(Clse, 1), out _));
        }

        [Fact] public void MissingProducerAttestationFails()
        {
            Assert.False(Inspect(Packet(), out _, complete: false));
            Assert.False(Inspect(Packet(), out _, endpoint: false));
        }

        [Fact] public void MaximumPayloadBoundIsAccepted()
        {
            Assert.True(Inspect(Packet(Cnxn, 4096), out var found));
            Assert.Equal(4096, found.PayloadLength);
        }

        [Fact] public void ReorderedRepeatedMessagesRemainStateless()
        {
            var a = Packet(Open);
            var b = Packet(Auth);
            Assert.True(Inspect(b, out var first));
            Assert.True(Inspect(a, out _));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public async Task ParallelInspectionIsDeterministic()
        {
            var results = await Task.WhenAll(Enumerable.Range(0, 32)
                .Select(_ => Task.Run(() => Inspect(Packet(), out _))));
            Assert.All(results, Assert.True);
        }

        [Fact] public void AuthBytesAndStreamIdentifiersAreNotRetained()
        {
            var a = Packet(Auth);
            var b = Packet(Auth);
            a[24] = 0xAA; b[24] = 0x55;
            a[16] = 0x01; b[16] = 0xFE; // checksum is deliberately not verified
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public void NoAuthenticationSuccessClaimFromAuthEnvelope()
        {
            Assert.True(Inspect(Packet(Auth), out var found));
            Assert.True(found.AuthenticationMessageUnverified);
        }
    }
}
