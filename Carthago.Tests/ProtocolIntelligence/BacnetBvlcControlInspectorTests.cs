// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic Annex J control frames, not captured or authenticated device data.
    public sealed class BacnetBvlcControlInspectorTests
    {
        private static byte[] Message(byte function, byte[]? body = null)
        {
            body ??= Array.Empty<byte>();
            var message = new byte[4 + body.Length];
            message[0] = 0x81;
            message[1] = function;
            BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2, 2), (ushort)message.Length);
            body.CopyTo(message, 4);
            return message;
        }

        private static bool Inspect(byte[] message, out BvlcControlObservation found,
            bool attested = true)
            => BacnetBvlcControlInspector.TryInspect(message, attested, out found);

        // Positive structural classification.
        [Theory]
        [InlineData(0)]
        [InlineData(60)]
        [InlineData(65535)]
        public void RegisterForeignDeviceRetainsOnlyTtl(int ttl)
        {
            var body = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(body, (ushort)ttl);
            Assert.True(Inspect(Message(0x05, body), out var found));
            Assert.Equal(BvlcControlFunction.RegisterForeignDevice, found.Function);
            Assert.Equal((ushort)ttl, found.RequestedTtlSeconds);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(32)]
        public void WriteBdtCountsBoundedEntriesWithoutExposingThem(int count)
        {
            var body = new byte[count * 10];
            for (int i = 0; i < count; i++)
                body[i * 10] = 192; // Synthetic table contents are not retained.
            Assert.True(Inspect(Message(0x01, body), out var found));
            Assert.Equal(count, found.TableEntryCount);
            Assert.Equal(0, found.RequestedTtlSeconds);
        }

        [Fact]
        public void DeleteFdtRecognizesExactAddressEnvelope()
        {
            var body = new byte[] { 192, 0, 2, 7, 0xba, 0xc0 };
            Assert.True(Inspect(Message(0x08, body), out var found));
            Assert.Equal(BvlcControlFunction.DeleteForeignDeviceTableEntry, found.Function);
            Assert.Equal(10, found.MessageLength);
        }

        [Theory]
        [InlineData(0x02)]
        [InlineData(0x06)]
        public void ReadTableRequestsHaveNoPayload(int function)
        {
            Assert.True(Inspect(Message((byte)function), out var found));
            Assert.Equal(4, found.MessageLength);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(0x30)]
        public void ResultCodeIsUnauthenticatedWireMetadata(int code)
        {
            var body = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(body, (ushort)code);
            Assert.True(Inspect(Message(0x00, body), out var found));
            Assert.Equal((ushort)code, found.UnauthenticatedResultCode);
        }

        // Legitimate negative and cross-protocol discrimination.
        [Theory]
        [InlineData(0x04)]
        [InlineData(0x09)]
        [InlineData(0x0a)]
        [InlineData(0x0b)]
        public void NpduFunctionsNeverPromotedToBvlcControl(int function)
        {
            Assert.False(Inspect(Message((byte)function), out _));
        }

        [Fact]
        public void BacnetIpv6AndArbitraryUdpAreRejected()
        {
            var ipv6 = Message(0x05, new byte[] { 0, 60 });
            ipv6[0] = 0x82;
            Assert.False(Inspect(ipv6, out _));
            var unrelated = Message(0x05, new byte[] { 0, 60 });
            unrelated[0] = 0x45;
            Assert.False(Inspect(unrelated, out _));
        }

        // Truncation, spoofing and finite memory bounds.
        [Fact]
        public void TruncatedAndExtraBytesFailClosed()
        {
            var valid = Message(0x05, new byte[] { 0, 60 });
            Assert.False(Inspect(valid.AsSpan(0, 5).ToArray(), out _));
            var extra = new byte[valid.Length + 1];
            valid.CopyTo(extra, 0);
            Assert.False(Inspect(extra, out _));
        }

        [Fact]
        public void DeclaredLengthSpoofingAndUnsupportedResultFailClosed()
        {
            var valid = Message(0x05, new byte[] { 0, 60 });
            valid[3] = 5;
            Assert.False(Inspect(valid, out _));
            Assert.False(Inspect(Message(0x00, new byte[] { 0, 0xff }), out _));
        }

        [Fact]
        public void MisalignedAndOversizedBdtFailClosed()
        {
            Assert.False(Inspect(Message(0x01), out _));
            Assert.False(Inspect(Message(0x01, new byte[9]), out _));
            Assert.False(Inspect(Message(0x01, new byte[33 * 10]), out _));
        }

        // Stateless duplicate/reordering and concurrency controls.
        [Fact]
        public void DuplicateAndReorderedDatagramsHaveIndependentResults()
        {
            var register = Message(0x05, new byte[] { 0, 60 });
            var read = Message(0x06);
            Assert.True(Inspect(register, out var first));
            Assert.True(Inspect(read, out _));
            Assert.True(Inspect(register, out var again));
            Assert.Equal(first, again);
        }

        [Fact]
        public void ConcurrentInspectionDoesNotShareState()
        {
            var message = Message(0x05, new byte[] { 0, 60 });
            int failures = 0;
            Parallel.For(0, 64, _ =>
            {
                if (!Inspect(message, out var found)
                    || found.Function != BvlcControlFunction.RegisterForeignDevice)
                    Interlocked.Increment(ref failures);
            });
            Assert.Equal(0, failures);
        }

        // Provenance, privacy and encrypted/no-plaintext boundary.
        [Fact]
        public void NoAttestationNeverProducesObservation()
        {
            Assert.False(Inspect(Message(0x05, new byte[] { 0, 60 }),
                out var found, attested: false));
            Assert.Equal(default, found);
        }

        [Fact]
        public void AddressBytesNeverAppearInObservation()
        {
            var body = new byte[] { 203, 0, 113, 27, 0xba, 0xc0 };
            Assert.True(Inspect(Message(0x08, body), out var found));
            Assert.DoesNotContain("203", found.ToString());
            Assert.DoesNotContain("113", found.ToString());
            Assert.Equal(0, found.TableEntryCount);
        }
    }
}
