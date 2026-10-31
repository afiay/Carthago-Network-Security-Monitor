// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic ODVA EtherNet/IP Volume 2 envelopes, not operational OT captures.
    public sealed class CipEncapsulationInspectorTests
    {
        private static byte[] Frame(ushort command, byte[]? payload = null,
            uint session = 1, uint status = 0, uint options = 0)
        {
            payload ??= Array.Empty<byte>();
            var frame = new byte[24 + payload.Length];
            BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(0, 2), command);
            BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(2, 2), (ushort)payload.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(4, 4), session);
            BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(8, 4), status);
            BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(20, 4), options);
            payload.CopyTo(frame, 24);
            return frame;
        }

        private static byte[] RegisterPayload() => new byte[] { 1, 0, 0, 0 };

        private static byte[] Cpf(bool unconnected)
        {
            // InterfaceHandle=0, timeout=0, two items: null/connected address, CIP data.
            var bytes = new byte[unconnected ? 18 : 22];
            bytes[6] = 2;
            int data = unconnected ? 12 : 16;
            if (!unconnected)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(8, 2), 0x00a1);
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(10, 2), 4);
            }
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(data, 2),
                unconnected ? (ushort)0x00b2 : (ushort)0x00b1);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(data + 2, 2), 2);
            bytes[data + 4] = 0x4c;
            bytes[data + 5] = 0x00;
            return bytes;
        }

        private static bool Inspect(byte[] bytes, out CipEncapsulationObservation found,
            bool complete = true, bool tcp = true, bool clientToServer = true,
            ushort sourcePort = 50000, ushort destinationPort = 44818)
            => CipEncapsulationInspector.TryInspect(bytes, sourcePort, destinationPort,
                tcp, clientToServer, complete, out found);

        // 1. Protocol-positive classification with typed, bounded observations.
        [Fact] public void RegisterSessionRequestRequiresZeroSessionAndVersionOne()
        {
            Assert.True(Inspect(Frame(0x65, RegisterPayload(), session: 0), out var found));
            Assert.Equal(CipEncapsulationCommand.RegisterSession, found.Command);
            Assert.Equal(28, found.MessageLength);
            Assert.False(found.IsReply);
        }

        [Fact] public void RegisterSessionResponseRequiresServerDirection()
        {
            Assert.True(Inspect(Frame(0x65, RegisterPayload()), out var found,
                clientToServer: false, sourcePort: 44818, destinationPort: 50000));
            Assert.True(found.IsReply);
        }

        [Theory]
        [InlineData((ushort)0x006f, CipEncapsulationCommand.SendRequestReplyData, true)]
        [InlineData((ushort)0x0070, CipEncapsulationCommand.SendUnitData, false)]
        public void RecognizesConservativeCpf(ushort command, CipEncapsulationCommand expected,
            bool unconnected)
        {
            Assert.True(Inspect(Frame(command, Cpf(unconnected)), out var found));
            Assert.Equal(expected, found.Command);
            Assert.Equal(Cpf(unconnected).Length, found.PayloadLength);
        }

        [Fact] public void UnregisterSessionRequestIsRecognized()
        {
            Assert.True(Inspect(Frame(0x66), out var found));
            Assert.Equal(CipEncapsulationCommand.UnregisterSession, found.Command);
        }

        // 2. Benign negative and cross-protocol discrimination.
        [Fact] public void ExistingListIdentityRemainsOwnedByExistingClassifier()
            => Assert.False(Inspect(Frame(0x63, session: 0), out _));

        [Fact] public void WrongPortAndDirectionFail()
        {
            var frame = Frame(0x66);
            Assert.False(Inspect(frame, out _, destinationPort: 502));
            Assert.False(Inspect(frame, out _, sourcePort: 44818));
            Assert.False(Inspect(frame, out _, clientToServer: false,
                sourcePort: 44818, destinationPort: 50000));
        }

        [Fact] public void UdpCannotBeTreatedAsSessionEncapsulation()
            => Assert.False(Inspect(Frame(0x65, RegisterPayload(), session: 0), out _, tcp: false));

        [Fact] public void OtherProtocolAndUnsupportedCommandFail()
        {
            Assert.False(Inspect(new byte[] { 0x47, 0x45, 0x54, 0x20 }, out _));
            Assert.False(Inspect(Frame(0x0004), out _));
        }

        // 3. Truncation, spoofing, endian, and strict bounds.
        [Fact] public void HeaderAndDeclaredLengthMustMatchExactly()
        {
            var frame = Frame(0x65, RegisterPayload(), session: 0);
            Assert.False(Inspect(frame.AsSpan(0, 23).ToArray(), out _));
            frame[2] = 5;
            Assert.False(Inspect(frame, out _));
        }

        [Fact] public void OversizedOrTrailingBytesFailClosed()
        {
            Assert.False(Inspect(new byte[65536], out _));
            var frame = Frame(0x66);
            Array.Resize(ref frame, 25);
            Assert.False(Inspect(frame, out _));
        }

        [Fact] public void NonzeroOptionsAndStatusFailClosed()
        {
            Assert.False(Inspect(Frame(0x66, options: 1), out _));
            Assert.False(Inspect(Frame(0x66, status: 1), out _));
        }

        [Fact] public void UnsupportedRegisterVersionAndFlagsFail()
        {
            Assert.False(Inspect(Frame(0x65, new byte[] { 2, 0, 0, 0 }, session: 0), out _));
            Assert.False(Inspect(Frame(0x65, new byte[] { 1, 0, 1, 0 }, session: 0), out _));
        }

        [Fact] public void MissingSessionForDataAndUnregisterFails()
        {
            Assert.False(Inspect(Frame(0x6f, Cpf(true), session: 0), out _));
            Assert.False(Inspect(Frame(0x66, session: 0), out _));
        }

        [Fact] public void TruncatedCpfItemAndIncorrectItemCountFail()
        {
            var frame = Frame(0x6f, Cpf(true));
            frame[24 + 6] = 3;
            Assert.False(Inspect(frame, out _));
            frame = Frame(0x6f, Cpf(true));
            frame[24 + 14] = 255;
            Assert.False(Inspect(frame, out _));
        }

        [Fact] public void CrossedAddressAndDataItemTypesFail()
        {
            Assert.False(Inspect(Frame(0x6f, Cpf(false)), out _));
            Assert.False(Inspect(Frame(0x70, Cpf(true)), out _));
        }

        // 4. Stateless reordering, retransmission and concurrent independent calls.
        [Fact] public void ReorderedAndRepeatedEnvelopesDoNotImplySessionState()
        {
            var unregister = Frame(0x66);
            var register = Frame(0x65, RegisterPayload(), session: 0);
            Assert.True(Inspect(unregister, out var a));
            Assert.True(Inspect(register, out _));
            Assert.True(Inspect(unregister, out var b));
            Assert.Equal(a, b);
        }

        [Fact] public void ParallelInspectionIsDeterministicAndBounded()
        {
            var frame = Frame(0x6f, Cpf(true));
            int count = 0;
            Parallel.For(0, 64, _ =>
            {
                if (Inspect(frame, out var found)
                    && found.Command == CipEncapsulationCommand.SendRequestReplyData)
                    Interlocked.Increment(ref count);
            });
            Assert.Equal(64, count);
        }

        // 5. Encryption, provenance and privacy boundaries.
        [Fact] public void NoTrustedPlaintextMessageMeansNoClassification()
            => Assert.False(Inspect(Frame(0x6f, Cpf(true)), out _, complete: false));

        [Fact] public void OpaqueSenderContextAndSessionHandleAreNeverReturned()
        {
            var frame = Frame(0x6f, Cpf(true), session: 0xdeadbeef);
            frame[12] = 0xaa;
            Assert.True(Inspect(frame, out var found));
            Assert.Equal(4, typeof(CipEncapsulationObservation).GetProperties().Length);
            Assert.DoesNotContain("3735928559", found.ToString());
            Assert.DoesNotContain("170", found.ToString());
        }

        [Fact] public void InvalidMessageAlwaysReturnsDefaultObservation()
        {
            Assert.False(Inspect(Frame(0x6f, new byte[2]), out var found));
            Assert.Equal(default(CipEncapsulationObservation), found);
        }
    }
}
