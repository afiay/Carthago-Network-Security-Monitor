// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;
namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic FT1.2 bytes based on Beckhoff IEC101 telegram structure; NOT capture.
    public sealed class Iec101Ft12InspectorTests
    {
        private static byte Sum(byte[] data, int start, int length)
        {
            int sum = 0;
            for (int i = start; i < start + length; i++) sum += data[i];
            return (byte)sum;
        }
        private static byte[] Fixed(int addressWidth = 1, byte control = 0x49)
        {
            var b = new byte[addressWidth + 4];
            b[0] = 0x10; b[1] = control;
            for (int i = 0; i < addressWidth; i++) b[2 + i] = (byte)(0x11 + i);
            b[^2] = Sum(b, 1, addressWidth + 1); b[^1] = 0x16;
            return b;
        }
        private static byte[] Variable(int addressWidth = 1, byte control = 0x08,
            byte[]? asdu = null)
        {
            asdu ??= new byte[] { 0x2d, 0x01, 0x06, 0, 1, 0 };
            int len = 1 + addressWidth + asdu.Length;
            var b = new byte[len + 6];
            b[0] = 0x68; b[1] = (byte)len; b[2] = (byte)len;
            b[3] = 0x68; b[4] = control;
            for (int i = 0; i < addressWidth; i++) b[5 + i] = (byte)(0x11 + i);
            Array.Copy(asdu, 0, b, 5 + addressWidth, asdu.Length);
            b[^2] = Sum(b, 4, len); b[^1] = 0x16;
            return b;
        }
        private static bool Inspect(byte[] bytes, out Iec101Ft12Observation result,
            bool complete = true, int addressWidth = 1)
            => Iec101Ft12Inspector.TryInspect(bytes, complete, addressWidth, out result);

        // Positive protocol classification.
        [Theory][InlineData(1)][InlineData(2)]
        public void FixedFrameRecognizedAtBothAddressWidths(int width)
        {
            Assert.True(Inspect(Fixed(width), out var r, addressWidth: width));
            Assert.Equal(Iec101Ft12FrameKind.Fixed, r.Kind);
            Assert.Equal(9, r.LinkFunctionCode);
            Assert.Null(r.AsduType);
        }
        [Theory][InlineData(1)][InlineData(2)]
        public void VariableFrameExposesOnlyUntrustedAsduType(int width)
        {
            Assert.True(Inspect(Variable(width), out var r, addressWidth: width));
            Assert.Equal(Iec101Ft12FrameKind.Variable, r.Kind);
            Assert.Equal((byte)0x2d, r.AsduType);
        }
        [Theory]
        [InlineData((byte)0xe5, Iec101Ft12FrameKind.PositiveAcknowledgement)]
        [InlineData((byte)0xa2, Iec101Ft12FrameKind.NegativeAcknowledgement)]
        public void SingleByteAcksAreOnlyLinkShape(byte b, Iec101Ft12FrameKind kind)
        {
            Assert.True(Inspect(new[] { b }, out var r));
            Assert.Equal(kind, r.Kind);
            Assert.Null(r.LinkFunctionCode);
        }

        // Legitimate negatives and cross-protocol discrimination.
        [Fact] public void Iec104AndHttpAreNotIec101()
        {
            Assert.False(Inspect(new byte[] { 0x68, 4, 0, 0, 0, 0 }, out _));
            Assert.False(Inspect(new byte[] { 0x47, 0x45, 0x54, 0x20 }, out _));
        }
        [Fact] public void IncorrectAddressConfigurationFails()
        {
            Assert.False(Inspect(Fixed(), out _, addressWidth: 2));
            Assert.False(Inspect(Fixed(), out _, addressWidth: 0));
            Assert.False(Inspect(Fixed(), out _, addressWidth: 3));
        }

        // Malformed/truncated/overlong/spoofed.
        [Fact] public void TruncatedAndOverlongFramesFail()
        {
            Assert.False(Inspect(Fixed().AsSpan(0, 4).ToArray(), out _));
            Assert.False(Inspect(Variable().AsSpan(0, 6).ToArray(), out _));
            Assert.False(Inspect(new byte[262], out _));
        }
        [Fact] public void RepeatedLengthStartAndChecksumMustAgree()
        {
            var b = Variable(); b[2]++; Assert.False(Inspect(b, out _));
            b = Variable(); b[3] = 0x10; Assert.False(Inspect(b, out _));
            b = Variable(); b[^2]++; Assert.False(Inspect(b, out _));
            b = Fixed(); b[^2]++; Assert.False(Inspect(b, out _));
            b = Fixed(); b[^1] = 0; Assert.False(Inspect(b, out _));
        }
        [Fact] public void ReservedControlAndEmptyAsduFail()
        {
            Assert.False(Inspect(Fixed(control: 0xc9), out _));
            Assert.False(Inspect(Variable(control: 0x88), out _));
            Assert.False(Inspect(Variable(asdu: new byte[] { 0 }), out _));
            Assert.False(Inspect(Variable(asdu: Array.Empty<byte>()), out _));
        }
        [Fact] public void MaximumFrameIsBounded()
        {
            var b = Variable(asdu: new byte[253]);
            b[6] = 1; b[^2] = Sum(b, 4, 255);
            Assert.True(Inspect(b, out var r));
            Assert.Equal(261, r.FrameLength);
            Array.Resize(ref b, 262);
            Assert.False(Inspect(b, out _));
        }

        // Stateless duplicate, reordering and concurrency.
        [Fact] public void RetransmissionDoesNotCreateLinkState()
        {
            var b = Variable();
            Assert.True(Inspect(b, out var first));
            Assert.True(Inspect(new byte[] { 0xe5 }, out _));
            Assert.True(Inspect(b, out var again));
            Assert.Equal(first, again);
        }
        [Fact] public void ParallelInspectionIsDeterministic()
        {
            var b = Variable(); int hits = 0;
            Parallel.For(0, 64, _ =>
            {
                if (Inspect(b, out var r) && r.Kind == Iec101Ft12FrameKind.Variable)
                    Interlocked.Increment(ref hits);
            });
            Assert.Equal(64, hits);
        }

        // Provenance, privacy and fail-closed.
        [Fact] public void MissingPlaintextSerialProvenanceFailsClosed()
        {
            Assert.False(Inspect(Variable(), out var r, complete: false));
            Assert.Equal(default(Iec101Ft12Observation), r);
        }
        [Fact] public void LinkAddressAndAsduPayloadAreNotReturned()
        {
            var b = Variable(addressWidth: 2);
            b[5] = 0xef; b[6] = 0xbe; b[^2] = Sum(b, 4, b[1]);
            Assert.True(Inspect(b, out var r, addressWidth: 2));
            Assert.Equal(4, typeof(Iec101Ft12Observation).GetProperties().Length);
            Assert.DoesNotContain("48879", r.ToString());
        }
        [Fact] public void InvalidBytesDoNotLeakPreviousObservation()
        {
            Assert.False(Inspect(new byte[] { 0x16, 0x68, 0xe5 }, out var r));
            Assert.Equal(default(Iec101Ft12Observation), r);
        }
    }
}
