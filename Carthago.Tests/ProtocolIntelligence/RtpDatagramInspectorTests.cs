// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 3550 RTP headers; no real calls, codec data or packet capture.
    public sealed class RtpDatagramInspectorTests
    {
        private static byte[] Packet()
            => new byte[] { 0x80, 96, 0x12, 0x34, 0, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef, 0x55 };
        private static bool Inspect(byte[] bytes, out RtpEnvelopeObservation r, bool complete = true)
            => RtpRtcpDatagramInspector.TryInspectRtp(bytes, complete, out r);

        // Positive header shapes.
        [Fact] public void BasicRtpHeaderReturnsOnlyTypedMetadata()
        {
            Assert.True(Inspect(Packet(), out var r));
            Assert.Equal(96, r.PayloadType);
            Assert.Equal((ushort)0x1234, r.SequenceNumber);
            Assert.Equal(13, r.DatagramLength);
        }
        [Fact] public void CsrcAndExtensionLengthsAreValidated()
        {
            var b = new byte[] { 0x91, 96, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2,
                0, 0, 0, 3, 0xbe, 0xde, 0, 1, 1, 2, 3, 4, 0x44 };
            Assert.True(Inspect(b, out var r));
            Assert.Equal(1, r.CsrcCount);
            Assert.True(r.HeaderExtensionPresent);
        }
        [Fact] public void ValidPaddingIsAcceptedWithoutInspectingMedia()
        {
            var b = Packet();
            b[0] |= 0x20;
            b[^1] = 1;
            Assert.True(Inspect(b, out var r));
            Assert.True(r.PaddingPresent);
        }
        [Fact] public void MarkerBitIsNotPartOfPayloadType()
        {
            var b = Packet(); b[1] = 0xe0;
            Assert.True(Inspect(b, out var r));
            Assert.Equal(96, r.PayloadType);
        }

        // Legitimate negatives and cross-protocol.
        [Fact] public void RtcpSenderReportIsNotRtp()
        {
            Assert.False(Inspect(new byte[] { 0x80, 200, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0 }, out _));
        }
        [Fact] public void HttpAndDtlsAreNotRtp()
        {
            Assert.False(Inspect(new byte[] { 71, 69, 84, 32, 47, 32, 0, 0, 0, 0, 0, 0 }, out _));
            Assert.False(Inspect(new byte[] { 22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, out _));
        }

        // Malformed and adversarial lengths.
        [Fact] public void TruncatedCsrcAndExtensionFail()
        {
            var b = Packet(); b[0] |= 0x02;
            Assert.False(Inspect(b, out _));
            b = Packet(); b[0] |= 0x10;
            Assert.False(Inspect(b, out _));
        }
        [Fact] public void SpoofedExtensionLengthFails()
        {
            var b = new byte[] { 0x90, 96, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
                0xbe, 0xde, 0xff, 0xff };
            Assert.False(Inspect(b, out _));
        }
        [Fact] public void PaddingCannotBeZeroOrOverlapHeader()
        {
            var b = Packet(); b[0] |= 0x20; b[^1] = 0;
            Assert.False(Inspect(b, out _));
            b[^1] = 14;
            Assert.False(Inspect(b, out _));
        }
        [Fact] public void OversizeWrongVersionAndShortHeaderFail()
        {
            Assert.False(Inspect(new byte[8193], out _));
            Assert.False(Inspect(new byte[11], out _));
            var b = Packet(); b[0] = 0x40;
            Assert.False(Inspect(b, out _));
        }

        // Stateless, unordered and concurrent packet observations.
        [Fact] public void ReorderedSequencesDoNotCreateSessionState()
        {
            var b = Packet();
            Assert.True(Inspect(b, out var a));
            b[3] = 0x30;
            Assert.True(Inspect(b, out var lower));
            b[3] = 0x34;
            Assert.True(Inspect(b, out var again));
            Assert.Equal(a, again);
            Assert.NotEqual(a.SequenceNumber, lower.SequenceNumber);
        }
        [Fact] public void ConcurrentInspectionIsDeterministic()
        {
            var b = Packet(); int hits = 0;
            Parallel.For(0, 64, _ =>
            {
                if (Inspect(b, out var r) && r.PayloadType == 96)
                    Interlocked.Increment(ref hits);
            });
            Assert.Equal(64, hits);
        }

        // Privacy and provenance.
        [Fact] public void MissingAttestationFailsClosed()
        {
            Assert.False(Inspect(Packet(), out var r, complete: false));
            Assert.Equal(default(RtpEnvelopeObservation), r);
        }
        [Fact] public void SsrcAndMediaAreNotRetained()
        {
            Assert.True(Inspect(Packet(), out var r));
            Assert.Equal(6, typeof(RtpEnvelopeObservation).GetProperties().Length);
            Assert.DoesNotContain("3735928559", r.ToString());
        }
        [Fact] public void InvalidPacketDoesNotReusePreviousObservation()
        {
            Assert.True(Inspect(Packet(), out _));
            Assert.False(Inspect(new byte[] { 0x80 }, out var r));
            Assert.Equal(default(RtpEnvelopeObservation), r);
        }
    }
}
