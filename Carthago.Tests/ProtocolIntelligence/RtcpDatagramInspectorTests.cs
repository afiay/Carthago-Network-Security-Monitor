// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 3550 RTCP packet structures, no real media/control session.
    public sealed class RtcpDatagramInspectorTests
    {
        private static byte[] Rr() => new byte[] { 0x80, 201, 0, 1, 1, 2, 3, 4 };
        private static byte[] Sr()
        {
            var b = new byte[28]; b[0] = 0x80; b[1] = 200; b[3] = 6; return b;
        }
        private static byte[] Join(params byte[][] parts)
        {
            int n = 0; foreach (var p in parts) n += p.Length;
            var b = new byte[n]; int off = 0;
            foreach (var p in parts) { Array.Copy(p, 0, b, off, p.Length); off += p.Length; }
            return b;
        }
        private static bool Inspect(byte[] bytes, out RtcpCompoundObservation r, bool complete = true)
            => RtpRtcpDatagramInspector.TryInspectRtcp(bytes, complete, out r);

        // Positive sender/receiver/compound structural envelopes.
        [Fact] public void ReceiverReportHeaderIsRecognized()
        {
            Assert.True(Inspect(Rr(), out var r));
            Assert.Equal(201, r.FirstPacketType);
            Assert.Equal(1, r.PacketCount);
        }
        [Fact] public void SenderReportRequiresFullSenderInfo()
        {
            Assert.True(Inspect(Sr(), out var r));
            Assert.Equal(200, r.FirstPacketType);
        }
        [Fact] public void CompoundReportAndByeExposeOnlyKinds()
        {
            var bye = new byte[] { 0x81, 203, 0, 1, 1, 2, 3, 4 };
            var sdes = new byte[] { 0x81, 202, 0, 1, 1, 2, 3, 4 };
            Assert.True(Inspect(Join(Rr(), sdes, bye), out var r));
            Assert.Equal(3, r.PacketCount);
            Assert.True(r.HasBye);
            Assert.False(r.HasFeedback);
        }
        [Fact] public void FeedbackAfterReportIsRecognized()
        {
            var fb = new byte[] { 0x80, 205, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0 };
            Assert.True(Inspect(Join(Rr(), fb), out var r));
            Assert.True(r.HasFeedback);
        }

        // Legitimate negative and cross-protocol discrimination.
        [Fact] public void RtpIsNotRtcp()
        {
            Assert.False(Inspect(new byte[] { 0x80, 96, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1 }, out _));
        }
        [Fact] public void StandaloneByeAndNonRtcpAreRejected()
        {
            Assert.False(Inspect(new byte[] { 0x81, 203, 0, 1, 0, 0, 0, 0 }, out _));
            Assert.False(Inspect(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 }, out _));
        }

        // Malformed, overlong, spoofed counts and padding.
        [Fact] public void DeclaredWordLengthAndTruncationFail()
        {
            var b = Rr(); b[3] = 2;
            Assert.False(Inspect(b, out _));
            Assert.False(Inspect(new byte[] { 0x80, 201, 0, 1 }, out _));
        }
        [Fact] public void ReportCountRequiresAllReportBlocks()
        {
            var b = Rr(); b[0] = 0x81;
            Assert.False(Inspect(b, out _));
            b = Sr(); b[0] = 0x81;
            Assert.False(Inspect(b, out _));
        }
        [Fact] public void WrongVersionAndInvalidPaddingFail()
        {
            var b = Rr(); b[0] = 0x40;
            Assert.False(Inspect(b, out _));
            b = Rr(); b[0] = 0xa0; b[^1] = 0;
            Assert.False(Inspect(b, out _));
            b = new byte[] { 0xa0, 201, 0, 2, 1, 2, 3, 4, 0, 0, 0, 4 };
            Assert.True(Inspect(b, out _));
        }
        [Fact] public void NonfinalPaddingAndOverlongCompoundFail()
        {
            var b = Rr(); b[0] |= 0x20; b[^1] = 1;
            Assert.False(Inspect(Join(b, Rr()), out _));
            Assert.False(Inspect(new byte[8193], out _));
        }

        // Bounded count, duplicates and concurrency.
        [Fact] public void CompoundCountIsBoundedTo32()
        {
            var parts = new byte[32][];
            for (int i = 0; i < parts.Length; i++) parts[i] = Rr();
            Assert.True(Inspect(Join(parts), out var r));
            Assert.Equal(32, r.PacketCount);
            Array.Resize(ref parts, 33); parts[32] = Rr();
            Assert.False(Inspect(Join(parts), out _));
        }
        [Fact] public void DuplicateAndReorderedReportsHaveNoSessionState()
        {
            var b = Join(Rr(), Sr());
            Assert.True(Inspect(b, out var first));
            Assert.True(Inspect(Rr(), out _));
            Assert.True(Inspect(b, out var again));
            Assert.Equal(first, again);
        }
        [Fact] public void ConcurrentCompoundParsingIsStateless()
        {
            var b = Join(Rr(), Sr()); int hits = 0;
            Parallel.For(0, 64, _ =>
            {
                if (Inspect(b, out var r) && r.PacketCount == 2)
                    Interlocked.Increment(ref hits);
            });
            Assert.Equal(64, hits);
        }

        // Provenance and privacy.
        [Fact] public void MissingPlaintextDatagramAttestationFails()
        {
            Assert.False(Inspect(Rr(), out var r, complete: false));
            Assert.Equal(default(RtcpCompoundObservation), r);
        }
        [Fact] public void SsrcAndReportBodyNeverAppearInObservation()
        {
            Assert.True(Inspect(Rr(), out var r));
            Assert.Equal(5, typeof(RtcpCompoundObservation).GetProperties().Length);
            Assert.DoesNotContain("16909060", r.ToString());
        }
        [Fact] public void FailedInspectionResetsObservation()
        {
            Assert.True(Inspect(Rr(), out _));
            Assert.False(Inspect(new byte[] { 0x80, 201 }, out var r));
            Assert.Equal(default(RtcpCompoundObservation), r);
        }
    }
}
