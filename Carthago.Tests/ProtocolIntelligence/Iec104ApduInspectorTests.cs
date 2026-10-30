// SPDX-License-Identifier: MIT
using System;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic IEC 60870-5-104 APCI shapes, not device command outcomes.
    public sealed class Iec104ApduInspectorTests
    {
        private static byte[] IFrame() => new byte[]
            { 0x68, 0x0e, 0x4e, 0x14, 0x7c, 0x00, 0x65, 0x01,
              0x0a, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x05 };

        [Fact] public void ValidInformationFrameRecognized()
        {
            Assert.True(Iec104ApduInspector.TryInspect(IFrame(), true, out var found));
            Assert.Equal(Iec104FrameKind.Information, found.Kind);
            Assert.Equal((byte)0x65, found.AsduType);
        }

        [Fact] public void ValidSupervisoryFrameRecognized()
        {
            Assert.True(Iec104ApduInspector.TryInspect(
                new byte[] { 0x68, 0x04, 0x01, 0x00, 0x0a, 0x00 }, true, out var found));
            Assert.Equal(Iec104FrameKind.Supervisory, found.Kind);
            Assert.Null(found.AsduType);
        }

        [Theory]
        [InlineData((byte)0x07)] [InlineData((byte)0x0b)]
        [InlineData((byte)0x13)] [InlineData((byte)0x23)]
        [InlineData((byte)0x43)] [InlineData((byte)0x83)]
        public void DefinedUnnumberedFramesRecognized(byte command)
        {
            Assert.True(Iec104ApduInspector.TryInspect(
                new byte[] { 0x68, 0x04, command, 0, 0, 0 }, true, out var found));
            Assert.Equal(Iec104FrameKind.Unnumbered, found.Kind);
        }

        [Fact] public void UnattestedBoundaryRejected()
        {
            Assert.False(Iec104ApduInspector.TryInspect(IFrame(), false, out _));
        }

        [Fact] public void Dnp3OrUnrelatedFrameRejected()
        {
            Assert.False(Iec104ApduInspector.TryInspect(
                new byte[] { 0x05, 0x64, 0x05, 0x00, 0, 0 }, true, out _));
        }

        [Fact] public void TruncatedFrameRejected()
        {
            Assert.False(Iec104ApduInspector.TryInspect(IFrame().AsSpan(0, 15), true, out _));
        }

        [Fact] public void DeclaredOverlongFrameRejected()
        {
            var bytes = IFrame(); bytes[1] = 0xfd;
            Assert.False(Iec104ApduInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void InvalidSupervisoryControlRejected()
        {
            Assert.False(Iec104ApduInspector.TryInspect(
                new byte[] { 0x68, 0x04, 0x01, 0x01, 0, 0 }, true, out _));
        }

        [Fact] public void InvalidUnnumberedReservedBitsRejected()
        {
            Assert.False(Iec104ApduInspector.TryInspect(
                new byte[] { 0x68, 0x04, 0x07, 0, 1, 0 }, true, out _));
        }

        [Fact] public void ZeroObjectInformationFrameRejected()
        {
            var bytes = IFrame(); bytes[7] = 0;
            Assert.False(Iec104ApduInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void RepeatIsStatelessNotReplayVerdict()
        {
            var bytes = IFrame();
            Assert.True(Iec104ApduInspector.TryInspect(bytes, true, out var first));
            Assert.True(Iec104ApduInspector.TryInspect(bytes, true, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public void NoStationAddressOrCommandBodyRetained()
        {
            var bytes = IFrame(); bytes[10] = 0xab;
            Assert.True(Iec104ApduInspector.TryInspect(bytes, true, out var found));
            Assert.DoesNotContain("171", found.ToString());
        }
    }
}