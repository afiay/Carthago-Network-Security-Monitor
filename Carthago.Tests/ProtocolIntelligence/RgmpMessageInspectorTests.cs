// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 3488 packets only; 0 executed, no capture or replay evidence.
    public sealed class RgmpMessageInspectorTests
    {
        private static byte[] Message(RgmpMessageKind kind,
            byte[]? group = null, byte reserved = 0)
        {
            var p = new byte[8];
            p[0] = (byte)kind;
            p[1] = reserved;
            if (group != null) Array.Copy(group, 0, p, 4, 4);
            Rechecksum(p);
            return p;
        }

        private static void Rechecksum(byte[] p)
        {
            p[2] = 0; p[3] = 0;
            uint sum = 0;
            for (int i = 0; i < p.Length; i += 2)
                sum += (uint)((p[i] << 8) | p[i + 1]);
            while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
            ushort checksum = (ushort)~sum;
            p[2] = (byte)(checksum >> 8);
            p[3] = (byte)checksum;
        }

        private static bool Inspect(byte[] packet, out RgmpObservation observation,
            byte protocol = 2, byte ttl = 1, byte[]? destination = null,
            bool complete = true, bool unfragmented = true, bool source = true)
            => RgmpMessageInspector.TryInspect(packet, protocol, ttl,
                destination ?? new byte[] { 224, 0, 0, 25 },
                complete, unfragmented, source, out observation);

        [Fact] public void HelloIsRecognized()
        {
            Assert.True(Inspect(Message(RgmpMessageKind.Hello), out var o));
            Assert.Equal(RgmpMessageKind.Hello, o.MessageKindUnverified);
            Assert.False(o.IsGroupSpecific);
        }

        [Fact] public void ByeIsRecognized()
        {
            Assert.True(Inspect(Message(RgmpMessageKind.Bye), out var o));
            Assert.Equal(RgmpMessageKind.Bye, o.MessageKindUnverified);
        }

        [Fact] public void JoinIsRecognized()
        {
            Assert.True(Inspect(Message(RgmpMessageKind.Join, new byte[] { 239, 1, 2, 3 }), out var o));
            Assert.True(o.IsGroupSpecific);
            Assert.False(o.HasForbiddenGroupUnverified);
        }

        [Fact] public void LeaveIsRecognized()
        {
            Assert.True(Inspect(Message(RgmpMessageKind.Leave, new byte[] { 225, 2, 3, 4 }), out var o));
            Assert.Equal(RgmpMessageKind.Leave, o.MessageKindUnverified);
        }

        [Fact] public void ReservedByteIsIgnoredOnReception()
        {
            Assert.True(Inspect(Message(RgmpMessageKind.Hello, reserved: 0x7f), out var o));
            Assert.True(o.ReservedByteNonZeroUnverified);
        }

        [Fact] public void ReservedMulticastGroupIsFlaggedNotMistakenForSuccess()
        {
            Assert.True(Inspect(Message(RgmpMessageKind.Join, new byte[] { 224, 0, 0, 25 }), out var o));
            Assert.True(o.HasForbiddenGroupUnverified);
        }

        [Fact] public void CiscoDiscoveryGroupIsFlagged()
        {
            Assert.True(Inspect(Message(RgmpMessageKind.Leave, new byte[] { 224, 0, 1, 39 }), out var o));
            Assert.True(o.HasForbiddenGroupUnverified);
        }

        [Fact] public void OtherCiscoDiscoveryGroupIsFlagged()
        {
            Assert.True(Inspect(Message(RgmpMessageKind.Join, new byte[] { 224, 0, 1, 40 }), out var o));
            Assert.True(o.HasForbiddenGroupUnverified);
        }

        [Fact] public void NonMulticastGroupIsRejected()
        {
            Assert.False(Inspect(Message(RgmpMessageKind.Join, new byte[] { 192, 0, 2, 1 }), out _));
        }

        [Fact] public void HelloWithNonzeroGroupIsRejected()
        {
            Assert.False(Inspect(Message(RgmpMessageKind.Hello, new byte[] { 239, 1, 1, 1 }), out _));
        }

        [Fact] public void ByeWithNonzeroGroupIsRejected()
        {
            Assert.False(Inspect(Message(RgmpMessageKind.Bye, new byte[] { 239, 1, 1, 1 }), out _));
        }

        [Fact] public void IgmpLikeMessageTypeIsNotRgmp()
        {
            var p = Message(RgmpMessageKind.Hello); p[0] = 0x16; Rechecksum(p);
            Assert.False(Inspect(p, out _));
        }

        [Fact] public void WrongDestinationIsNotRgmp()
        {
            Assert.False(Inspect(Message(RgmpMessageKind.Hello), out _,
                destination: new byte[] { 224, 0, 0, 1 }));
        }

        [Fact] public void WrongIpProtocolIsNotRgmp()
        {
            Assert.False(Inspect(Message(RgmpMessageKind.Hello), out _, protocol: 17));
        }

        [Fact] public void WrongTtlIsNotRgmp()
        {
            Assert.False(Inspect(Message(RgmpMessageKind.Hello), out _, ttl: 64));
        }

        [Fact] public void TruncatedPayloadFailsClosed()
        {
            Assert.False(Inspect(Message(RgmpMessageKind.Hello).Take(7).ToArray(), out _));
            Assert.False(Inspect(Array.Empty<byte>(), out _));
        }

        [Fact] public void OverlongPayloadFailsClosed()
        {
            Assert.False(Inspect(Message(RgmpMessageKind.Hello).Concat(new byte[] { 0 }).ToArray(), out _));
        }

        [Fact] public void TamperedChecksumFailsClosed()
        {
            var p = Message(RgmpMessageKind.Hello); p[3] ^= 0x01;
            Assert.False(Inspect(p, out _));
        }

        [Fact] public void MissingAnyProducerAttestationFailsClosed()
        {
            var p = Message(RgmpMessageKind.Hello);
            Assert.False(Inspect(p, out _, complete: false));
            Assert.False(Inspect(p, out _, unfragmented: false));
            Assert.False(Inspect(p, out _, source: false));
        }

        [Fact] public void InvalidInputResetsOutput()
        {
            Assert.False(Inspect(new byte[8], out var o));
            Assert.Equal(default(RgmpObservation), o);
        }

        [Fact] public void DuplicateAndOutOfOrderPacketsAreStateless()
        {
            var hello = Message(RgmpMessageKind.Hello);
            var bye = Message(RgmpMessageKind.Bye);
            Assert.True(Inspect(bye, out var first));
            Assert.True(Inspect(hello, out _));
            Assert.True(Inspect(bye, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public async Task ConcurrentInspectionIsDeterministic()
        {
            var p = Message(RgmpMessageKind.Join, new byte[] { 239, 1, 2, 3 });
            var results = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ =>
                Task.Run(() =>
                {
                    Assert.True(Inspect(p, out var o));
                    return o;
                })));
            Assert.All(results, item => Assert.Equal(results[0], item));
        }

        [Fact] public void GroupAddressIsNotRetainedInObservation()
        {
            Assert.True(Inspect(Message(RgmpMessageKind.Join,
                new byte[] { 239, 1, 2, 3 }), out var a));
            Assert.True(Inspect(Message(RgmpMessageKind.Join,
                new byte[] { 239, 9, 8, 7 }), out var b));
            Assert.Equal(a, b);
        }
    }
}
