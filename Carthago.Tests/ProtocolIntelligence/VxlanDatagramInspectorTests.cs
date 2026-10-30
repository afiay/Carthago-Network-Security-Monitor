// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 7348 base VXLAN envelopes; no real MAC/IP/tenant secrets.
    public sealed class VxlanDatagramInspectorTests
    {
        private static byte[] Ipv4(int vni = 42, bool vlan = false)
        {
            int payloadOffset = vlan ? 26 : 22;
            var bytes = new byte[payloadOffset + 20];
            bytes[0] = 0x08;
            bytes[4] = (byte)(vni >> 16);
            bytes[5] = (byte)(vni >> 8);
            bytes[6] = (byte)vni;
            if (vlan)
            {
                bytes[20] = 0x81; bytes[21] = 0x00;
                bytes[24] = 0x08; bytes[25] = 0x00;
            }
            else
            {
                bytes[20] = 0x08; bytes[21] = 0x00;
            }
            bytes[payloadOffset] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(payloadOffset + 2, 2), 20);
            return bytes;
        }

        [Theory]
        [InlineData(0)]
        [InlineData(42)]
        [InlineData(0xffffff)]
        public void ValidIpv4EnvelopeWithVni(int vni)
        {
            Assert.True(VxlanDatagramInspector.TryInspect(Ipv4(vni), 4789, true, out var found));
            Assert.Equal(vni, found.Vni);
            Assert.Equal((ushort)0x0800, found.InnerEtherType);
            Assert.False(found.HasVlanTag);
        }

        [Fact] public void SingleVlanTagRecognized()
        {
            Assert.True(VxlanDatagramInspector.TryInspect(Ipv4(7, true), 4789, true, out var found));
            Assert.True(found.HasVlanTag);
            Assert.Equal(7, found.Vni);
        }

        [Fact] public void Ipv6EnvelopeRecognized()
        {
            var bytes = new byte[8 + 14 + 41];
            bytes[0] = 8; bytes[20] = 0x86; bytes[21] = 0xdd;
            bytes[22] = 0x60; bytes[27] = 1;
            Assert.True(VxlanDatagramInspector.TryInspect(bytes, 4789, true, out var found));
            Assert.Equal((ushort)0x86dd, found.InnerEtherType);
        }

        [Fact] public void ArpEnvelopeRecognizedWithoutArpSemanticClaims()
        {
            var bytes = new byte[8 + 14 + 28];
            bytes[0] = 8; bytes[20] = 0x08; bytes[21] = 0x06;
            Assert.True(VxlanDatagramInspector.TryInspect(bytes, 4789, true, out _));
        }

        [Fact] public void WrongUdpDestinationRejected()
            => Assert.False(VxlanDatagramInspector.TryInspect(Ipv4(), 8472, true, out _));

        [Fact] public void UnattestedUdpBoundaryRejected()
            => Assert.False(VxlanDatagramInspector.TryInspect(Ipv4(), 4789, false, out _));

        [Fact] public void MissingIFlagRejected()
        {
            var bytes = Ipv4(); bytes[0] = 0;
            Assert.False(VxlanDatagramInspector.TryInspect(bytes, 4789, true, out _));
        }

        [Fact] public void UnknownExtensionFlagsFailClosed()
        {
            var bytes = Ipv4(); bytes[0] = 0x0c;
            Assert.False(VxlanDatagramInspector.TryInspect(bytes, 4789, true, out _));
        }

        [Fact] public void ReservedBytesRejectedInStrictBaseProfile()
        {
            var bytes = Ipv4(); bytes[3] = 1;
            Assert.False(VxlanDatagramInspector.TryInspect(bytes, 4789, true, out _));
        }

        [Fact] public void TruncatedInnerFrameRejected()
        {
            var bytes = Ipv4();
            Assert.False(VxlanDatagramInspector.TryInspect(bytes.AsSpan(0, 21), 4789, true, out _));
        }

        [Fact] public void TruncatedIpv4HeaderRejected()
        {
            var bytes = Ipv4();
            Assert.False(VxlanDatagramInspector.TryInspect(bytes.AsSpan(0, 41), 4789, true, out _));
        }

        [Fact] public void InvalidInnerIpLengthRejected()
        {
            var bytes = Ipv4(); bytes[25] = 21;
            Assert.False(VxlanDatagramInspector.TryInspect(bytes, 4789, true, out _));
        }

        [Fact] public void NestedVlanTagsNotSilentlyDecoded()
        {
            var bytes = Ipv4(42, true); bytes[24] = 0x81; bytes[25] = 0x00;
            Assert.False(VxlanDatagramInspector.TryInspect(bytes, 4789, true, out _));
        }

        [Fact] public void OversizedDatagramRejected()
            => Assert.False(VxlanDatagramInspector.TryInspect(new byte[65536], 4789, true, out _));

        [Fact] public void RepeatedFrameDoesNotProveVtepAuthorization()
        {
            var bytes = Ipv4();
            Assert.True(VxlanDatagramInspector.TryInspect(bytes, 4789, true, out var first));
            Assert.True(VxlanDatagramInspector.TryInspect(bytes, 4789, true, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public void InnerMacAndIpAreNotRetained()
        {
            var bytes = Ipv4(); bytes[8] = 0xaa; bytes[14] = 0xbb; bytes[34] = 203;
            Assert.True(VxlanDatagramInspector.TryInspect(bytes, 4789, true, out var found));
            Assert.DoesNotContain("203", found.ToString());
            Assert.DoesNotContain("170", found.ToString());
        }

        [Fact] public void StatelessConcurrentInspectionIsDeterministic()
        {
            var bytes = Ipv4();
            Parallel.For(0, 32, index =>
                Assert.True(VxlanDatagramInspector.TryInspect(bytes, 4789, true, out var observation)));
        }
    }
}
