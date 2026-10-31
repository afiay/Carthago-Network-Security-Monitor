// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 8926 envelopes, no real tenant IDs, MACs or addresses.
    public sealed class GeneveDatagramInspectorTests
    {
        private static byte[] Ipv4(int vni = 42, bool vlan = false, bool option = false)
        {
            int start = option ? 12 : 8;
            int ipOffset = start + (vlan ? 18 : 14);
            var bytes = new byte[ipOffset + 20];
            bytes[0] = option ? (byte)1 : (byte)0;
            bytes[2] = 0x65; bytes[3] = 0x58;
            bytes[4] = (byte)(vni >> 16);
            bytes[5] = (byte)(vni >> 8);
            bytes[6] = (byte)vni;
            if (option)
            {
                bytes[8] = 0x01; bytes[9] = 0x02; bytes[10] = 0x01; bytes[11] = 0;
            }
            int typeOffset = start + 12;
            if (vlan)
            {
                bytes[typeOffset] = 0x81; bytes[typeOffset + 1] = 0;
                bytes[typeOffset + 4] = 8; bytes[typeOffset + 5] = 0;
            }
            else
            {
                bytes[typeOffset] = 8; bytes[typeOffset + 1] = 0;
            }
            bytes[ipOffset] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(ipOffset + 2, 2), 20);
            return bytes;
        }

        [Theory]
        [InlineData(0)]
        [InlineData(42)]
        [InlineData(16777215)]
        public void ValidVniAndIpv4Frame(int vni)
        {
            Assert.True(GeneveDatagramInspector.TryInspect(Ipv4(vni), 6081, true, out var result));
            Assert.Equal(vni, result.Vni);
            Assert.Equal((ushort)0x0800, result.InnerEtherType);
        }

        [Fact] public void NoncriticalOptionIsBoundedAndCounted()
        {
            Assert.True(GeneveDatagramInspector.TryInspect(Ipv4(option: true), 6081, true, out var result));
            Assert.Equal(1, result.NonCriticalOptionCount);
        }

        [Fact] public void SingleInnerVlanRecognized()
        {
            Assert.True(GeneveDatagramInspector.TryInspect(Ipv4(vlan: true), 6081, true, out var result));
            Assert.True(result.HasVlanTag);
        }

        [Fact] public void WrongPortFails()
            => Assert.False(GeneveDatagramInspector.TryInspect(Ipv4(), 4789, true, out _));

        [Fact] public void UnattestedPayloadFails()
            => Assert.False(GeneveDatagramInspector.TryInspect(Ipv4(), 6081, false, out _));

        [Fact] public void NonGeneveVersionFails()
        {
            var bytes = Ipv4(); bytes[0] = 0x40;
            Assert.False(GeneveDatagramInspector.TryInspect(bytes, 6081, true, out _));
        }

        [Fact] public void ControlFlagRequiresSeparateHandling()
        {
            var bytes = Ipv4(); bytes[1] = 0x80;
            Assert.False(GeneveDatagramInspector.TryInspect(bytes, 6081, true, out _));
        }

        [Fact] public void CriticalHeaderFlagFailsClosed()
        {
            var bytes = Ipv4(option: true); bytes[1] = 0x40;
            Assert.False(GeneveDatagramInspector.TryInspect(bytes, 6081, true, out _));
        }

        [Fact] public void CriticalOptionWithoutHeaderFlagFailsClosed()
        {
            var bytes = Ipv4(option: true); bytes[10] = 0x81;
            Assert.False(GeneveDatagramInspector.TryInspect(bytes, 6081, true, out _));
        }

        [Fact] public void OptionLengthBeyondBoundaryFails()
        {
            var bytes = Ipv4(option: true); bytes[11] = 2;
            Assert.False(GeneveDatagramInspector.TryInspect(bytes, 6081, true, out _));
        }

        [Fact] public void TruncatedEnvelopeFails()
            => Assert.False(GeneveDatagramInspector.TryInspect(Ipv4().AsSpan(0, 21), 6081, true, out _));

        [Fact] public void UnsupportedProtocolTypeFails()
        {
            var bytes = Ipv4(); bytes[2] = 0x08; bytes[3] = 0;
            Assert.False(GeneveDatagramInspector.TryInspect(bytes, 6081, true, out _));
        }

        [Fact] public void NestedVlanFailsClosed()
        {
            var bytes = Ipv4(vlan: true); bytes[24] = 0x81; bytes[25] = 0;
            Assert.False(GeneveDatagramInspector.TryInspect(bytes, 6081, true, out _));
        }

        [Fact] public void InvalidInnerIpv4LengthFails()
        {
            var bytes = Ipv4(); bytes[24] = 0; bytes[25] = 21;
            Assert.False(GeneveDatagramInspector.TryInspect(bytes, 6081, true, out _));
        }

        [Fact] public void OversizedDatagramFails()
            => Assert.False(GeneveDatagramInspector.TryInspect(new byte[65536], 6081, true, out _));

        [Fact] public void ReorderedOrRepeatedDatagramsAreStateless()
        {
            var first = Ipv4(1); var second = Ipv4(2);
            Assert.True(GeneveDatagramInspector.TryInspect(second, 6081, true, out var b));
            Assert.True(GeneveDatagramInspector.TryInspect(first, 6081, true, out var a));
            Assert.True(GeneveDatagramInspector.TryInspect(second, 6081, true, out var again));
            Assert.Equal(b, again);
            Assert.NotEqual(a.Vni, b.Vni);
        }

        [Fact] public void ConcurrentInspectionIsDeterministic()
        {
            var bytes = Ipv4();
            Parallel.For(0, 32, index =>
                Assert.True(GeneveDatagramInspector.TryInspect(bytes, 6081, true, out _)));
        }

        [Fact] public void SensitiveInnerBytesAreNotInObservation()
        {
            var bytes = Ipv4(); bytes[8] = 0xee; bytes[9] = 0xdd;
            Assert.True(GeneveDatagramInspector.TryInspect(bytes, 6081, true, out var result));
            Assert.DoesNotContain("238", result.ToString());
            Assert.DoesNotContain("221", result.ToString());
        }
    }
}
