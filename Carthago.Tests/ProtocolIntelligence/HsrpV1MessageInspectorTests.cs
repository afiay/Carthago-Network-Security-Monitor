// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 2281 HSRP version-0 messages. Authentication bytes are fake.
    public sealed class HsrpV1MessageInspectorTests
    {
        private static byte[] Hello(byte state = 16, byte group = 7)
        {
            var bytes = new byte[20];
            bytes[0] = 0; bytes[1] = 0; bytes[2] = state;
            bytes[3] = 3; bytes[4] = 10; bytes[5] = 100; bytes[6] = group;
            return bytes;
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(4)]
        [InlineData(8)]
        [InlineData(16)]
        public void Rfc2281StatesRecognized(byte state)
        {
            Assert.True(HsrpV1MessageInspector.TryInspect(Hello(state), 1985, true, true, out var found));
            Assert.Equal(state, found.State);
            Assert.Equal((byte)7, found.Group);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        public void CoupAndResignShapesRecognized(byte op)
        {
            var bytes = Hello(); bytes[1] = op;
            Assert.True(HsrpV1MessageInspector.TryInspect(bytes, 1985, true, true, out var found));
            Assert.Equal(op, found.OpCode);
        }

        [Fact] public void WrongPortFails()
            => Assert.False(HsrpV1MessageInspector.TryInspect(Hello(), 1986, true, true, out _));

        [Fact] public void UnattestedUdpBoundaryFails()
            => Assert.False(HsrpV1MessageInspector.TryInspect(Hello(), 1985, false, true, out _));

        [Fact] public void UnattestedTtlAndMulticastFails()
            => Assert.False(HsrpV1MessageInspector.TryInspect(Hello(), 1985, true, false, out _));

        [Fact] public void HsrpV2IsNotMisclassifiedAsV1()
        {
            var bytes = Hello(); bytes[0] = 2;
            Assert.False(HsrpV1MessageInspector.TryInspect(bytes, 1985, true, true, out _));
        }

        [Fact] public void InvalidStateFails()
        {
            var bytes = Hello(); bytes[2] = 3;
            Assert.False(HsrpV1MessageInspector.TryInspect(bytes, 1985, true, true, out _));
        }

        [Fact] public void InvalidOpCodeFails()
        {
            var bytes = Hello(); bytes[1] = 3;
            Assert.False(HsrpV1MessageInspector.TryInspect(bytes, 1985, true, true, out _));
        }

        [Fact] public void ReservedFieldFails()
        {
            var bytes = Hello(); bytes[7] = 1;
            Assert.False(HsrpV1MessageInspector.TryInspect(bytes, 1985, true, true, out _));
        }

        [Fact] public void HoldtimeMustExceedHellotime()
        {
            var bytes = Hello(); bytes[4] = 3;
            Assert.False(HsrpV1MessageInspector.TryInspect(bytes, 1985, true, true, out _));
        }

        [Fact] public void TruncatedMessageFails()
            => Assert.False(HsrpV1MessageInspector.TryInspect(Hello().AsSpan(0, 19), 1985, true, true, out _));

        [Fact] public void OverlongMessageFails()
            => Assert.False(HsrpV1MessageInspector.TryInspect(new byte[21], 1985, true, true, out _));

        [Fact] public void ReorderedMessagesDoNotClaimAnElection()
        {
            var a = Hello(16, 1); var b = Hello(8, 1);
            Assert.True(HsrpV1MessageInspector.TryInspect(b, 1985, true, true, out var standby));
            Assert.True(HsrpV1MessageInspector.TryInspect(a, 1985, true, true, out var active));
            Assert.Equal((byte)8, standby.State);
            Assert.Equal((byte)16, active.State);
        }

        [Fact] public void StatelessConcurrencyIsDeterministic()
        {
            var bytes = Hello();
            Parallel.For(0, 32, index =>
                Assert.True(HsrpV1MessageInspector.TryInspect(bytes, 1985, true, true, out _)));
        }

        [Fact] public void AuthenticationAndVirtualIpAreNeverExposed()
        {
            var bytes = Hello();
            bytes[8] = 0xfa; bytes[15] = 0xfb;
            bytes[16] = 203; bytes[17] = 0; bytes[18] = 113; bytes[19] = 99;
            Assert.True(HsrpV1MessageInspector.TryInspect(bytes, 1985, true, true, out var result));
            Assert.DoesNotContain("203", result.ToString());
            Assert.DoesNotContain("250", result.ToString());
            Assert.DoesNotContain("251", result.ToString());
        }
    }
}
