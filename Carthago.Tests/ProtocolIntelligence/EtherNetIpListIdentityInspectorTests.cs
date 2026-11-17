// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class EtherNetIpListIdentityInspectorTests
    {
        private static byte[] Request()
        {
            var bytes = new byte[24];
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0, 2), 0x0063);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(12, 8), 0x12345678UL);
            return bytes;
        }

        [Fact]
        public void CompleteListIdentityRequestIsRecognizedWithoutSuccessInference()
        {
            Assert.True(EtherNetIpListIdentityInspector.TryInspectRequest(Request(), true, out var result));
            Assert.Equal(0x12345678UL, result.SenderContext);
        }

        [Fact]
        public void PartialAndCoalescedMessagesAreRejected()
        {
            var request = Request();
            Assert.False(EtherNetIpListIdentityInspector.TryInspectRequest(request, false, out _));
            Assert.False(EtherNetIpListIdentityInspector.TryInspectRequest(request.AsSpan(0, 23), true, out _));
            Assert.False(EtherNetIpListIdentityInspector.TryInspectRequest(new byte[48], true, out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(2)]
        [InlineData(4)]
        [InlineData(8)]
        [InlineData(20)]
        public void InvalidHeaderFieldsFailClosed(int offset)
        {
            var request = Request();
            request[offset] = 1;
            Assert.False(EtherNetIpListIdentityInspector.TryInspectRequest(request, true, out _));
        }
    }
}
