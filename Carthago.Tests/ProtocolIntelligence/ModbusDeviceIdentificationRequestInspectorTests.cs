// SPDX-License-Identifier: MIT
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class ModbusDeviceIdentificationRequestInspectorTests
    {
        private static byte[] Valid() => new byte[] { 0x12, 0x34, 0, 0, 0, 5, 1, 0x2B, 0x0E, 1, 0 };

        [Fact]
        public void CompleteRequestParsesTransactionAndFunction()
        {
            Assert.True(ModbusDeviceIdentificationRequestInspector.TryInspect(Valid(), true, out var value));
            Assert.Equal((ushort)0x1234, value.TransactionId);
            Assert.Equal((byte)1, value.UnitId);
            Assert.Equal((byte)1, value.ReadCode);
        }

        [Fact]
        public void IncompleteEvidenceIsRejected()
        {
            Assert.False(ModbusDeviceIdentificationRequestInspector.TryInspect(Valid(), false, out _));
        }

        [Theory]
        [InlineData(2, 1)]
        [InlineData(3, 1)]
        [InlineData(5, 4)]
        [InlineData(7, 0x2A)]
        [InlineData(8, 0x0D)]
        [InlineData(9, 0)]
        [InlineData(9, 5)]
        [InlineData(10, 1)]
        public void MalformedOrUnsupportedRequestIsRejected(int index, int value)
        {
            var frame = Valid();
            frame[index] = (byte)value;
            Assert.False(ModbusDeviceIdentificationRequestInspector.TryInspect(frame, true, out _));
        }

        [Fact]
        public void SpecificObjectRequestIsAllowedWithoutClaimingSuccess()
        {
            var frame = Valid();
            frame[9] = 4;
            frame[10] = 0x80;
            Assert.True(ModbusDeviceIdentificationRequestInspector.TryInspect(frame, true, out var observation));
            Assert.Equal((byte)0x80, observation.ObjectId);
        }
    }
}
