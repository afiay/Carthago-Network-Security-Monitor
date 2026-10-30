// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic OPC UA Part 6 UACP connection messages, never captured credentials.
    public sealed class OpcUaConnectionInspectorTests
    {
        private static byte[] Message(string type, int bodyBytes)
        {
            var bytes = new byte[8 + bodyBytes];
            bytes[0] = (byte)type[0]; bytes[1] = (byte)type[1]; bytes[2] = (byte)type[2];
            bytes[3] = (byte)'F';
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4, 4), (uint)bytes.Length);
            if (type is "HEL" or "ACK")
            {
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12, 4), 8192);
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(16, 4), 8192);
            }
            return bytes;
        }

        [Fact] public void ValidHelloWithEmptyEndpointRecognized()
        {
            var bytes = Message("HEL", 24);
            Assert.True(OpcUaConnectionInspector.TryInspect(bytes, true, out var found));
            Assert.Equal(OpcUaConnectionKind.Hello, found.Kind);
            Assert.Equal(32, found.MessageLength);
        }

        [Fact] public void ValidAcknowledgeRecognized()
        {
            Assert.True(OpcUaConnectionInspector.TryInspect(Message("ACK", 20), true, out var found));
            Assert.Equal(OpcUaConnectionKind.Acknowledge, found.Kind);
        }

        [Fact] public void ValidErrorWithNullReasonRecognized()
        {
            var bytes = Message("ERR", 8);
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12, 4), -1);
            Assert.True(OpcUaConnectionInspector.TryInspect(bytes, true, out var found));
            Assert.Equal(OpcUaConnectionKind.Error, found.Kind);
        }

        [Fact] public void UnattestedBoundaryRejected()
        {
            Assert.False(OpcUaConnectionInspector.TryInspect(Message("ACK", 20), false, out _));
        }

        [Theory]
        [InlineData("OPN")] [InlineData("MSG")] [InlineData("CLO")] [InlineData("RHE")]
        public void SecureOrUnsupportedMessagesNotDecoded(string type)
        {
            Assert.False(OpcUaConnectionInspector.TryInspect(Message(type, 20), true, out _));
        }

        [Fact] public void DeclaredLengthMismatchRejected()
        {
            var bytes = Message("ACK", 20); bytes[4]--;
            Assert.False(OpcUaConnectionInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void BadChunkTypeRejected()
        {
            var bytes = Message("ACK", 20); bytes[3] = (byte)'C';
            Assert.False(OpcUaConnectionInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void TruncatedHelloRejected()
        {
            var bytes = Message("HEL", 24);
            Assert.False(OpcUaConnectionInspector.TryInspect(bytes.AsSpan(0, 31), true, out _));
        }

        [Fact] public void ForgedEndpointLengthRejected()
        {
            var bytes = Message("HEL", 24);
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(28, 4), 5000);
            Assert.False(OpcUaConnectionInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void TinyNegotiatedBuffersRejected()
        {
            var bytes = Message("ACK", 20); bytes[12] = 0; bytes[13] = 0;
            Assert.False(OpcUaConnectionInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void OversizeRejected()
        {
            Assert.False(OpcUaConnectionInspector.TryInspect(new byte[8193], true, out _));
        }

        [Fact] public void RepeatedMessageDeterministicWithoutSessionInference()
        {
            var bytes = Message("ACK", 20);
            Assert.True(OpcUaConnectionInspector.TryInspect(bytes, true, out var first));
            Assert.True(OpcUaConnectionInspector.TryInspect(bytes, true, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public void EndpointTextIsNotRetained()
        {
            var bytes = Message("HEL", 30);
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(28, 4), 6);
            bytes[32] = (byte)'s'; bytes[33] = (byte)'e'; bytes[34] = (byte)'c';
            bytes[35] = (byte)'r'; bytes[36] = (byte)'e'; bytes[37] = (byte)'t';
            Assert.True(OpcUaConnectionInspector.TryInspect(bytes, true, out var found));
            Assert.DoesNotContain("secret", found.ToString());
        }
    }
}