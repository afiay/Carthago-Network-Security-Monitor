// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Hand-authored RESP2 framing examples, not captured traffic or executed tests.
    public sealed class Resp2CommandInspectorTests
    {
        private static byte[] Command(params string[] fields)
        {
            var bytes = new List<byte>();
            bytes.AddRange(Encoding.ASCII.GetBytes("*" + fields.Length + "\r\n"));
            foreach (string field in fields)
            {
                var payload = Encoding.UTF8.GetBytes(field);
                bytes.AddRange(Encoding.ASCII.GetBytes("$" + payload.Length + "\r\n"));
                bytes.AddRange(payload);
                bytes.Add(13);
                bytes.Add(10);
            }
            return bytes.ToArray();
        }

        [Theory]
        [InlineData("AUTH", Resp2CommandKind.Auth)]
        [InlineData("RESTORE", Resp2CommandKind.Restore)]
        [InlineData("CONFIG", Resp2CommandKind.Config)]
        public void KnownCommandNamesProduceOnlyBoundedCommandKinds(
            string name, Resp2CommandKind kind)
        {
            var bytes = Command(name, "private-secret");
            Assert.True(Resp2CommandInspector.TryInspect(bytes, true, out var found));
            Assert.Equal(kind, found.Command);
            Assert.Equal(1, found.ArgumentCount);
            Assert.Equal(bytes.Length, found.BytesConsumed);
            Assert.DoesNotContain("private-secret", found.ToString());
        }

        [Fact]
        public void CaseInsensitiveRedisCommandIsRecognizedWithoutAllocatingValues()
        {
            Assert.True(Resp2CommandInspector.TryInspect(
                Command("pInG"), true, out var found));
            Assert.Equal(Resp2CommandKind.Ping, found.Command);
            Assert.Equal(0, found.ArgumentCount);
        }

        [Fact]
        public void HttpAndUnrelatedPlaintextCannotBecomeRedisCommands()
        {
            Assert.False(Resp2CommandInspector.TryInspect(
                Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n\r\n"), true, out _));
        }

        [Fact]
        public void NoAttestedPlaintextClientBoundaryMeansNoClassification()
        {
            Assert.False(Resp2CommandInspector.TryInspect(
                Command("AUTH", "private"), false, out _));
            Assert.False(Resp2CommandInspector.TryInspect(
                new byte[] { 0x17, 3, 3, 0, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, false, out _));
        }

        [Fact]
        public void TruncatedBulkPayloadFailsClosed()
        {
            var bytes = Command("SET", "key", "value");
            Assert.False(Resp2CommandInspector.TryInspect(
                bytes.AsSpan(0, bytes.Length - 1), true, out _));
        }

        [Fact]
        public void NullBulkAndNestedAggregateAreOutsideCommandSubset()
        {
            Assert.False(Resp2CommandInspector.TryInspect(
                Encoding.ASCII.GetBytes("*1\r\n$-1\r\n"), true, out _));
            Assert.False(Resp2CommandInspector.TryInspect(
                Encoding.ASCII.GetBytes("*1\r\n*1\r\n$4\r\nPING\r\n"), true, out _));
        }

        [Fact]
        public void ForgedLengthAndWrongCrlfAreRejected()
        {
            var bytes = Command("AUTH", "private");
            var lengthMarker = Encoding.ASCII.GetBytes("$99\r\n");
            var wrong = Encoding.ASCII.GetBytes("*1\r\n").Concat(lengthMarker)
                .Concat(Encoding.ASCII.GetBytes("AUTH\r\n")).ToArray();
            Assert.False(Resp2CommandInspector.TryInspect(wrong, true, out _));
            bytes[bytes.Length - 1] = (byte)'X';
            Assert.False(Resp2CommandInspector.TryInspect(bytes, true, out _));
        }

        [Fact]
        public void NonMinimalDecimalAndNegativeArrayCountsAreRejected()
        {
            Assert.False(Resp2CommandInspector.TryInspect(
                Encoding.ASCII.GetBytes("*01\r\n$4\r\nPING\r\n"), true, out _));
            Assert.False(Resp2CommandInspector.TryInspect(
                Encoding.ASCII.GetBytes("*-1\r\n$4\r\nPING\r\n"), true, out _));
        }

        [Fact]
        public void BoundedArrayElementCountRejectsOversizedCommand()
        {
            Assert.False(Resp2CommandInspector.TryInspect(
                Command(Enumerable.Repeat("PING", 17).ToArray()), true, out _));
        }

        [Fact]
        public void OversizedBufferFailsBeforeParsing()
        {
            Assert.False(Resp2CommandInspector.TryInspect(
                new byte[8_193], true, out _));
        }

        [Fact]
        public void CoalescedCommandsOnlyReportFirstCommand()
        {
            var first = Command("GET", "key");
            var combined = first.Concat(Command("SET", "key", "value")).ToArray();
            Assert.True(Resp2CommandInspector.TryInspect(combined, true, out var found));
            Assert.Equal(Resp2CommandKind.Get, found.Command);
            Assert.Equal(first.Length, found.BytesConsumed);
        }

        [Fact]
        public void RepeatedRequestDoesNotClaimReplayOrExecution()
        {
            var bytes = Command("RESTORE", "key", "0", "opaque");
            Assert.True(Resp2CommandInspector.TryInspect(bytes, true, out var first));
            Assert.True(Resp2CommandInspector.TryInspect(bytes, true, out var repeated));
            Assert.Equal(first, repeated);
        }

        [Fact]
        public void UnrecognizedValidCommandIsNotGuessedFromPortOrShape()
        {
            Assert.False(Resp2CommandInspector.TryInspect(
                Command("SCAN", "0"), true, out _));
        }

        [Fact]
        public void ArgumentsAreNeverReflectedInObservation()
        {
            var bytes = Command("AUTH", "token-with-private-content");
            Assert.True(Resp2CommandInspector.TryInspect(bytes, true, out var found));
            Assert.DoesNotContain("token-with-private-content", found.ToString());
        }
    }
}
