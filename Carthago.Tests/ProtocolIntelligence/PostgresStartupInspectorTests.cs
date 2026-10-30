// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic PostgreSQL frontend startup bytes derived from the public format;
    // no network capture, credentials or external test execution.
    public sealed class PostgresStartupInspectorTests
    {
        private static byte[] Startup(params string[] keyValuePairs)
        {
            if (keyValuePairs.Length % 2 != 0)
                throw new ArgumentException("Pairs required", nameof(keyValuePairs));
            var body = new List<byte>();
            foreach (string field in keyValuePairs)
            {
                body.AddRange(Encoding.UTF8.GetBytes(field));
                body.Add(0);
            }
            body.Add(0);
            var result = new byte[8 + body.Count];
            BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(0, 4), result.Length);
            BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(4, 4), 0x00030000);
            body.CopyTo(result, 8);
            return result;
        }

        private static byte[] Special(int code)
        {
            var result = new byte[8];
            BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(0, 4), 8);
            BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(4, 4), code);
            return result;
        }

        [Fact]
        public void PlaintextV30StartupReportsPresenceWithoutValues()
        {
            var bytes = Startup("user", "private-actor", "database", "private-db");
            Assert.True(PostgresStartupInspector.TryInspect(bytes, true, out var found));
            Assert.Equal(PostgresStartupKind.StartupV30, found.Kind);
            Assert.Equal(2, found.ParameterPairs);
            Assert.True(found.HasUserParameter);
            Assert.True(found.HasDatabaseParameter);
            Assert.Equal(bytes.Length, found.BytesConsumed);
            Assert.DoesNotContain("private-actor", found.ToString());
            Assert.DoesNotContain("private-db", found.ToString());
        }

        [Theory]
        [InlineData(80877103, PostgresStartupKind.SslRequest)]
        [InlineData(80877104, PostgresStartupKind.GssEncryptionRequest)]
        public void NegotiationRequestsAreOnlyShapeObservations(
            int code, PostgresStartupKind expected)
        {
            Assert.True(PostgresStartupInspector.TryInspect(Special(code), true, out var found));
            Assert.Equal(expected, found.Kind);
            Assert.Equal(0, found.ParameterPairs);
            Assert.False(found.HasUserParameter);
        }

        [Fact]
        public void BenignHttpIsNotPostgresStartup()
        {
            Assert.False(PostgresStartupInspector.TryInspect(
                Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n\r\n"), true, out _));
        }

        [Fact]
        public void NoTrustedPlaintextBoundaryOrEncryptedBytesMeansNoClassification()
        {
            Assert.False(PostgresStartupInspector.TryInspect(
                Startup("user", "alice"), false, out _));
            Assert.False(PostgresStartupInspector.TryInspect(
                new byte[] { 0x16, 3, 3, 0, 8, 1, 2, 3, 4 }, false, out _));
        }

        [Fact]
        public void TruncatedStartupFailsClosed()
        {
            var bytes = Startup("user", "alice");
            Assert.False(PostgresStartupInspector.TryInspect(
                bytes.AsSpan(0, bytes.Length - 1), true, out _));
        }

        [Fact]
        public void ForgedOversizedAndUndersizedLengthsFailClosed()
        {
            var bytes = Startup("user", "alice");
            BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(0, 4), int.MaxValue);
            Assert.False(PostgresStartupInspector.TryInspect(bytes, true, out _));
            BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(0, 4), 7);
            Assert.False(PostgresStartupInspector.TryInspect(bytes, true, out _));
        }

        [Fact]
        public void MissingRequiredUserParameterIsRejected()
        {
            Assert.False(PostgresStartupInspector.TryInspect(
                Startup("database", "public"), true, out _));
        }

        [Fact]
        public void MissingValueTerminatorAndExtraTrailingKeyAreRejected()
        {
            var bytes = Startup("user", "alice");
            bytes[bytes.Length - 2] = (byte)'x';
            Assert.False(PostgresStartupInspector.TryInspect(bytes, true, out _));
            Assert.False(PostgresStartupInspector.TryInspect(
                Startup("user", "alice", "bad key", "value"), true, out _));
        }

        [Fact]
        public void UnsupportedProtocolV32IsNotMisreportedAsV30()
        {
            var bytes = Startup("user", "alice");
            BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(4, 4), 0x00030002);
            Assert.False(PostgresStartupInspector.TryInspect(bytes, true, out _));
        }

        [Fact]
        public void ParameterCountBoundRejectsUnboundedKeyValueLists()
        {
            var fields = new List<string> { "user", "alice" };
            for (int i = 0; i < 32; i++)
            {
                fields.Add("k" + i);
                fields.Add("v");
            }
            Assert.False(PostgresStartupInspector.TryInspect(
                Startup(fields.ToArray()), true, out _));
        }

        [Fact]
        public void OversizedInputIsRejectedBeforeParsing()
        {
            Assert.False(PostgresStartupInspector.TryInspect(
                new byte[8_193], true, out _));
        }

        [Fact]
        public void CoalescedRequestOnlyConsumesFirstCompleteMessage()
        {
            var first = Startup("user", "alice");
            var combined = first.Concat(Special(80877103)).ToArray();
            Assert.True(PostgresStartupInspector.TryInspect(combined, true, out var found));
            Assert.Equal(first.Length, found.BytesConsumed);
        }

        [Fact]
        public void RepeatedObservationDoesNotImplyReplayOrSuccessfulLogin()
        {
            var bytes = Startup("user", "alice");
            Assert.True(PostgresStartupInspector.TryInspect(bytes, true, out var first));
            Assert.True(PostgresStartupInspector.TryInspect(bytes, true, out var repeated));
            Assert.Equal(first, repeated);
        }

        [Fact]
        public void EmptyUserValueIsNotTreatedAsAuthenticatedUser()
        {
            var bytes = Startup("user", "");
            Assert.True(PostgresStartupInspector.TryInspect(bytes, true, out var found));
            Assert.True(found.HasUserParameter);
            Assert.Equal(PostgresStartupKind.StartupV30, found.Kind);
        }
    }
}
