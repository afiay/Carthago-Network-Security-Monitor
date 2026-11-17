// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public class PostgreSqlStartupInspectorTests
    {
        private static byte[] Startup(string pairs)
        {
            byte[] body = Encoding.ASCII.GetBytes(pairs);
            byte[] packet = new byte[8 + body.Length];
            BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(0, 4), packet.Length);
            BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(4, 4), 196608);
            body.CopyTo(packet, 8);
            return packet;
        }

        [Fact]
        public void CompletePlaintextStartupIsOnlyProtocolEvidence()
        {
            var packet = Startup("user\0alice\0database\0app\0\0");
            Assert.True(PostgreSqlStartupInspector.IsCompleteStartup(packet, true, true));
            Assert.False(PostgreSqlStartupInspector.IsCompleteStartup(packet, false, true));
            Assert.False(PostgreSqlStartupInspector.IsCompleteStartup(packet, true, false));
        }

        [Fact]
        public void RejectsMissingUserAndDuplicateUser()
        {
            Assert.False(PostgreSqlStartupInspector.IsCompleteStartup(Startup("database\0app\0\0"), true, true));
            Assert.False(PostgreSqlStartupInspector.IsCompleteStartup(Startup("user\0a\0user\0b\0\0"), true, true));
        }

        [Fact]
        public void RejectsTruncatedAndContradictoryFraming()
        {
            var packet = Startup("user\0alice\0\0");
            Assert.False(PostgreSqlStartupInspector.IsCompleteStartup(packet.AsSpan(0, packet.Length - 1), true, true));
            packet[7] = 1;
            Assert.False(PostgreSqlStartupInspector.IsCompleteStartup(packet, true, true));
        }

        [Fact]
        public void RejectsMalformedAndControlValue()
        {
            Assert.False(PostgreSqlStartupInspector.IsCompleteStartup(Startup("user\0\0"), true, true));
            Assert.False(PostgreSqlStartupInspector.IsCompleteStartup(Startup("user\0a\nb\0\0"), true, true));
        }
    }
}
