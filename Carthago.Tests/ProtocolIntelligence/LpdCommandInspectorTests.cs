// SPDX-License-Identifier: MIT
using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 1179 top-level first-command envelopes, not captured jobs.
    public sealed class LpdCommandInspectorTests
    {
        private static byte[] Command(byte code = 1, string body = "office")
        {
            byte[] tail = Encoding.ASCII.GetBytes(body + "\n");
            var bytes = new byte[tail.Length + 1];
            bytes[0] = code;
            tail.CopyTo(bytes, 1);
            return bytes;
        }

        private static bool Inspect(byte[] bytes, out LpdCommandObservation observation,
            bool complete = true, ushort sourcePort = 730, ushort destinationPort = 515)
            => LpdCommandInspector.TryInspect(bytes, sourcePort, destinationPort,
                complete, out observation);

        // 1. Valid positives: all five top-level command kinds.
        [Theory]
        [InlineData((byte)1, LpdCommandKind.PrintWaiting)]
        [InlineData((byte)2, LpdCommandKind.ReceiveJob)]
        [InlineData((byte)3, LpdCommandKind.QueueShort)]
        [InlineData((byte)4, LpdCommandKind.QueueLong)]
        [InlineData((byte)5, LpdCommandKind.RemoveJobs)]
        public void RecognizesFiveTopLevelCommands(byte code, LpdCommandKind expected)
        {
            string body = code == 5 ? "office operator" : "office";
            Assert.True(Inspect(Command(code, body), out var found));
            Assert.Equal(expected, found.CommandKind);
            Assert.Equal(6, found.QueueNameLength);
        }

        [Fact]
        public void QueueQueriesAllowBoundedFiltersWithoutRetainingThem()
        {
            Assert.True(Inspect(Command(3, "office user1 123"), out var found));
            Assert.Equal(2, found.ArgumentCount);
        }

        [Fact]
        public void RemoveJobsRequiresAnAgentOperand()
        {
            Assert.False(Inspect(Command(5), out _));
            Assert.True(Inspect(Command(5, "office admin 123"), out var found));
            Assert.Equal(2, found.ArgumentCount);
        }

        // 2. Benign negatives, cross-protocol discrimination, direction.
        [Fact]
        public void ReceiveJobRejectsUnexpectedOperands()
            => Assert.False(Inspect(Command(2, "office user"), out _));

        [Fact]
        public void OtherPrinterPortIsNotAnLpdCommand()
            => Assert.False(Inspect(Command(), out _, destinationPort: 631));

        [Fact]
        public void ReversedClientServerPortsFailClosed()
            => Assert.False(Inspect(Command(), out _, sourcePort: 515, destinationPort: 730));

        [Fact]
        public void HttpAndRfbLookalikesFailClosed()
        {
            Assert.False(Inspect(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n"), out _));
            Assert.False(Inspect(Encoding.ASCII.GetBytes("RFB 003.008\n"), out _));
        }

        // 3. Malformed, truncated, ambiguous, and bounded framing.
        [Fact]
        public void MissingNewlineFailsClosed()
            => Assert.False(Inspect(new byte[] { 1, (byte)'q' }, out _));

        [Fact]
        public void EmbeddedNewlineAndCarriageReturnFailClosed()
        {
            Assert.False(Inspect(Command(3, "office\nadmin"), out _));
            Assert.False(Inspect(Command(3, "office\radmin"), out _));
        }

        [Fact]
        public void InvalidQueueCharactersFailClosed()
            => Assert.False(Inspect(Command(1, "../office/secret"), out _));

        [Fact]
        public void EmptyOrOversizedQueueFailsClosed()
        {
            Assert.False(Inspect(Command(1, ""), out _));
            Assert.False(Inspect(Command(1, new string('a', 65)), out _));
        }

        [Fact]
        public void RepeatedOrTrailingSpacesFailClosed()
        {
            Assert.False(Inspect(Command(3, "office  user"), out _));
            Assert.False(Inspect(Command(3, "office user "), out _));
        }

        [Fact]
        public void TooManyArgumentsFailClosed()
            => Assert.False(Inspect(Command(4, "office a b c d e f g h i"), out _));

        [Fact]
        public void OverlongCommandFailsClosed()
            => Assert.False(Inspect(Command(3, "office " + new string('x', 250)), out _));

        // 4. Statelessness, reordering and concurrency.
        [Fact]
        public void ReorderedCommandsCannotManufactureJobState()
        {
            Assert.True(Inspect(Command(5, "office admin"), out var remove));
            Assert.True(Inspect(Command(2), out var receive));
            Assert.Equal(LpdCommandKind.RemoveJobs, remove.CommandKind);
            Assert.Equal(LpdCommandKind.ReceiveJob, receive.CommandKind);
        }

        [Fact]
        public void ParallelIndependentInspectionsAreDeterministic()
        {
            byte[] bytes = Command(3, "office operator");
            int count = 0;
            Parallel.For(0, 64, _ =>
            {
                if (Inspect(bytes, out var found) && found.CommandKind == LpdCommandKind.QueueShort)
                    Interlocked.Increment(ref count);
            });
            Assert.Equal(64, count);
        }

        // 5. Provenance, privacy, fail-closed, no outcome claims.
        [Fact]
        public void UnattestedFirstCommandFailsClosed()
            => Assert.False(Inspect(Command(), out _, complete: false));

        [Fact]
        public void QueueAndAgentAreNeverReturned()
        {
            Assert.True(Inspect(Command(5, "privatequeue sensitiveagent"), out var found));
            Assert.DoesNotContain("privatequeue", found.ToString());
            Assert.DoesNotContain("sensitiveagent", found.ToString());
            Assert.Equal(4, typeof(LpdCommandObservation).GetProperties().Length);
        }

        [Fact]
        public void InvalidInputReturnsDefaultObservation()
        {
            Assert.False(Inspect(Command(5), out var found));
            Assert.Equal(default(LpdCommandObservation), found);
        }
    }
}
