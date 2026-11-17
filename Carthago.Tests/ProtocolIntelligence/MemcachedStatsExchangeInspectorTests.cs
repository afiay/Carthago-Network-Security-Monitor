// SPDX-License-Identifier: MIT
using System;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public class MemcachedStatsExchangeInspectorTests
    {
        private static readonly byte[] Request = Encoding.ASCII.GetBytes("stats\r\n");
        private static readonly byte[] Response = Encoding.ASCII.GetBytes("STAT pid 123\r\nSTAT uptime 50\r\nEND\r\n");

        [Fact]
        public void CompleteExchangeReturnsOnlyRedactedStatCount()
        {
            Assert.True(MemcachedStatsExchangeInspector.IsCompleteStatsExchange(
                Request, Response, true, true, true, out int count));
            Assert.Equal(2, count);
        }

        [Theory]
        [InlineData(false, true, true)]
        [InlineData(true, false, true)]
        [InlineData(true, true, false)]
        public void UntrustedCaptureOrFlowBindingFailsClosed(bool complete, bool plaintext, bool sameFlow)
        {
            Assert.False(MemcachedStatsExchangeInspector.IsCompleteStatsExchange(
                Request, Response, complete, plaintext, sameFlow, out _));
        }

        [Theory]
        [InlineData("STAT pid 123\r\n")]
        [InlineData("ERROR\r\n")]
        [InlineData("STAT pid 123\r\nEND\r\nEXTRA\r\n")]
        [InlineData("STAT pid\r\nEND\r\n")]
        [InlineData("END\r\n")]
        public void TruncatedMalformedOrUnsuccessfulResponsesAreRejected(string response)
        {
            Assert.False(MemcachedStatsExchangeInspector.IsCompleteStatsExchange(
                Request, Encoding.ASCII.GetBytes(response), true, true, true, out _));
        }

        [Fact]
        public void DifferentCommandCannotBePresentedAsStats()
        {
            Assert.False(MemcachedStatsExchangeInspector.IsCompleteStatsExchange(
                Encoding.ASCII.GetBytes("stats slabs\r\n"), Response, true, true, true, out _));
        }
    }
}
