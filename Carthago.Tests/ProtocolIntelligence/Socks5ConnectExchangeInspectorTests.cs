// SPDX-License-Identifier: MIT
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class Socks5ConnectExchangeInspectorTests
    {
        private static readonly byte[] Greeting = { 5, 1, 0 };
        private static readonly byte[] Method = { 5, 0 };
        private static readonly byte[] Request = { 5, 1, 0, 1, 192, 0, 2, 1, 1, 187 };
        private static readonly byte[] Success = { 5, 0, 0, 1, 127, 0, 0, 1, 0, 80 };

        [Fact]
        public void CompleteExchangeReportsOnlySocksConnectOutcome()
        {
            Assert.True(Socks5ConnectExchangeInspector.TryInspect(Greeting, Method, Request, Success, true, out var result));
            Assert.True(result.ServerAccepted);
            Assert.Equal((byte)1, result.AddressType);
        }

        [Fact]
        public void RejectionIsNotSuccessfulConnect()
        {
            var refused = (byte[])Success.Clone();
            refused[1] = 5;
            Assert.True(Socks5ConnectExchangeInspector.TryInspect(Greeting, Method, Request, refused, true, out var result));
            Assert.False(result.ServerAccepted);
        }

        [Fact]
        public void IncompleteOrUntrustedExchangeFailsClosed()
        {
            Assert.False(Socks5ConnectExchangeInspector.TryInspect(Greeting, Method, Request, Success, false, out _));
            Assert.False(Socks5ConnectExchangeInspector.TryInspect(Greeting, Method, Request.AsSpan(0, 9), Success, true, out _));
            Assert.False(Socks5ConnectExchangeInspector.TryInspect(Greeting, Method, Request, Success.AsSpan(0, 9), true, out _));
        }

        [Fact]
        public void InvalidMethodsCommandsAndAddressFramesFailClosed()
        {
            Assert.False(Socks5ConnectExchangeInspector.TryInspect(new byte[] { 5, 1, 2 }, Method, Request, Success, true, out _));
            Assert.False(Socks5ConnectExchangeInspector.TryInspect(Greeting, new byte[] { 5, 2 }, Request, Success, true, out _));
            var bind = (byte[])Request.Clone();
            bind[1] = 2;
            Assert.False(Socks5ConnectExchangeInspector.TryInspect(Greeting, Method, bind, Success, true, out _));
            var invalid = (byte[])Request.Clone();
            invalid[3] = 3;
            Assert.False(Socks5ConnectExchangeInspector.TryInspect(Greeting, Method, invalid, Success, true, out _));
        }
    }
}
