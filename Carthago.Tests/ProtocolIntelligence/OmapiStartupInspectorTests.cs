// SPDX-License-Identifier: MIT
// Synthetic ISC OMAPI 1.00 startup prefixes, from ISC doc/api+protocol.
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class OmapiStartupInspectorTests
    {
        private static byte[] Startup(uint version = 100, uint headerBytes = 56,
            int totalBytes = 8)
        {
            var bytes = new byte[totalBytes];
            if (totalBytes >= 8)
            {
                BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(0, 4), version);
                BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(4, 4), headerBytes);
            }
            return bytes;
        }

        private static bool Inspect(ReadOnlySpan<byte> prefix,
            out OmapiStartupObservation observation)
            => OmapiStartupInspector.TryInspect(
                prefix, true, true, true, true, out observation);

        [Theory]
        [InlineData(56u)]
        [InlineData(64u)]
        [InlineData(4096u)]
        public void RecognizesVersion100WithBoundedAdvertisedHeader(uint headerBytes)
        {
            Assert.True(Inspect(Startup(headerBytes: headerBytes), out var result));
            Assert.Equal(100, result.VersionHundredths);
            Assert.Equal((int)headerBytes, result.AdvertisedFixedHeaderBytes);
        }

        [Fact]
        public void AValidPrefixMayBeFollowedByOpaqueMessageBytes()
        {
            Assert.True(Inspect(Startup(totalBytes: 64), out var result));
            Assert.Equal(56, result.AdvertisedFixedHeaderBytes);
        }

        [Fact]
        public void CommonNonOmapiProtocolsDoNotMatch()
        {
            Assert.False(Inspect("GET / HTTP/1.1"u8, out _));
            Assert.False(Inspect("SSH-2.0-client"u8, out _));
            Assert.False(Inspect(new byte[] { 0x16, 0x03, 0x03, 0, 5, 1, 2, 3 }, out _));
        }

        [Theory]
        [InlineData(0u)]
        [InlineData(99u)]
        [InlineData(101u)]
        public void UnknownVersionFailsClosed(uint version)
            => Assert.False(Inspect(Startup(version: version), out _));

        [Fact]
        public void EveryTruncatedStartupPrefixFailsClosed()
        {
            var complete = Startup();
            for (int length = 0; length < 8; length++)
                Assert.False(Inspect(complete.AsSpan(0, length), out _));
        }

        [Theory]
        [InlineData(0u)]
        [InlineData(55u)]
        [InlineData(4097u)]
        [InlineData(uint.MaxValue)]
        public void UnsupportedHeaderLengthsFailClosed(uint headerBytes)
            => Assert.False(Inspect(Startup(headerBytes: headerBytes), out _));

        [Fact]
        public void MaximumInputPrefixIsBounded()
        {
            Assert.True(Inspect(Startup(totalBytes: 4096), out _));
            Assert.False(Inspect(Startup(totalBytes: 4097), out _));
        }

        [Fact]
        public void ByteOrderMustBeNetworkOrder()
        {
            var bytes = Startup();
            Array.Reverse(bytes, 0, 4);
            Assert.False(Inspect(bytes, out _));
        }

        [Theory]
        [InlineData(false, true, true, true)]
        [InlineData(true, false, true, true)]
        [InlineData(true, true, false, true)]
        [InlineData(true, true, true, false)]
        public void AllFourIndependentProducerAttestationsAreRequired(
            bool streamStart, bool endpoint, bool plaintext, bool provenance)
        {
            Assert.False(OmapiStartupInspector.TryInspect(Startup(),
                streamStart, endpoint, plaintext, provenance, out var result));
            Assert.Equal(default(OmapiStartupObservation), result);
        }

        [Fact]
        public void InvalidInputDoesNotLeakPreviousOutput()
        {
            Assert.True(Inspect(Startup(), out _));
            Assert.False(Inspect(Startup(version: 101), out var rejected));
            Assert.Equal(default(OmapiStartupObservation), rejected);
        }

        [Fact]
        public void PayloadAndAuthenticationAreNeverInterpreted()
        {
            var a = Startup(totalBytes: 64);
            var b = Startup(totalBytes: 64);
            a[20] = 1; b[20] = 255;
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
            Assert.DoesNotContain(typeof(OmapiStartupObservation).GetProperties(),
                property => property.PropertyType == typeof(string) ||
                            property.PropertyType == typeof(byte[]));
        }

        [Fact]
        public void DuplicateAndOutOfOrderObservationsAreStateless()
        {
            var a = Startup(headerBytes: 56);
            var b = Startup(headerBytes: 64);
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(b, out var second));
            Assert.True(Inspect(a, out var repeated));
            Assert.Equal(first, repeated);
            Assert.NotEqual(first, second);
        }

        [Fact]
        public async Task ConcurrentInspectionsRemainDeterministic()
        {
            var prefix = Startup();
            var observations = await Task.WhenAll(
                Enumerable.Range(0, 32).Select(_ => Task.Run(() =>
                {
                    Assert.True(Inspect(prefix, out var observation));
                    return observation;
                })));
            Assert.All(observations, value => Assert.Equal(observations[0], value));
        }
    }
}
