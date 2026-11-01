// SPDX-License-Identifier: MIT
// Synthetic legacy HICP UDP/3250 requests; no real devices or credentials.
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED, 0 EXECUTED.
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class HicpConfigurationAttemptInspectorTests
    {
        private const string Prefix = "Configure: 00-30-11-00-BA-CA; ";

        private static byte[] Packet(string fields) =>
            Encoding.ASCII.GetBytes(Prefix + fields);

        private static bool Inspect(ReadOnlySpan<byte> bytes,
            out HicpConfigurationAttemptObservation observation) =>
            HicpConfigurationAttemptInspector.TryInspect(
                bytes, true, true, true, true, true, true, out observation);

        [Theory]
        [InlineData("IP = 192.0.2.10")]
        [InlineData("SN = 255.255.255.0")]
        [InlineData("GW = 192.0.2.1")]
        [InlineData("DHCP = ON")]
        public void RecognizesConservativeNetworkSettingShapes(string field)
        {
            Assert.True(Inspect(Packet(field), out var result));
            Assert.True(result.HasNetworkSettingFieldUnverified);
            Assert.False(result.HasNewPasswordFieldUnverified);
            Assert.Equal(1, result.ParsedFieldCount);
        }

        [Fact]
        public void MultipleFieldsRemainOnlyAnUnverifiedRequest()
        {
            Assert.True(Inspect(Packet("IP = 192.0.2.10; SN = 255.255.255.0; DHCP = OFF"),
                out var result));
            Assert.Equal(3, result.ParsedFieldCount);
            Assert.True(result.HasNetworkSettingFieldUnverified);
        }

        [Fact]
        public void PasswordChangeFieldIsFlaggedWithoutReadingItsValue()
        {
            Assert.True(Inspect(Packet("New password = synthetic-secret"), out var result));
            Assert.True(result.HasNewPasswordFieldUnverified);
            Assert.False(result.HasNetworkSettingFieldUnverified);
        }

        [Fact]
        public void DiscoveryIsNotMistakenForAConfigurationAttempt()
        {
            Assert.False(Inspect(Encoding.ASCII.GetBytes("Module scan"), out _));
            Assert.False(Inspect(Encoding.ASCII.GetBytes("Module scan response"), out _));
        }

        [Fact]
        public void SecureHicpAndOtherUdpTrafficFailClosed()
        {
            Assert.False(Inspect(Encoding.ASCII.GetBytes("SHICP"), out _));
            Assert.False(Inspect(Encoding.ASCII.GetBytes("GET / HTTP/1.1"), out _));
            Assert.False(Inspect(Encoding.ASCII.GetBytes("Configure: 00-30-11-00-BA-CA"),
                out _));
        }

        [Fact]
        public void PrefixMustMatchExactly()
        {
            Assert.False(Inspect(Encoding.ASCII.GetBytes(
                "configure: 00-30-11-00-BA-CA; IP = 192.0.2.10"), out _));
            Assert.False(Inspect(Encoding.ASCII.GetBytes(
                "Configure 00-30-11-00-BA-CA; IP = 192.0.2.10"), out _));
        }

        [Fact]
        public void TargetMustBeSixHyphenDelimitedHexOctets()
        {
            Assert.False(Inspect(Encoding.ASCII.GetBytes(
                "Configure: 00:30:11:00:BA:CA; IP = 192.0.2.10"), out _));
            Assert.False(Inspect(Encoding.ASCII.GetBytes(
                "Configure: 00-30-11-00-BZ-CA; IP = 192.0.2.10"), out _));
        }

        [Fact]
        public void MissingTargetSeparatorFailsClosed()
        {
            Assert.False(Inspect(Encoding.ASCII.GetBytes(
                "Configure: 00-30-11-00-BA-CA IP = 192.0.2.10"), out _));
        }

        [Fact]
        public void MissingEqualsOrValueFailsClosed()
        {
            Assert.False(Inspect(Packet("IP 192.0.2.10"), out _));
            Assert.False(Inspect(Packet("IP = "), out _));
            Assert.False(Inspect(Packet(" = 192.0.2.10"), out _));
        }

        [Fact]
        public void BinaryAndControlBytesAreNotParsedAsText()
        {
            var nul = Packet("IP = 192.0.2.10");
            nul[^1] = 0;
            Assert.False(Inspect(nul, out _));
            Assert.False(Inspect(Packet("IP = 192.0.2.10\r\n"), out _));
        }

        [Fact]
        public void TruncatedAndCoalescedDatagramsFailClosed()
        {
            var packet = Packet("IP = 192.0.2.10");
            Assert.False(Inspect(packet.AsSpan(0, Prefix.Length - 1), out _));
            Assert.False(Inspect(packet.Concat(packet).ToArray(), out _));
        }

        [Fact]
        public void OversizedDatagramFailsClosed()
        {
            Assert.False(Inspect(new byte[1201], out _));
        }

        [Fact]
        public void FieldLengthIsBounded()
        {
            Assert.False(Inspect(Packet("IP = " + new string('1', 129)), out _));
        }

        [Fact]
        public void FieldCountIsBounded()
        {
            Assert.False(Inspect(Packet(string.Join("; ",
                Enumerable.Repeat("IP = 192.0.2.10", 25))), out _));
        }

        [Fact]
        public void EmptyOrUnknownOnlyFieldsAreNotProof()
        {
            Assert.False(Inspect(Packet(""), out _));
            Assert.False(Inspect(Packet("Mystery = 1"), out _));
        }

        [Theory]
        [InlineData(false, true, true, true, true, true)]
        [InlineData(true, false, true, true, true, true)]
        [InlineData(true, true, false, true, true, true)]
        [InlineData(true, true, true, false, true, true)]
        [InlineData(true, true, true, true, false, true)]
        [InlineData(true, true, true, true, true, false)]
        public void AllSixProvenanceAndBoundaryAttestationsAreRequired(
            bool complete, bool unfragmented, bool endpoint, bool plaintext,
            bool provenance, bool direction)
        {
            Assert.False(HicpConfigurationAttemptInspector.TryInspect(
                Packet("IP = 192.0.2.10"), complete, unfragmented, endpoint,
                plaintext, provenance, direction, out _));
        }

        [Fact]
        public void ObservationDoesNotRetainSensitiveValuesOrTargetMac()
        {
            Assert.True(Inspect(Packet("New password = secret-one"), out var first));
            Assert.True(Inspect(Packet("New password = secret-two"), out var second));
            Assert.Equal(first, second);
            Assert.DoesNotContain(typeof(HicpConfigurationAttemptObservation).GetProperties(),
                property => property.PropertyType == typeof(string) ||
                            property.PropertyType == typeof(byte[]));
        }

        [Fact]
        public void DuplicateAndReorderedRequestsAreStateless()
        {
            var a = Packet("IP = 192.0.2.10");
            var b = Packet("DHCP = OFF");
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(b, out _));
            Assert.True(Inspect(a, out var again));
            Assert.Equal(first, again);
        }

        [Fact]
        public async Task ConcurrentInspectionsRemainDeterministic()
        {
            var packet = Packet("IP = 192.0.2.10");
            var results = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ =>
                Task.Run(() =>
                {
                    Assert.True(Inspect(packet, out var observation));
                    return observation;
                })));
            Assert.All(results, value => Assert.Equal(results[0], value));
        }

        [Fact]
        public void InvalidInputReturnsDefaultObservation()
        {
            Assert.False(Inspect(Packet("Mystery = 1"), out var observation));
            Assert.Equal(default(HicpConfigurationAttemptObservation), observation);
        }
    }
}
