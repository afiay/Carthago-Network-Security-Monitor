// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 8684 initial-SYN TCP option arrays; not live traffic.
    public sealed class MptcpCapableSynInspectorTests
    {
        private static byte[] Capable(byte flags = 0x81)
            => new byte[] { 30, 4, 0x01, flags };

        private static bool Inspect(byte[] options, out MptcpCapableSynObservation result,
            bool complete = true, bool syn = true, bool unfragmented = true,
            bool source = true)
            => MptcpCapableSynInspector.TryInspect(options, complete, syn,
                unfragmented, source, out result);

        [Fact] public void V1InitialSynRecognizesChecksumAndVersion()
        {
            Assert.True(Inspect(Capable(), out var found));
            Assert.Equal((byte)1, found.OfferedVersion);
            Assert.True(found.ChecksumRequestedUnverified);
            Assert.False(found.AdditionalSubflowsToSourceDisallowedUnverified);
        }

        [Fact] public void V1InitialSynWithoutChecksumIsStillValid()
        {
            Assert.True(Inspect(Capable(0x01), out var found));
            Assert.False(found.ChecksumRequestedUnverified);
        }

        [Fact] public void CFlagIsOnlyUnverifiedSourceAddressRestriction()
        {
            Assert.True(Inspect(Capable(0xA1), out var found));
            Assert.True(found.AdditionalSubflowsToSourceDisallowedUnverified);
        }

        [Fact] public void OtherWellFormedTcpOptionsCanPrecedeMptcp()
        {
            Assert.True(Inspect(new byte[] { 2, 4, 5, 180, 30, 4, 1, 1 }, out _));
        }

        [Fact] public void NopsAndEolPaddingAreRecognized()
        {
            Assert.True(Inspect(new byte[] { 1, 1, 30, 4, 1, 0x81, 0, 0 }, out _));
            Assert.True(Inspect(new byte[] { 30, 4, 1, 1, 0, 0, 0, 0 }, out _));
        }

        [Fact] public void OrdinaryTcpOptionsDoNotImplyMptcp()
        {
            Assert.False(Inspect(new byte[] { 2, 4, 5, 180 }, out _));
            Assert.False(Inspect(new byte[] { 1, 1, 0, 0 }, out _));
        }

        [Fact] public void UnknownValidOptionIsSkippedNotMisclassified()
        {
            Assert.True(Inspect(new byte[] { 99, 4, 1, 2, 30, 4, 1, 1 }, out _));
        }

        [Fact] public void V0AndOtherMptcpSubtypesFailClosed()
        {
            Assert.False(Inspect(new byte[] { 30, 4, 0, 1 }, out _));
            Assert.False(Inspect(new byte[] { 30, 4, 0x11, 1 }, out _));
        }

        [Fact] public void ReservedBAndCryptoFlagsFailClosed()
        {
            Assert.False(Inspect(Capable(0x41), out _));
            Assert.False(Inspect(Capable(0x03), out _));
        }

        [Fact] public void MissingHmacSha256NegotiationFailsClosed()
        {
            Assert.False(Inspect(Capable(0x80), out _));
            Assert.False(Inspect(Capable(0), out _));
        }

        [Fact] public void TruncatedAndOverlongTcpOptionsFailClosed()
        {
            Assert.False(Inspect(new byte[] { 30, 4, 1 }, out _));
            Assert.False(Inspect(new byte[44], out _));
            Assert.False(Inspect(Array.Empty<byte>(), out _));
        }

        [Fact] public void MalformedLengthsAndTruncatedNeighborsFailClosed()
        {
            Assert.False(Inspect(new byte[] { 30, 3, 1, 1 }, out _));
            Assert.False(Inspect(new byte[] { 2, 5, 0, 0 }, out _));
            Assert.False(Inspect(new byte[] { 2, 1, 0, 0 }, out _));
        }

        [Fact] public void DuplicateMptcpOptionsAreRejected()
        {
            Assert.False(Inspect(Capable().Concat(Capable()).ToArray(), out _));
        }

        [Fact] public void BytesAfterEolCannotSmuggleMptcp()
        {
            Assert.False(Inspect(new byte[] { 0, 30, 4, 1 }, out _));
            Assert.False(Inspect(new byte[] { 30, 4, 1, 1, 0, 1, 0, 0 }, out _));
        }

        [Fact] public void EachProvenanceAttestationIsMandatory()
        {
            var options = Capable();
            Assert.False(Inspect(options, out _, complete: false));
            Assert.False(Inspect(options, out _, syn: false));
            Assert.False(Inspect(options, out _, unfragmented: false));
            Assert.False(Inspect(options, out _, source: false));
        }

        [Fact] public void DuplicatesAndReorderingDoNotCreateState()
        {
            var first = Capable(0x81);
            var second = Capable(0x21);
            Assert.True(Inspect(second, out var a));
            Assert.True(Inspect(first, out _));
            Assert.True(Inspect(second, out var b));
            Assert.Equal(a, b);
        }

        [Fact] public async Task ConcurrentInspectionsAreDeterministic()
        {
            var options = Capable(0xA1);
            var results = await Task.WhenAll(Enumerable.Range(0, 24).Select(_ =>
                Task.Run(() =>
                {
                    Assert.True(Inspect(options, out var observation));
                    return observation;
                })));
            Assert.All(results, item => Assert.Equal(results[0], item));
        }

        [Fact] public void ObservationNeverRetainsRawOptionsOrKeyMaterial()
        {
            Assert.True(Inspect(Capable(0x81), out var a));
            Assert.True(Inspect(new byte[] { 1, 1, 30, 4, 1, 0x81, 0, 0 }, out var b));
            Assert.Equal(a, b);
            Assert.Equal(3, typeof(MptcpCapableSynObservation).GetProperties().Length);
        }

        [Fact] public void FailureResetsOutputToDefault()
        {
            Assert.False(Inspect(new byte[] { 30, 4, 1, 0 }, out var found));
            Assert.Equal(default(MptcpCapableSynObservation), found);
        }
    }
}
