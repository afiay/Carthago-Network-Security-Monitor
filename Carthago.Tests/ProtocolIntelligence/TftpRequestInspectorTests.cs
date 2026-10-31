// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 1350 / RFC 2347 request envelopes; never real filenames or captures.
    public sealed class TftpRequestInspectorTests
    {
        private static byte[] Request(byte opcode = 1, string filename = "router.cfg",
            string mode = "octet", params string[] options)
        {
            var bytes = new List<byte> { 0, opcode };
            AddToken(bytes, filename);
            AddToken(bytes, mode);
            foreach (string option in options)
                AddToken(bytes, option);
            return bytes.ToArray();
        }

        private static void AddToken(List<byte> bytes, string value)
        {
            bytes.AddRange(Encoding.ASCII.GetBytes(value));
            bytes.Add(0);
        }

        private static bool Inspect(byte[] bytes, out TftpRequestObservation observation,
            ushort sourcePort = 50000, ushort destinationPort = 69, bool complete = true)
            => TftpRequestInspector.TryInspect(bytes, sourcePort, destinationPort,
                complete, out observation);

        // 1. Valid initial-request classification and bounded extension framing.
        [Theory]
        [InlineData((byte)1, TftpRequestKind.Read)]
        [InlineData((byte)2, TftpRequestKind.Write)]
        public void RecognizesBothInitialRequestDirections(byte opcode, TftpRequestKind kind)
        {
            var request = Request(opcode);
            Assert.True(Inspect(request, out var observation));
            Assert.Equal(kind, observation.RequestKind);
            Assert.Equal(TftpTransferMode.Octet, observation.Mode);
            Assert.Equal(request.Length, observation.DatagramLength);
        }

        [Theory]
        [InlineData("NETASCII", TftpTransferMode.Netascii)]
        [InlineData("Octet", TftpTransferMode.Octet)]
        [InlineData("MAIL", TftpTransferMode.Mail)]
        public void ModesAreAsciiCaseInsensitive(string mode, TftpTransferMode expected)
        {
            Assert.True(Inspect(Request(mode: mode), out var observation));
            Assert.Equal(expected, observation.Mode);
        }

        [Fact]
        public void ExtensionOptionsAreCountedWithoutRetainingValues()
        {
            Assert.True(Inspect(Request(options: new[] { "blksize", "1428", "tsize", "0" }),
                out var observation));
            Assert.Equal(2, observation.OptionCount);
        }

        [Fact]
        public void LegalSpacesInFilenameDoNotExposeFilename()
        {
            Assert.True(Inspect(Request(filename: "backup config"), out var observation));
            Assert.Equal(0, observation.OptionCount);
        }

        // 2. Legitimate negatives, port boundaries and cross-protocol discrimination.
        [Fact]
        public void OtherUdpServicePortIsNotTftpRequest()
            => Assert.False(Inspect(Request(), out _, destinationPort: 53));

        [Fact]
        public void ServerSourcePortIsNotInitialClientRequest()
            => Assert.False(Inspect(Request(), out _, sourcePort: 69));

        [Theory]
        [InlineData((byte)3)]
        [InlineData((byte)4)]
        [InlineData((byte)5)]
        [InlineData((byte)6)]
        public void DataAckErrorAndOackAreNotInitialRequests(byte opcode)
            => Assert.False(Inspect(Request(opcode), out _));

        [Fact]
        public void DnsLikePayloadDoesNotPassTftpFraming()
            => Assert.False(Inspect(new byte[] { 0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, out _));

        // 3. Truncation, invalid strings, overlong requests and option ambiguity.
        [Fact]
        public void TruncatedAndMissingTerminatorsFailClosed()
        {
            var request = Request();
            Array.Resize(ref request, request.Length - 1);
            Assert.False(Inspect(request, out _));
            Assert.False(Inspect(new byte[] { 0, 1, (byte)'x', 0 }, out _));
        }

        [Fact]
        public void EmptyFilenameAndEmptyModeFailClosed()
        {
            Assert.False(Inspect(Request(filename: ""), out _));
            Assert.False(Inspect(Request(mode: ""), out _));
        }

        [Fact]
        public void NonPrintableFilenameAndUnsupportedModeFailClosed()
        {
            Assert.False(Inspect(Request(filename: "a\nsecret"), out _));
            Assert.False(Inspect(Request(mode: "binary"), out _));
        }

        [Fact]
        public void InvalidOpcodeHighByteFailsClosed()
        {
            var request = Request();
            request[0] = 1;
            Assert.False(Inspect(request, out _));
        }

        [Fact]
        public void OverlongFilenameAndDatagramFailClosed()
        {
            Assert.False(Inspect(Request(filename: new string('a', 256)), out _));
            Assert.False(Inspect(Request(filename: new string('a', 250),
                options: new[] { "x", new string('a', 750) }), out _));
        }

        [Fact]
        public void OddOrEmptyOptionPairFailsClosed()
        {
            Assert.False(Inspect(Request(options: new[] { "blksize" }), out _));
            Assert.False(Inspect(Request(options: new[] { "", "1428" }), out _));
            Assert.False(Inspect(Request(options: new[] { "blksize", "" }), out _));
        }

        [Fact]
        public void DuplicateOptionNamesFailCaseInsensitively()
            => Assert.False(Inspect(Request(options: new[] { "blksize", "1428", "BLKSIZE", "512" }), out _));

        [Fact]
        public void TooManyOptionsFailClosed()
        {
            var options = new List<string>();
            for (int i = 0; i < 9; i++)
            {
                options.Add("x" + i);
                options.Add("1");
            }
            Assert.False(Inspect(Request(options: options.ToArray()), out _));
        }

        [Fact]
        public void OverlongOptionNameAndValueFailClosed()
        {
            Assert.False(Inspect(Request(options: new[] { new string('x', 33), "1" }), out _));
            Assert.False(Inspect(Request(options: new[] { "blksize", new string('1', 65) }), out _));
        }

        // 4. Stateless operation across reordered requests and concurrent callers.
        [Fact]
        public void ReorderedWriteAndReadRequestsDoNotInventTransferState()
        {
            Assert.True(Inspect(Request(2), out var write));
            Assert.True(Inspect(Request(1), out var read));
            Assert.Equal(TftpRequestKind.Write, write.RequestKind);
            Assert.Equal(TftpRequestKind.Read, read.RequestKind);
        }

        [Fact]
        public void ParallelCallsAreIndependentAndDeterministic()
        {
            var valid = Request(2);
            int recognized = 0;
            Parallel.For(0, 64, _ =>
            {
                if (Inspect(valid, out var result) && result.RequestKind == TftpRequestKind.Write)
                    Interlocked.Increment(ref recognized);
            });
            Assert.Equal(64, recognized);
        }

        // 5. Attestation, redaction, fail-closed output and no exploit assertions.
        [Fact]
        public void UnattestedDatagramFailsWithDefaultObservation()
        {
            Assert.False(Inspect(Request(), out var observation, complete: false));
            Assert.Equal(default, observation);
        }

        [Fact]
        public void FilenameAndOptionValuesNeverAppearInObservation()
        {
            var request = Request(2, "sensitive-router-config.txt", "octet",
                "tsize", "123456");
            Assert.True(Inspect(request, out var observation));
            var text = observation.ToString();
            Assert.False(text.Contains("sensitive", StringComparison.OrdinalIgnoreCase));
            Assert.False(text.Contains("123456", StringComparison.Ordinal));
            Assert.Equal(TftpRequestKind.Write, observation.RequestKind);
        }

        [Fact]
        public void InvalidInputNeverLeavesPartiallyPopulatedObservation()
        {
            var invalid = Request(options: new[] { "blksize", "1428", "BLKSIZE", "512" });
            Assert.False(Inspect(invalid, out var observation));
            Assert.Equal(default, observation);
        }

        [Fact]
        public void ObservationsCannotAssertSuccessOrAuthentication()
        {
            Assert.True(Inspect(Request(2), out var observation));
            Assert.Equal(TftpRequestKind.Write, observation.RequestKind);
            Assert.Equal(4, typeof(TftpRequestObservation).GetProperties().Length);
        }
    }
}
