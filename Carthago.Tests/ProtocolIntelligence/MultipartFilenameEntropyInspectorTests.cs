// SPDX-License-Identifier: MIT
using System;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public class MultipartFilenameEntropyInspectorTests
    {
        private static byte[] Body(string filename) => Encoding.ASCII.GetBytes(
            "--safeBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" +
            filename + "\"\r\nContent-Type: application/octet-stream\r\n\r\nabc\r\n--safeBoundary--\r\n");

        [Fact]
        public void CompleteHighEntropyFilenameIsCandidateOnly()
        {
            Assert.True(MultipartFilenameEntropyInspector.TryInspect(
                Body("aB3xY9kL2pQ7rT5vZ8.bin"), "safeBoundary", true, out var entropy));
            Assert.True(entropy >= 3.5);
        }

        [Fact]
        public void IncompleteOrUntrustedBodyFailsClosed()
        {
            Assert.False(MultipartFilenameEntropyInspector.TryInspect(
                Body("aB3xY9kL2pQ7rT5vZ8.bin"), "safeBoundary", false, out _));
            Assert.False(MultipartFilenameEntropyInspector.TryInspect(
                Body("aB3xY9kL2pQ7rT5vZ8.bin"), "wrong", true, out _));
        }

        [Theory]
        [InlineData("normal-report.txt")]
        [InlineData("../aB3xY9kL2pQ7rT5vZ8.bin")]
        [InlineData("aaaaaaaaaaaaaaaaaaaa.bin")]
        public void BenignOrMalformedFilenamesFailClosed(string filename)
        {
            Assert.False(MultipartFilenameEntropyInspector.TryInspect(
                Body(filename), "safeBoundary", true, out _));
        }
    }
}
