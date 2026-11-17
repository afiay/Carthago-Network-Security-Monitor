// SPDX-License-Identifier: MIT
using System;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class Pop3CleartextCommandInspectorTests
    {
        private static byte[] Bytes(string value) => Encoding.ASCII.GetBytes(value);
        private static bool Inspect(string line, bool complete = true, bool plaintext = true)
            => Pop3CleartextCommandInspector.TryInspect(Bytes(line), complete, plaintext, out _);

        [Theory]
        [InlineData("USER alice\\r\\n", Pop3CredentialCommandKind.User)]
        [InlineData("PASS secret-value\\r\\n", Pop3CredentialCommandKind.Pass)]
        public void CompletePlaintextCommandsProduceOnlyRedactedKind(
            string encoded, Pop3CredentialCommandKind kind)
        {
            var bytes = Bytes(encoded.Replace("\\r", "\r").Replace("\\n", "\n"));
            Assert.True(Pop3CleartextCommandInspector.TryInspect(bytes, true, true, out var result));
            Assert.Equal(kind, result.Kind);
            Assert.DoesNotContain("secret", result.ToString(), StringComparison.OrdinalIgnoreCase);
        }

        [Fact] public void PartialOrEncryptedTransportIsNotEvidence()
        {
            Assert.False(Inspect("PASS secret\r\n", complete: false));
            Assert.False(Inspect("PASS secret\r\n", plaintext: false));
        }

        [Theory]
        [InlineData("PASS \r\n")]
        [InlineData("PASS secret\n")]
        [InlineData("PASS secret\r\nUSER alice\r\n")]
        [InlineData("PASS secret with space\r\n")]
        [InlineData("pass secret\r\n")]
        [InlineData("+OK secret\r\n")]
        [InlineData("STLS\r\n")]
        public void MalformedOrUnrelatedCommandsFailClosed(string line)
            => Assert.False(Inspect(line));

        [Fact] public void LengthLimitFailsClosed()
            => Assert.False(Inspect("PASS " + new string('A', 506) + "\r\n"));
    }
}
