// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic source-only fixtures; no credentials from real systems.
    // SOURCE CANDIDATE — UNVERIFIED; no tests executed.
    public sealed class RexecRequestInspectorTests
    {
        private static byte[] Request(string stderrPort = "0",
            string username = "labuser", string password = "fake-secret",
            string command = "id")
            => Encoding.ASCII.GetBytes(
                stderrPort + "\0" + username + "\0" + password + "\0" + command + "\0");

        private static bool Inspect(ReadOnlySpan<byte> bytes,
            out RexecRequestObservation result)
            => RexecRequestInspector.TryInspect(bytes,
                true, true, true, true, true, true, out result);

        [Theory]
        [InlineData("0", 0)]
        [InlineData("12345", 12345)]
        [InlineData("65535", 65535)]
        public void ValidCompleteClientRequestYieldsOnlyMetadata(string port, int expected)
        {
            Assert.True(Inspect(Request(stderrPort: port), out var result));
            Assert.Equal(expected, result.StandardErrorPort);
            Assert.True(result.HasCredentialField);
            Assert.True(result.HasCommandField);
        }

        [Fact] public void EmptyPasswordIsSyntacticallyPossibleNotAuthEvidence()
        {
            Assert.True(Inspect(Request(password: ""), out _));
        }

        [Fact] public void SshBannerIsNotRexec()
        {
            Assert.False(Inspect(Encoding.ASCII.GetBytes("SSH-2.0-Test\r\n"), out _));
        }

        [Fact] public void ReorderedNullTerminatedFieldsFailClosed()
        {
            Assert.False(Inspect(Encoding.ASCII.GetBytes("user\0pass\0id\00\0"), out _));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        public void TruncatedTailIsRejected(int missingBytes)
        {
            var request = Request();
            Assert.False(Inspect(request.AsSpan(0, request.Length - missingBytes), out _));
        }

        [Theory]
        [InlineData("65536")]
        [InlineData("x")]
        [InlineData("")]
        public void InvalidStderrPortFailsClosed(string port)
        {
            Assert.False(Inspect(Request(stderrPort: port), out _));
        }

        [Fact] public void ExcessivelyLongUsernameIsRejected()
        {
            Assert.False(Inspect(Request(username: new string('a', 129)), out _));
        }

        [Fact] public void ExcessivelyLongPasswordIsRejectedWithoutRetention()
        {
            Assert.False(Inspect(Request(password: new string('p', 257)), out _));
        }

        [Fact] public void ExcessivelyLongCommandIsRejected()
        {
            Assert.False(Inspect(Request(command: new string('x', 1025)), out _));
        }

        [Fact] public void NonAsciiUsernameIsRejected()
        {
            Assert.False(Inspect(Request(username: "user\nadmin"), out _));
        }

        [Fact] public void ControlCharacterCommandIsRejected()
        {
            Assert.False(Inspect(Request(command: "id\nwhoami"), out _));
        }

        [Fact] public void TrailingDataAfterCompleteRequestIsRejected()
        {
            var bytes = Request().Concat(new byte[] { 0x41 }).ToArray();
            Assert.False(Inspect(bytes, out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        public void MissingTrustedProvenanceFlagRejectsRequest(int missingFlag)
        {
            bool[] flags = { true, true, true, true, true, true };
            flags[missingFlag] = false;
            Assert.False(RexecRequestInspector.TryInspect(Request(),
                flags[0], flags[1], flags[2], flags[3], flags[4], flags[5], out _));
        }

        [Fact] public void OutputNeverContainsUserPasswordOrCommand()
        {
            var bytes = Request(username: "unique_user", password: "secret_token",
                command: "sensitive_command");
            Assert.True(Inspect(bytes, out var observation));
            string printed = observation.ToString();
            Assert.DoesNotContain("unique_user", printed);
            Assert.DoesNotContain("secret_token", printed);
            Assert.DoesNotContain("sensitive_command", printed);
        }

        [Fact] public void ConcurrentInspectionIsStatelessAndDeterministic()
        {
            var bytes = Request();
            Parallel.For(0, 128, _ =>
            {
                Assert.True(Inspect(bytes, out var observation));
                Assert.Equal(0, observation.StandardErrorPort);
            });
        }
    }
}
