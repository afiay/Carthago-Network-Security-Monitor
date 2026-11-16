// SPDX-License-Identifier: MIT
using System;
using System.Security.Cryptography;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class RadiusAccessRejectExchangeVerifierTests
    {
        private static readonly byte[] Secret = Encoding.ASCII.GetBytes("synthetic-lab-secret");
        private static byte[] Packet(byte code, byte identifier)
        {
            var bytes = new byte[20];
            bytes[0] = code; bytes[1] = identifier; bytes[3] = 20;
            for (int i = 4; i < 20; i++) bytes[i] = (byte)(i + 11);
            return bytes;
        }
        private static (byte[] Request, byte[] Response) Pair()
        {
            var req = Packet(1, 7); var reply = Packet(3, 7);
            var message = new byte[reply.Length + Secret.Length];
            reply.AsSpan(0, 4).CopyTo(message.AsSpan(0, 4));
            req.AsSpan(4, 16).CopyTo(message.AsSpan(4, 16));
            Secret.AsSpan().CopyTo(message.AsSpan(reply.Length));
            MD5.HashData(message).AsSpan().CopyTo(reply.AsSpan(4, 16));
            CryptographicOperations.ZeroMemory(message);
            return (req, reply);
        }
        private static bool Check(byte[] req, byte[] reply, byte[]? secret = null,
            string client = "192.0.2.10", string server = "192.0.2.53",
            ushort responseDestinationPort = 55000, bool complete = true)
            => RadiusAccessRejectExchangeVerifier.TryVerify(
                req, client, 55000, server, 1812,
                reply, server, 1812, client, responseDestinationPort,
                secret ?? Secret, complete, out _);

        [Fact] public void VerifiedPairReportsOnlyTypedReject()
        {
            var pair = Pair();
            Assert.True(RadiusAccessRejectExchangeVerifier.TryVerify(
                pair.Request, "192.0.2.10", 55000, "192.0.2.53", 1812,
                pair.Response, "192.0.2.53", 1812, "192.0.2.10", 55000,
                Secret, true, out var found));
            Assert.Equal((byte)3, found.Code);
            Assert.DoesNotContain("synthetic-lab-secret", found.ToString());
        }
        [Fact] public void WrongSecretOrTamperedResponseFailsClosed()
        {
            var pair = Pair();
            Assert.False(Check(pair.Request, pair.Response,
                Encoding.ASCII.GetBytes("wrong-secret")));
            pair.Response[4] ^= 1;
            Assert.False(Check(pair.Request, pair.Response));
        }
        [Fact] public void BrokenCorrelationFailsClosed()
        {
            var pair = Pair();
            Assert.False(Check(pair.Request, pair.Response, client: "192.0.2.11"));
            Assert.False(Check(pair.Request, pair.Response, responseDestinationPort: 55001));
            Assert.False(Check(pair.Request, pair.Response, complete: false));
            var other = Packet(1, 7);
            other[6] ^= 1;
            Assert.False(Check(other, pair.Response));
            other[1] = 8;
            Assert.False(Check(other, pair.Response));
        }
        [Fact] public void UnsupportedResponseAndMessageAuthenticatorFailClosed()
        {
            var pair = Pair();
            pair.Response[0] = 2;
            Assert.False(Check(pair.Request, pair.Response));
            pair = Pair();
            var reply = pair.Response;
            Array.Resize(ref reply, 38);
            reply[3] = 38;
            reply[20] = 80; reply[21] = 18;
            Assert.False(Check(pair.Request, reply));
        }
    }
}
