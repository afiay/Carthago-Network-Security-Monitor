// SPDX-License-Identifier: MIT
using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class RegistryOperationAuditAdmissionTests
    {
        private static readonly byte[] Key = SHA256.HashData(Encoding.UTF8.GetBytes("lab-registry-exporter-key"));
        private static readonly DateTime Now = new(2026, 11, 17, 3, 0, 0, DateTimeKind.Utc);
        private static RegistryAuditCandidate Candidate(string id = "event-1",
            string operation = "pull", string auth = "no", int status = 200,
            DateTime? at = null) => new(id, "lab-registry", "opaque-actor",
                "team/image", operation, auth, status, at ?? Now);
        private static byte[] Sign(RegistryAuditCandidate c)
        {
            static string F(string s) => s.Length.ToString(CultureInfo.InvariantCulture) + ":" + s;
            string payload = string.Join("|", new[] {
                F(c.EventId), F(c.RegistryId), F(c.ActorId), F(c.Repository),
                F(c.Operation), F(c.AuthenticatedActor),
                c.HttpStatus.ToString(CultureInfo.InvariantCulture),
                c.TimestampUtc.Ticks.ToString(CultureInfo.InvariantCulture)
            });
            return HMACSHA256.HashData(Key,
                Encoding.UTF8.GetBytes("carthago-registry-audit-v1|" + payload));
        }
        private static bool Admit(RegistryOperationAuditAdmission gate,
            RegistryAuditCandidate c, out RegistryAuditObservation result,
            byte[]? signature = null) =>
            gate.TryAdmit(c, Key, signature ?? Sign(c), Now, out result);

        [Theory]
        [InlineData("pull", "no", 200)]
        [InlineData("push", "yes", 201)]
        [InlineData("build-context", "unknown", 202)]
        public void SignedTerminalResponseIsTypedButNotAnAlert(
            string operation, string auth, int status)
        {
            var gate = new RegistryOperationAuditAdmission();
            Assert.True(Admit(gate, Candidate(operation: operation,
                auth: auth, status: status), out var result));
            Assert.Equal(operation, result.Operation);
            Assert.True(result.HttpAccepted);
            Assert.Equal(auth == "no", result.ExplicitlyUnauthenticated);
            Assert.Equal(auth == "yes", result.AuthenticatedActor);
        }

        [Fact] public void DeniedResponseNeverBecomesAcceptedPull()
        {
            var gate = new RegistryOperationAuditAdmission();
            Assert.True(Admit(gate, Candidate(status: 401), out var result));
            Assert.False(result.HttpAccepted);
        }

        [Fact] public void TamperedOrUnknownAuthIsRejected()
        {
            var gate = new RegistryOperationAuditAdmission();
            var c = Candidate();
            Assert.False(Admit(gate, c with { HttpStatus = 201 }, out _,
                signature: Sign(c)));
            Assert.False(Admit(gate, Candidate(auth: "none"), out _));
            Assert.False(Admit(gate, Candidate(operation: "delete"), out _));
        }

        [Fact] public void ReplayAndOutOfOrderEventsFailClosed()
        {
            var gate = new RegistryOperationAuditAdmission();
            Assert.True(Admit(gate, Candidate("first"), out _));
            Assert.False(Admit(gate, Candidate("first", at: Now.AddMinutes(1)), out _,
                signature: Sign(Candidate("first"))));
            Assert.True(Admit(gate, Candidate("second", at: Now.AddMinutes(1)), out _));
            Assert.False(Admit(gate, Candidate("old", at: Now.AddMinutes(-10)), out _));
        }
    }
}
