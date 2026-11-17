// SPDX-License-Identifier: MIT
using System;
using System.Security.Cryptography;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class KubernetesAuditAdmissionTests
    {
        private static readonly byte[] Key = SHA256.HashData(Encoding.UTF8.GetBytes("isolated-test-exporter-key"));
        private static readonly DateTime Now = new(2026, 11, 17, 2, 0, 0, DateTimeKind.Utc);
        private static KubernetesAuditCandidate Candidate(string resource = "secrets",
            string subresource = "", string verb = "get", string stage = "ResponseComplete",
            string decision = "allow", string id = "audit-1") =>
            new(id, "lab-cluster", "system:serviceaccount:lab:reader",
                resource, verb, stage, "lab", subresource, decision, Now);

        private static byte[] Sign(KubernetesAuditCandidate c)
        {
            static string F(string s) => s.Length + ":" + s;
            string payload = string.Join("|", new[] { F(c.AuditId), F(c.Cluster),
                F(c.Principal), F(c.Resource), F(c.Verb), F(c.Stage),
                F(c.Namespace), F(c.Subresource), F(c.Decision),
                c.TimestampUtc.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture) });
            return HMACSHA256.HashData(Key,
                Encoding.UTF8.GetBytes("carthago-k8s-audit-v1|" + payload));
        }
        private static bool Admit(KubernetesAuditAdmission gate,
            KubernetesAuditCandidate c, out KubernetesAuditObservation observation,
            byte[]? signature = null) =>
            gate.TryAdmit(c, Key, signature ?? Sign(c), Now, out observation);

        [Theory]
        [InlineData("secrets", "", "get", KubernetesAuditOperation.SecretsRead)]
        [InlineData("pods", "exec", "create", KubernetesAuditOperation.PodExecRequest)]
        [InlineData("pods", "portforward", "create", KubernetesAuditOperation.PortForwardRequest)]
        public void SignedTerminalAuditIsTypedButNotAnAttack(
            string resource, string subresource, string verb, KubernetesAuditOperation expected)
        {
            var gate = new KubernetesAuditAdmission();
            Assert.True(Admit(gate, Candidate(resource, subresource, verb),
                out var observation));
            Assert.Equal(expected, observation.Operation);
            Assert.True(observation.AuditAllowed);
        }

        [Fact] public void DeniedAuditDoesNotClaimAllowedOutcome()
        {
            var gate = new KubernetesAuditAdmission();
            Assert.True(Admit(gate, Candidate(decision: "deny"), out var observation));
            Assert.False(observation.AuditAllowed);
        }

        [Fact] public void InvalidSignatureAndNonTerminalStageFailClosed()
        {
            var gate = new KubernetesAuditAdmission();
            Assert.False(Admit(gate, Candidate(), out _, new byte[32]));
            Assert.False(Admit(gate, Candidate(stage: "RequestReceived"), out _));
            Assert.True(Admit(gate, Candidate(), out _));
        }

        [Fact] public void DuplicateAndStaleEventsFailClosed()
        {
            var gate = new KubernetesAuditAdmission();
            var first = Candidate();
            Assert.True(Admit(gate, first, out _));
            Assert.False(Admit(gate, first, out _));
            Assert.False(Admit(gate, first with {
                AuditId = "late", TimestampUtc = Now.AddMinutes(-11) }, out _));
        }

        [Fact] public void ContradictoryFieldsAreRejected()
        {
            var gate = new KubernetesAuditAdmission();
            Assert.False(Admit(gate, Candidate(id: "bad|id"), out _));
            Assert.False(Admit(gate, Candidate(decision: "unknown"), out _));
        }
    }
}
