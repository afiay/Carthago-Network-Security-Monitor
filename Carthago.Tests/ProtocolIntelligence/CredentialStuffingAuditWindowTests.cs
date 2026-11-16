// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class CredentialStuffingAuditWindowTests
    {
        private static readonly byte[] Key = Enumerable.Repeat((byte)0x53, 32).ToArray();
        private static readonly DateTime Epoch = new(2026, 11, 16, 12, 0, 0, DateTimeKind.Utc);
        private static bool Add(CredentialStuffingAuditWindow w, int i, DateTime at,
            out int accounts, out int agents, byte[]? key = null,
            string source = "192.0.2.10", string destination = "login.example.test")
        {
            string account = "account-digest-" + i, agent = "agent-digest-" + (i % 3),
                id = "event-" + i;
            var sig = CredentialStuffingAuditWindow.SignForExporter(
                source, destination, account, agent, id, at, Key);
            return w.TryObserveFailure(source, destination, account, agent, id,
                at, sig, key ?? Key, out accounts, out agents);
        }

        [Fact] public void FiveAuthenticatedDistinctAccountsAndThreeAgentsAreObservationsOnly()
        {
            var w = new CredentialStuffingAuditWindow();
            for (int i = 0; i < 5; i++)
            {
                Assert.True(Add(w, i, Epoch.AddSeconds(i), out var accounts, out var agents));
                Assert.Equal(i + 1, accounts);
                Assert.Equal(Math.Min(i + 1, 3), agents);
            }
        }

        [Fact] public void ForgeryReplayAndStaleAuditFailClosed()
        {
            var w = new CredentialStuffingAuditWindow();
            Assert.True(Add(w, 1, Epoch.AddSeconds(10), out _, out _));
            Assert.False(Add(w, 1, Epoch.AddHours(1), out _, out _));
            Assert.False(Add(w, 2, Epoch.AddSeconds(11), out _, out _,
                key: Enumerable.Repeat((byte)0x42, 32).ToArray()));
            Assert.False(Add(w, 3, Epoch, out _, out _));
            Assert.True(Add(w, 2, Epoch.AddSeconds(11), out var accounts, out _));
            Assert.Equal(2, accounts);
        }

        [Fact] public void DistinctSourcesAndDestinationsCannotInflateOneGroup()
        {
            var w = new CredentialStuffingAuditWindow();
            Assert.True(Add(w, 1, Epoch, out _, out _));
            Assert.True(Add(w, 2, Epoch, out var accounts, out _,
                source: "192.0.2.20"));
            Assert.Equal(1, accounts);
            Assert.True(Add(w, 3, Epoch, out accounts, out _,
                destination: "other.example.test"));
            Assert.Equal(1, accounts);
        }

        [Fact] public void ExpirationDoesNotManufactureAThreshold()
        {
            var w = new CredentialStuffingAuditWindow();
            Assert.True(Add(w, 1, Epoch, out _, out _));
            Assert.True(Add(w, 2, Epoch.AddMinutes(20).AddTicks(1),
                out var accounts, out _));
            Assert.Equal(1, accounts);
        }
    }
}
