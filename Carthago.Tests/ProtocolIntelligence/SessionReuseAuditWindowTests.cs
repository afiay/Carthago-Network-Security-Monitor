// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class SessionReuseAuditWindowTests
    {
        private static readonly byte[] Key = Enumerable.Repeat((byte)0x7A, 32).ToArray();
        private static readonly DateTime Epoch = new(2026, 11, 16, 12, 0, 0, DateTimeKind.Utc);

        private static bool Add(SessionReuseAuditWindow window, string id,
            string country, DateTime time, out int countries,
            string token = "opaque-token-digest", string account = "opaque-account-digest",
            string source = "192.0.2.10", string destination = "login.example.test",
            bool accepted = true, byte[]? verificationKey = null)
        {
            byte[] sig = SessionReuseAuditWindow.SignForExporter(id, account,
                token, source, destination, country, accepted, time, Key);
            return window.TryObserve(id, account, token, source, destination,
                country, accepted, time, sig, verificationKey ?? Key, out countries);
        }

        [Fact] public void TwoSignedAcceptedUsesOfSameSessionAcrossCountriesAreObservations()
        {
            var w = new SessionReuseAuditWindow();
            Assert.True(Add(w, "evt1", "FR", Epoch, out var first));
            Assert.Equal(1, first);
            Assert.True(Add(w, "evt2", "JP", Epoch.AddSeconds(1), out var second));
            Assert.Equal(2, second);
            // This is not a detector-positive assertion.
        }

        [Fact] public void DifferentTokenOrAccountDoesNotCountAsSameSession()
        {
            var w = new SessionReuseAuditWindow();
            Assert.True(Add(w, "evt1", "FR", Epoch, out _));
            Assert.True(Add(w, "evt2", "JP", Epoch.AddSeconds(1),
                out var differentToken, token: "another-token"));
            Assert.Equal(1, differentToken);
            Assert.True(Add(w, "evt3", "JP", Epoch.AddSeconds(2),
                out var differentAccount, account: "another-account"));
            Assert.Equal(1, differentAccount);
        }

        [Fact] public void RejectedOutcomeWrongKeyAndReplayCannotInflateObservation()
        {
            var w = new SessionReuseAuditWindow();
            Assert.False(Add(w, "rejected", "FR", Epoch, out _, accepted: false));
            Assert.False(Add(w, "bad-key", "FR", Epoch, out _,
                verificationKey: Enumerable.Repeat((byte)0x55, 32).ToArray()));
            Assert.True(Add(w, "evt1", "FR", Epoch, out _));
            Assert.False(Add(w, "evt1", "JP", Epoch.AddSeconds(2), out _));
            Assert.False(Add(w, "old", "JP", Epoch.AddTicks(-1), out _));
        }

        [Fact] public void ExpirationAndCountryNormalizationPreventFalseThreshold()
        {
            var w = new SessionReuseAuditWindow();
            Assert.True(Add(w, "evt1", "fr", Epoch, out _));
            Assert.True(Add(w, "evt2", "FR", Epoch.AddSeconds(1), out var same));
            Assert.Equal(1, same);
            Assert.True(Add(w, "evt3", "JP", Epoch.AddMinutes(30).AddTicks(1),
                out var expired));
            Assert.Equal(2, expired);
            Assert.True(Add(w, "evt4", "DE", Epoch.AddMinutes(31),
                out var current));
            Assert.Equal(2, current);
        }

        [Fact] public void IncompleteOrContradictoryAuditFieldsFailClosed()
        {
            var w = new SessionReuseAuditWindow();
            var signature = SessionReuseAuditWindow.SignForExporter("evt", "account",
                "token", "source", "destination", "FR", true, Epoch, Key);
            Assert.False(w.TryObserve("evt", "account", "token", "source",
                "destination", "JP", true, Epoch, signature, Key, out _));
            Assert.False(w.TryObserve("evt", "account", "token", "source",
                "destination", "", true, Epoch, signature, Key, out _));
            Assert.False(w.TryObserve("evt", "account", "token", "source",
                "destination", "FR", true,
                DateTime.SpecifyKind(Epoch, DateTimeKind.Unspecified),
                signature, Key, out _));
        }
    }
}
