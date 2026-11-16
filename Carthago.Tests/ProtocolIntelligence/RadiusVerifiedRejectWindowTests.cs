// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class RadiusVerifiedRejectWindowTests
    {
        private static readonly byte[] Secret = Encoding.ASCII.GetBytes("isolated-lab-secret");
        private static readonly DateTime Epoch = new(2026, 11, 16, 12, 0, 0, DateTimeKind.Utc);

        private static (byte[] Request, byte[] Reject) Pair(int nonce)
        {
            var request = new byte[20];
            request[0] = 1; request[1] = (byte)nonce; request[3] = 20;
            BinaryPrimitives.WriteInt32LittleEndian(request.AsSpan(4, 4), nonce);
            for (int i = 8; i < 20; i++) request[i] = (byte)(i + 11);
            var reject = new byte[20];
            reject[0] = 3; reject[1] = (byte)nonce; reject[3] = 20;
            var material = new byte[20 + Secret.Length];
            reject.AsSpan(0, 4).CopyTo(material.AsSpan(0, 4));
            request.AsSpan(4, 16).CopyTo(material.AsSpan(4, 16));
            Secret.AsSpan().CopyTo(material.AsSpan(20));
            MD5.HashData(material).AsSpan().CopyTo(reject.AsSpan(4, 16));
            CryptographicOperations.ZeroMemory(material);
            return (request, reject);
        }

        private static bool Observe(RadiusVerifiedRejectWindow window, int nonce,
            DateTime at, out RadiusVerifiedRejectSummary summary,
            string client = "192.0.2.10", string server = "192.0.2.53",
            byte[]? secret = null, bool complete = true)
        {
            var pair = Pair(nonce);
            return window.TryObserve(pair.Request, client, 55000, server, 1812,
                pair.Reject, server, 1812, client, 55000, secret ?? Secret,
                complete, at, out summary);
        }

        [Fact] public void FourUniqueVerifiedExchangesReachObservationThreshold()
        {
            var window = new RadiusVerifiedRejectWindow();
            for (int i = 0; i < 4; i++)
            {
                Assert.True(Observe(window, i, Epoch.AddSeconds(i), out var observation));
                Assert.Equal(i + 1, observation.DistinctProtocolRejects);
                Assert.Equal(i == 3, observation.HasFourDistinctRejects);
            }
        }

        [Fact] public void DuplicateRequestAndContradictoryEvidenceFailClosed()
        {
            var window = new RadiusVerifiedRejectWindow();
            Assert.True(Observe(window, 7, Epoch, out _));
            Assert.False(Observe(window, 7, Epoch.AddSeconds(1), out _));
            Assert.False(Observe(window, 8, Epoch.AddSeconds(2), out _,
                secret: Encoding.ASCII.GetBytes("wrong")));
            Assert.False(Observe(window, 8, Epoch.AddSeconds(2), out _, complete: false));
            Assert.True(Observe(window, 8, Epoch.AddSeconds(3), out var result));
            Assert.Equal(2, result.DistinctProtocolRejects);
        }

        [Fact] public void ClientAndServerIsolationPreventCrossHostInflation()
        {
            var window = new RadiusVerifiedRejectWindow();
            Assert.True(Observe(window, 1, Epoch, out _));
            Assert.True(Observe(window, 2, Epoch, out var other,
                client: "192.0.2.20"));
            Assert.Equal(1, other.DistinctProtocolRejects);
            Assert.True(Observe(window, 3, Epoch, out var another,
                server: "192.0.2.54"));
            Assert.Equal(1, another.DistinctProtocolRejects);
        }

        [Fact] public void MonotonicWindowRejectsStaleAndExpiresAtExactBoundary()
        {
            var window = new RadiusVerifiedRejectWindow();
            Assert.True(Observe(window, 1, Epoch, out _));
            Assert.True(Observe(window, 2, Epoch.AddMinutes(10), out var inclusive));
            Assert.Equal(2, inclusive.DistinctProtocolRejects);
            Assert.True(Observe(window, 3, Epoch.AddMinutes(10).AddTicks(1),
                out var after));
            Assert.Equal(2, after.DistinctProtocolRejects);
            Assert.False(Observe(window, 4, Epoch, out _));
            window.Reset();
            Assert.True(Observe(window, 4, Epoch, out var reset));
            Assert.Equal(1, reset.DistinctProtocolRejects);
        }

        [Fact] public void CapacityExhaustionNeverEvictsUnexpiredIdentity()
        {
            var window = new RadiusVerifiedRejectWindow();
            for (int i = 0; i < RadiusVerifiedRejectWindow.MaximumObservations; i++)
                Assert.True(Observe(window, i, Epoch, out _));
            Assert.False(Observe(window, 5000, Epoch.AddMinutes(10), out _));
            // The 10-minute counting window expires, but the bounded replay
            // cache remains saturated rather than evicting trusted identities.
            Assert.False(Observe(window, 5000, Epoch.AddMinutes(10).AddTicks(1), out _));
            Assert.False(Observe(window, 0, Epoch.AddMinutes(10).AddTicks(1), out _));
            Assert.True(Observe(window, 5000, Epoch.AddHours(24).AddTicks(1),
                out var recovered));
            Assert.Equal(1, recovered.DistinctProtocolRejects);
        }

        [Fact] public void OutOfOrderVerifiedCaptureCannotBackfillThreshold()
        {
            var window = new RadiusVerifiedRejectWindow();
            Assert.True(Observe(window, 1, Epoch.AddSeconds(30), out var first));
            Assert.Equal(1, first.DistinctProtocolRejects);
            Assert.False(Observe(window, 2, Epoch.AddSeconds(10), out var rejected));
            Assert.Equal(default, rejected);
            Assert.True(Observe(window, 3, Epoch.AddSeconds(30), out var second));
            Assert.Equal(2, second.DistinctProtocolRejects);
            Assert.False(Observe(window, 2, Epoch.AddSeconds(10), out _));
            Assert.True(Observe(window, 4, Epoch.AddSeconds(31), out var third));
            Assert.Equal(3, third.DistinctProtocolRejects);
            Assert.False(third.HasFourDistinctRejects);
        }

        [Fact] public void EqualTimestampDistinctExchangesRemainEligible()
        {
            var window = new RadiusVerifiedRejectWindow();
            for (int i = 0; i < 4; i++)
            {
                Assert.True(Observe(window, i, Epoch, out var observation));
                Assert.Equal(i == 3, observation.HasFourDistinctRejects);
            }
        }

        [Fact] public void MappedAddressFormsAreCanonicalizedForReplay()
        {
            var window = new RadiusVerifiedRejectWindow();
            Assert.True(Observe(window, 1, Epoch, out _));
            Assert.False(Observe(window, 1, Epoch, out _,
                client: "::ffff:192.0.2.10", server: "::ffff:192.0.2.53"));
            Assert.True(Observe(window, 2, Epoch, out var result,
                client: "::ffff:192.0.2.10", server: "::ffff:192.0.2.53"));
            Assert.Equal(2, result.DistinctProtocolRejects);
        }

        [Fact] public void ExpiredCountDoesNotPermitReplayWithinRetention()
        {
            var window = new RadiusVerifiedRejectWindow();
            Assert.True(Observe(window, 9, Epoch, out _));
            Assert.True(Observe(window, 10, Epoch.AddMinutes(11), out var fresh));
            Assert.Equal(1, fresh.DistinctProtocolRejects);
            Assert.False(Observe(window, 9, Epoch.AddMinutes(11), out _));
            Assert.True(Observe(window, 11, Epoch.AddMinutes(11), out var second));
            Assert.Equal(2, second.DistinctProtocolRejects);
        }

        [Fact] public void UnspecifiedTimeZoneIsNotTrusted()
        {
            var window = new RadiusVerifiedRejectWindow();
            Assert.False(Observe(window, 1,
                DateTime.SpecifyKind(Epoch, DateTimeKind.Unspecified), out _));
        }
    }
}
