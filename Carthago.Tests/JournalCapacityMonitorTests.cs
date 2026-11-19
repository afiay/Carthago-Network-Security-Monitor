// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests
{
    public sealed class JournalCapacityMonitorTests
    {
        [Fact]
        public async Task AlreadyCancelledOwnerStopsWithoutSamplingOrDelivery()
        {
            var journal = new DetectionJournal(new DetectionJournalOptions());
            var policyReads = 0;
            var deliveries = 0;
            var monitor = new JournalCapacityMonitor(
                journal, 1024, 10, TimeSpan.FromMilliseconds(20),
                () => { Interlocked.Increment(ref policyReads); return false; },
                _ => Interlocked.Increment(ref deliveries));
            using var owner = new CancellationTokenSource();
            owner.Cancel();
            await monitor.RunAsync(owner.Token);
            Assert.Equal(0, Volatile.Read(ref policyReads));
            Assert.Equal(0, Volatile.Read(ref deliveries));
        }

        [Fact]
        public void RejectsMissingPolicyOrDeliveryAndInvalidCadence()
        {
            var journal = new DetectionJournal(new DetectionJournalOptions());
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                new JournalCapacityMonitor(journal, 1024, 10, TimeSpan.Zero,
                    () => false, (_, _, _) => { }));
            Assert.Throws<ArgumentNullException>(() =>
                new JournalCapacityMonitor(journal, 1024, 10, TimeSpan.FromSeconds(1),
                    null!, (_, _, _) => { }));
            Assert.Throws<ArgumentNullException>(() =>
                new JournalCapacityMonitor(journal, 1024, 10, TimeSpan.FromSeconds(1),
                    () => false, null!));
        }
        [Fact]
        public async Task ConcurrentOwnerIsRejectedAndMonitorCanRestartAfterCancellation()
        {
            var journal = new DetectionJournal(new DetectionJournalOptions());
            var monitor = new JournalCapacityMonitor(
                journal, 1024, 10, TimeSpan.FromMilliseconds(50),
                () => true, _ => { });
            using var owner = new CancellationTokenSource();
            var running = monitor.RunAsync(owner.Token);
            try
            {
                await Assert.ThrowsAsync<InvalidOperationException>(
                    () => monitor.RunAsync(CancellationToken.None));
            }
            finally
            {
                owner.Cancel();
                await running;
            }
            using var nextOwner = new CancellationTokenSource();
            nextOwner.Cancel();
            await monitor.RunAsync(nextOwner.Token);
        }

    }
}
