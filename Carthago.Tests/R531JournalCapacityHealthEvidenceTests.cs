// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests
{
    public sealed class R531JournalCapacityHealthEvidenceTests
    {
        private static DetectionJournal CreateJournal()
            => new(new DetectionJournalOptions
            {
                DirectoryPath = Path.Combine(
                    Path.GetTempPath(), "carthago-r531", Guid.NewGuid().ToString("N"))
            });

        private static TrafficRecord CreateRecord(JournalCapacityHealthEvidence? evidence = null)
        {
            var record = new TrafficRecord
            {
                Source = "carthago-local-journal-health",
                Destination = "configured-journal:" + (evidence?.JournalIdentity ?? "untrusted"),
                Protocol = "platform-health",
                ApplicationProtocol = "platform-health",
                ApplicationService = "detection-journal",
                Info = "OS-backed configured journal capacity observation",
                Length = 1
            };
            record.TrustedJournalCapacityEvidence = evidence;
            return record;
        }

        [Fact]
        public void JournalOwnerRejectsSamplesThatDoNotBreachBothThresholds()
        {
            var journal = CreateJournal();

            var evidence = journal.CreateConfirmedLowCapacityEvidence(
                DateTime.UtcNow, 500, 1000, 100, 10);

            Assert.Null(evidence);
        }

        [Fact]
        public void JournalOwnerCreatesPathBoundImmutableEvidenceForConfirmedLowSample()
        {
            var journal = CreateJournal();

            var evidence = journal.CreateConfirmedLowCapacityEvidence(
                DateTime.UtcNow, 50, 1000, 100, 10);

            Assert.NotNull(evidence);
            Assert.True(evidence!.IsValid);
            Assert.Equal(32, evidence.JournalIdentity.Length);
            Assert.Equal(50, evidence.AvailableBytes);
            Assert.Equal(1000, evidence.TotalBytes);
            Assert.Equal(DateTimeKind.Utc, evidence.SampledAtUtc.Kind);
        }

        [Fact]
        public async Task R531DoesNotMatchMutablePacketTextWithoutTypedJournalEvidence()
        {
            var rule = new R531_DetectionJournalDiskSpaceLowRule();
            var record = CreateRecord();
            var context = new RuleEvaluationContext(
                record, Sensitivity.Balanced, DateTime.UtcNow);

            var result = await rule.EvaluateAsync(context);

            Assert.False(result.Matched);
            Assert.Contains(result.NoMatchReasons,
                reason => reason.Code == "JOURNAL_FREE_SPACE_TRUSTED_VOLUME_METRIC_UNAVAILABLE");
        }

        [Fact]
        public void RuleEngineRejectsHealthEvidenceFromAnotherJournalOwner()
        {
            var directory = Path.Combine(
                Path.GetTempPath(), "carthago-r531-shared-" + Guid.NewGuid().ToString("N"));
            var producerJournal = new DetectionJournal(new DetectionJournalOptions
            {
                DirectoryPath = directory
            });
            var persistenceJournal = new DetectionJournal(new DetectionJournalOptions
            {
                DirectoryPath = directory
            });
            var evidence = producerJournal.CreateConfirmedLowCapacityEvidence(
                DateTime.UtcNow, 50, 1000, 100, 10);

            Assert.NotNull(evidence);
            using (RuleEngine.PushDetectionJournalForTests(persistenceJournal))
            {
                Assert.Same(persistenceJournal,
                    RuleEngine.GetActiveDetectionJournalForHealthMonitor());

                // Same configured path is insufficient: distinct journal instances
                // have distinct write ownership and cannot exchange health evidence.
                Assert.Throws<InvalidOperationException>(() =>
                    RuleEngine.EvaluateJournalCapacityHealth(
                        persistenceJournal, evidence!, Sensitivity.Balanced));

                // Even the evidence's creator cannot dispatch while a different
                // persistence owner is active in this execution context.
                Assert.Throws<InvalidOperationException>(() =>
                    RuleEngine.EvaluateJournalCapacityHealth(
                        producerJournal, evidence!, Sensitivity.Balanced));
            }
        }

        [Fact]
        public async Task R531MatchesTypedJournalEvidenceAndPrecisionProfileAcceptsIt()
        {
            var rule = new R531_DetectionJournalDiskSpaceLowRule();
            var journal = CreateJournal();
            var evidence = journal.CreateConfirmedLowCapacityEvidence(
                DateTime.UtcNow, 50, 1000, 100, 10);
            Assert.NotNull(evidence);

            var record = CreateRecord(evidence);
            var validation = RulePrecisionCatalog.Validate("R531", record);
            Assert.True(validation.CanEvaluate,
                string.Join("; ", validation.MissingTelemetry.Concat(validation.MissingFields)));

            var context = new RuleEvaluationContext(
                record, Sensitivity.Balanced, evidence!.SampledAtUtc);
            var result = await rule.EvaluateAsync(context);

            Assert.True(result.Matched);
            Assert.Single(result.Events);
            Assert.True(result.Events[0].ConfidenceScore >= 90);
            Assert.Contains(result.Events[0].StructuredEvidence.Items,
                item => item.Key == "journal.availableBytes" && item.Value == "50");
        }
    }
}
