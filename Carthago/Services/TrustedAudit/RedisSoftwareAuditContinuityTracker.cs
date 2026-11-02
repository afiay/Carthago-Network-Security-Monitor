// SPDX-License-Identifier: MIT
// GA R437 — SOURCE CANDIDATE — UNVERIFIED.
using System;
using System.Collections.Generic;

namespace Carthago.Services.TrustedAudit
{
    public enum RedisAuditDeliveryStatus
    {
        FirstObservation,
        Contiguous,
        SequenceGap,
        DuplicateOrRollback,
        AlreadyCompromised,
        InvalidProducerIdentity,
        CapacityExceeded
    }

    /// <summary>
    /// This is a local delivery diagnostic, not authentication or evidence that
    /// every event Redis produced was ever queued/delivered. The operator's
    /// trusted transport must identify the producer; the raw JSON has no such ID.
    /// </summary>
    public sealed record RedisAuditDeliveryAssessment(
        RedisAuditDeliveryStatus Status,
        long? PreviousSequence,
        long CurrentSequence)
    {
        // A contiguous index alone does not prove complete command auditing,
        // transport trust, server identity, or CONFIG SET intent.
        public bool NoGapObserved => Status == RedisAuditDeliveryStatus.Contiguous;
        public bool AuthenticityEstablished => false;
    }

    /// <summary>
    /// Tracks audit_seq per (operator-authenticated source, audit_worker_id).
    /// Redis Software documents audit_seq as a per-worker sequence; do not
    /// partition by database or command because that conceals other events.
    /// Feed ALL event types through this tracker, not just CONFIG commands.
    ///
    /// A gap, rollback or duplicate poisons a worker for the lifetime of
    /// this instance. Explicit operator review/reinitialization is required;
    /// a reconnect never silently clears a loss indication.
    /// </summary>
    public sealed class RedisSoftwareAuditContinuityTracker
    {
        private const int MaxWorkerStreams = 256;
        private readonly object _gate = new();
        private readonly Dictionary<string, (long Sequence, bool Compromised)> _streams
            = new(StringComparer.Ordinal);

        public RedisAuditDeliveryAssessment Observe(
            string? provisionedProducerId,
            RedisSoftwareAuditObservation? observation)
        {
            if (observation == null || !ValidSourceId(provisionedProducerId))
                return new(RedisAuditDeliveryStatus.InvalidProducerIdentity,
                    null, observation?.AuditSequence ?? -1);

            var sourceKey = provisionedProducerId + ":" + observation.WorkerId;
            lock (_gate)
            {
                if (!_streams.TryGetValue(sourceKey, out var state))
                {
                    if (_streams.Count >= MaxWorkerStreams)
                        return new(RedisAuditDeliveryStatus.CapacityExceeded,
                            null, observation.AuditSequence);

                    _streams.Add(sourceKey, (observation.AuditSequence, false));
                    return new(RedisAuditDeliveryStatus.FirstObservation,
                        null, observation.AuditSequence);
                }

                if (state.Compromised)
                    return new(RedisAuditDeliveryStatus.AlreadyCompromised,
                        state.Sequence, observation.AuditSequence);

                if (observation.AuditSequence <= state.Sequence)
                {
                    _streams[sourceKey] = (state.Sequence, true);
                    return new(RedisAuditDeliveryStatus.DuplicateOrRollback,
                        state.Sequence, observation.AuditSequence);
                }

                if (state.Sequence == long.MaxValue
                    || observation.AuditSequence != state.Sequence + 1)
                {
                    _streams[sourceKey] = (state.Sequence, true);
                    return new(RedisAuditDeliveryStatus.SequenceGap,
                        state.Sequence, observation.AuditSequence);
                }

                _streams[sourceKey] = (observation.AuditSequence, false);
                return new(RedisAuditDeliveryStatus.Contiguous,
                    state.Sequence, observation.AuditSequence);
            }
        }

        private static bool ValidSourceId(string? source)
        {
            if (source is not { Length: >= 3 and <= 64 })
                return false;
            foreach (var c in source)
                if (!char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or '.'))
                    return false;
            return true;
        }
    }
}
