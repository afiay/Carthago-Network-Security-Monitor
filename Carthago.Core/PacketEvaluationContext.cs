// SPDX-License-Identifier: MIT
using Carthago.Models;

namespace Carthago.Engine.Rules;

/// <summary>
/// Packet evaluation inputs only. The record is a caller-owned mutable observation,
/// not an authenticated audit receipt or a snapshot of host runtime state.
/// </summary>
public sealed class PacketEvaluationContext
{
    public PacketEvaluationContext(TrafficRecord record, Sensitivity sensitivity, DateTime timestampUtc)
    {
        Record = record ?? throw new ArgumentNullException(nameof(record));
        if (timestampUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("An explicit UTC timestamp is required.", nameof(timestampUtc));
        Sensitivity = sensitivity;
        TimestampUtc = timestampUtc;
    }

    public TrafficRecord Record { get; }
    public Sensitivity Sensitivity { get; }
    public DateTime TimestampUtc { get; }
}
