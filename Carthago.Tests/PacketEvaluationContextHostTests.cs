// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class PacketEvaluationContextHostTests
{
    [Theory]
    [InlineData(DateTimeKind.Utc)]
    [InlineData(DateTimeKind.Local)]
    [InlineData(DateTimeKind.Unspecified)]
    public void HostPreservesLegacyTimeNormalizationAndRecordIdentity(DateTimeKind kind)
    {
        var record = new TrafficRecord { Source = "192.0.2.10" };
        var time = new DateTime(2026, 11, 13, 12, 0, 0, kind);
        var context = new RuleEvaluationContext(record, Sensitivity.Relaxed, time);
        Assert.Same(record, context.Record);
        Assert.Same(record, context.Packet.Record);
        Assert.Equal(Sensitivity.Relaxed, context.Packet.Sensitivity);
        Assert.Equal(time.ToUniversalTime(), context.TimestampUtc);
        Assert.Equal(context.TimestampUtc, context.Packet.TimestampUtc);
        Assert.Equal(DateTimeKind.Utc, context.TimestampUtc.Kind);
        Assert.NotNull(context.HealthSnapshot);
    }
}
