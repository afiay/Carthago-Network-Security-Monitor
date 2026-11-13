// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules;
using Carthago.Models;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableEvaluationContextTests
{
    [Fact]
    public void PacketContextPreservesExactRecordSensitivityAndUtcTime()
    {
        var record = new TrafficRecord { Source = "192.0.2.10", Destination = "198.51.100.1" };
        var time = new DateTime(2026, 11, 13, 12, 0, 0, DateTimeKind.Utc);
        var context = new PacketEvaluationContext(record, Sensitivity.Aggressive, time);
        Assert.Same(record, context.Record);
        Assert.Equal(Sensitivity.Aggressive, context.Sensitivity);
        Assert.Equal(time, context.TimestampUtc);
        Assert.Equal(DateTimeKind.Utc, context.TimestampUtc.Kind);
    }

    [Theory]
    [InlineData(DateTimeKind.Unspecified)]
    [InlineData(DateTimeKind.Local)]
    public void NonUtcInputsRejectedRatherThanUsingHostTimezone(DateTimeKind kind)
    {
        var time = new DateTime(2026, 11, 13, 12, 0, 0, kind);
        Assert.Throws<ArgumentException>(() => new PacketEvaluationContext(new TrafficRecord(), Sensitivity.Balanced, time));
    }

    [Fact]
    public void MissingRecordRejected()
    {
        Assert.Throws<ArgumentNullException>(() => new PacketEvaluationContext(null!, Sensitivity.Balanced, DateTime.UnixEpoch));
    }

    [Fact]
    public void PacketContextHasNoHostCapabilitySurface()
    {
        var type = typeof(PacketEvaluationContext);
        Assert.Same(typeof(TrafficRecord).Assembly, type.Assembly);
        Assert.Equal("Carthago.Core", type.Assembly.GetName().Name);
        Assert.Equal(new[] { "Record", "Sensitivity", "TimestampUtc" },
            type.GetProperties().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray());
        var constructor = Assert.Single(type.GetConstructors());
        Assert.Equal(new[] { typeof(TrafficRecord), typeof(Sensitivity), typeof(DateTime) },
            constructor.GetParameters().Select(p => p.ParameterType).ToArray());
        Assert.DoesNotContain(type.Assembly.GetReferencedAssemblies(), r =>
            r.Name is "Carthago" or "PresentationFramework" or "PresentationCore" or "WindowsBase");
    }
}
