// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

internal static class HealthBatch051055Context
{
    internal static readonly DateTime T0 = new(2026, 10, 27, 8, 0, 0, DateTimeKind.Utc);

    internal static RuleEvaluationContext At(
        int seconds = 0, long drops = 0, long sink = 0, long journal = 0,
        long reload = 0, DateTime? feed = null, DateTime? observedAt = null)
    {
        var now = T0.AddSeconds(seconds);
        var health = new RuleEngineHealthSnapshot(
            observedAt ?? now, null, 0, drops, sink, journal, reload, feed, TimeSpan.Zero);
        return new RuleEvaluationContext(new TrafficRecord(), Sensitivity.Balanced, now, health);
    }
}
