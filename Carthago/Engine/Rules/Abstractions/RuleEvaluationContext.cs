// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/RuleEvaluationContext.cs
using System;
using Carthago.Models;
using Carthago.Engine.Rules;
using Carthago.Services;

namespace Carthago.Engine.Rules
{
    public sealed class RuleEvaluationContext
    {
        public RuleEvaluationContext(TrafficRecord record, Sensitivity sensitivity, DateTime timestampUtc, RuleEngineHealthSnapshot? healthSnapshot = null)
        {
            Record = record ?? throw new ArgumentNullException(nameof(record));
            Sensitivity = sensitivity;
            TimestampUtc = timestampUtc.Kind == DateTimeKind.Utc ? timestampUtc : timestampUtc.ToUniversalTime();
            HealthSnapshot = healthSnapshot ?? RuleEngineHealthSnapshot.Empty(timestampUtc);
        }

        public TrafficRecord Record { get; }
        public Sensitivity Sensitivity { get; }
        public DateTime TimestampUtc { get; }
        public RuleEngineHealthSnapshot HealthSnapshot { get; }
    }
}
