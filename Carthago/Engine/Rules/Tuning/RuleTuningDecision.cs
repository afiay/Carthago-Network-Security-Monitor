// SPDX-License-Identifier: MIT
// File: Engine/Rules/Tuning/RuleTuningDecision.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Tuning
{
    public sealed record RuleTuningDecision
    {
        public required string RuleId { get; init; }
        public required string ProfileName { get; init; }
        public required RuleTuningTier Tier { get; init; }
        public RuleMode DefaultMode { get; init; }
        public RuleMode EffectiveMode { get; init; }
        public double? ConfidenceFloor { get; init; }
        public bool RequiresBaseline { get; init; }
        public string? BaselineDependency { get; init; }
        public IReadOnlyList<string> RequiredProfiles { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> RequiredAssetConfiguration { get; init; } = Array.Empty<string>();
        public IReadOnlyList<RuleTuningReason> Reasons { get; init; } = Array.Empty<RuleTuningReason>();
        public IReadOnlyList<string> ReasonDetails { get; init; } = Array.Empty<string>();
        public bool NoisyByDefault { get; init; }
        public bool ResearchOnly { get; init; }

        public bool AlertsByDefault => DefaultMode == RuleMode.Alert;
        public bool AlertsEffectively => EffectiveMode == RuleMode.Alert;
    }
}
