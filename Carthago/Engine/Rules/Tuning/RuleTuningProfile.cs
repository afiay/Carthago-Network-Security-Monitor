// SPDX-License-Identifier: MIT
// File: Engine/Rules/Tuning/RuleTuningProfile.cs
namespace Carthago.Engine.Rules.Tuning
{
    public enum RuleTuningTier
    {
        HighFidelityAlert,
        MediumFidelityAlert,
        ShadowFirst,
        BaselineRequired,
        EnvironmentSpecific,
        DisabledUntilConfigured,
        HealthOnly
    }

    public sealed record RuleTuningProfile(
        string Name,
        string Description,
        bool BroadAlerting = false,
        bool NoisyRuleWarningsEnabled = false,
        bool ResearchOnly = false);
}
