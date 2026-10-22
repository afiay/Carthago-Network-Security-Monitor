// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R015_ArpSpoofingRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R015_ArpSpoofingRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R015",
            Name: "ARP Spoofing",
            Category: "Network",
            Description: "Potential ARP spoofing",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R015.Enabled",
            EnabledByDefault: true);
    }
}
