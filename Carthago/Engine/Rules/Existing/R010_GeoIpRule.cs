// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R010_GeoIpRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R010_GeoIpRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R010",
            Name: "GeoIP",
            Category: "GeoIP",
            Description: "Destination country or geo-policy anomaly",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R010.Enabled",
            EnabledByDefault: true);
    }
}
