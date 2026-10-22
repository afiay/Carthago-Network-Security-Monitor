// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R039_AsnNoveltyOnSensitiveVlansRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R039_AsnNoveltyOnSensitiveVlansRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R039",
            Name: "ASN Novelty on Sensitive VLANs",
            Category: "Egress",
            Description: "New ASN from sensitive VLAN",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R039.Enabled",
            EnabledByDefault: true);
    }
}
